//! Native archive application model.
//!
//! `deb_payload` decides whether a `.deb` is a structurally valid, bounded, and
//! authenticated Debian archive. This module turns one accepted validation into
//! the application-ready description the native transaction engine needs before
//! it may mutate a root: normalized payload entries with exact metadata and
//! bounded content, verified `md5sums`, lifecycle scripts, conffile
//! declarations, trigger declarations, and the control relationships that
//! authorize placement. It never writes a target file, never executes a script,
//! and never implements package-database or lifecycle semantics.
//!
//! Every archive feature is explicitly classified. Anything outside the v1
//! profile documented in `doc/archive-application-model.md` is rejected during
//! preflight with a typed diagnostic instead of being approximated.

const std = @import("std");
const deb_archive = @import("deb_archive.zig");
const deb_payload = @import("deb_payload.zig");
const control_record = @import("control_record.zig");
const relation = @import("relation.zig");

pub const model_version: u32 = 1;

/// Domain separator for the deterministic application digest. Changing the
/// modeled contract requires changing this string and `model_version`.
pub const digest_domain = "debz.archive-application.v1";

pub const Limits = struct {
    payload: deb_payload.Limits = .{},
    max_files: usize = 250_000,
    max_control_members: usize = 64,
    max_checksums_bytes: usize = 32 * 1024 * 1024,
    max_checksum_entries: usize = 250_000,
    max_triggers_bytes: usize = 1024 * 1024,
    max_trigger_declarations: usize = 4096,
    max_trigger_target_bytes: usize = 4096,
    max_control_member_bytes: usize = 16 * 1024 * 1024,
};

pub const Identity = deb_payload.Identity;
pub const Provenance = deb_payload.Provenance;
pub const ProvenanceKind = deb_payload.ProvenanceKind;

/// Selects the acquisition boundary that produced the archive bytes.
pub const Request = union(enum) {
    /// Authenticated repository selection; identity, size, digest, and origin
    /// are all mandatory expectations.
    repository: deb_payload.Expected,
    /// Standalone artifact; optional expectations still fail closed.
    local: deb_payload.LocalExpected,
};

pub const FileKind = enum { regular, directory, symlink, hardlink };

/// Bounded location of validated content inside the decompressed member.
pub const Content = struct {
    offset: usize,
    length: usize,
};

/// One normalized, application-ready payload entry. `path` is canonical and
/// archive-root-relative; it is never absolute and never traverses.
pub const File = struct {
    path: []const u8,
    kind: FileKind,
    /// Permission and special mode bits only; file-type bits are rejected.
    mode: u32,
    uid: u64,
    gid: u64,
    owner_name: ?[]const u8,
    group_name: ?[]const u8,
    mtime: u64,
    size: u64,
    /// Regular files only.
    content: ?Content,
    /// SHA-256 of the exact regular-file bytes.
    sha256: ?[32]u8,
    /// MD5 declared by the package `md5sums` manifest, already verified.
    md5: ?[16]u8,
    /// Canonical archive-root-relative link identity for symlinks and the
    /// earlier regular file named by a hard link.
    link_target: ?[]const u8,
    /// Exact bytes a symlink must publish.
    link_literal: ?[]const u8,
    conffile: bool,
    entry_index: usize,

    pub fn setuid(self: File) bool {
        return self.mode & 0o4000 != 0;
    }

    pub fn setgid(self: File) bool {
        return self.mode & 0o2000 != 0;
    }

    pub fn sticky(self: File) bool {
        return self.mode & 0o1000 != 0;
    }

    pub fn permissions(self: File) u32 {
        return self.mode & 0o777;
    }
};

/// Metadata of the conventional `./` archive root record when present.
pub const RootMetadata = struct {
    mode: u32,
    uid: u64,
    gid: u64,
    mtime: u64,
};

pub const ScriptKind = enum {
    preinst,
    postinst,
    prerm,
    postrm,
    /// debconf configuration script. V1 models and preserves it but never
    /// executes it; it is not part of the dpkg lifecycle sequence.
    config,

    pub fn memberName(self: ScriptKind) []const u8 {
        return switch (self) {
            .preinst => "preinst",
            .postinst => "postinst",
            .prerm => "prerm",
            .postrm => "postrm",
            .config => "config",
        };
    }

    pub fn lifecycle(self: ScriptKind) bool {
        return self != .config;
    }
};

pub const Script = struct {
    kind: ScriptKind,
    name: []const u8,
    mode: u32,
    size: u64,
    sha256: [32]u8,
    content: Content,
};

/// Control member that dpkg copies verbatim into the package information
/// directory without interpreting it. V1 preserves the exact bytes and digest
/// and never derives behavior from them.
pub const MetadataMember = struct {
    name: []const u8,
    mode: u32,
    size: u64,
    sha256: [32]u8,
    content: Content,
};

pub const Conffile = struct {
    /// Canonical archive-root-relative path.
    path: []const u8,
    /// Debian `remove-on-upgrade` declaration; such conffiles are deliberately
    /// absent from the payload.
    remove_on_upgrade: bool,
    /// Index into `files` for shipped conffiles.
    file_index: ?usize,
};

pub const Checksum = struct {
    path: []const u8,
    md5: [16]u8,
    file_index: usize,
};

pub const TriggerDirective = enum {
    interest,
    interest_await,
    interest_noawait,
    activate,
    activate_await,
    activate_noawait,
};

pub const TriggerKind = enum { interest, activate };

pub const AwaitPolicy = enum { awaited, noawait };

pub const TriggerTargetKind = enum { name, path };

pub const Trigger = struct {
    directive: TriggerDirective,
    kind: TriggerKind,
    await_policy: AwaitPolicy,
    target_kind: TriggerTargetKind,
    /// Trigger name, or the exact absolute path of a file trigger.
    target: []const u8,
};

pub const RelationshipField = enum {
    pre_depends,
    depends,
    recommends,
    suggests,
    enhances,
    conflicts,
    breaks,
    replaces,
    provides,

    pub fn fieldName(self: RelationshipField) []const u8 {
        return switch (self) {
            .pre_depends => "Pre-Depends",
            .depends => "Depends",
            .recommends => "Recommends",
            .suggests => "Suggests",
            .enhances => "Enhances",
            .conflicts => "Conflicts",
            .breaks => "Breaks",
            .replaces => "Replaces",
            .provides => "Provides",
        };
    }
};

pub const relationship_fields = std.enums.values(RelationshipField);

/// Control facts required to authorize and order application. Relationship
/// text and parsed relations are read through `Model.relationship`.
pub const ControlFacts = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    essential: bool,
    protected: bool,
    important: bool,
    multi_arch: control_record.MultiArch,
    priority: ?control_record.Priority,
    installed_size: ?u64,
};

/// Supported archive features actually used by one package. This is the
/// inventory surface for the compatibility corpus and cutover gates.
pub const Features = struct {
    control_compression: deb_archive.Compression,
    data_compression: deb_archive.Compression,
    archive_root_record: bool = false,
    regular_files: bool = false,
    directories: bool = false,
    symlinks: bool = false,
    hardlinks: bool = false,
    setuid_or_setgid: bool = false,
    sticky_bits: bool = false,
    non_root_ownership: bool = false,
    conffiles: bool = false,
    remove_on_upgrade_conffiles: bool = false,
    checksums: bool = false,
    lifecycle_scripts: bool = false,
    debconf_config_script: bool = false,
    retained_metadata: bool = false,
    trigger_interests: bool = false,
    trigger_activations: bool = false,
    essential: bool = false,
    empty_payload: bool = false,
};

/// Coarse classification of every rejected archive feature. Callers report it
/// instead of guessing whether an unsupported archive could be approximated.
pub const UnsupportedFeature = enum {
    archive_container,
    compression,
    tar_extension,
    file_type,
    file_metadata,
    path_or_link,
    control_member,
    control_metadata,
    checksum_manifest,
    conffile_declaration,
    trigger_declaration,
    maintainer_script,
    identity_binding,
    resource_limit,
    local_profile,
};

pub const Stage = enum {
    payload,
    control_members,
    files,
    checksums,
    conffiles,
    triggers,
    relationships,
    revalidation,
};

pub const Code = enum {
    payload_rejected,
    unsupported_control_member,
    control_member_not_regular,
    control_member_limit,
    control_member_unsafe_mode,
    script_not_executable,
    file_limit,
    unsupported_mode_bits,
    invalid_checksums,
    checksum_limit,
    duplicate_checksum,
    checksum_target_missing,
    checksum_mismatch,
    conffile_not_shipped,
    conffile_unexpectedly_shipped,
    invalid_triggers,
    trigger_limit,
    duplicate_trigger,
    invalid_control_record,
    artifact_binding_mismatch,
    model_digest_mismatch,
    out_of_memory,
};

pub const Diagnostic = struct {
    stage: Stage,
    code: Code,
    /// Offset inside the decompressed member that carries the rejected record.
    offset: usize = 0,
    entry_index: ?usize = null,
    payload: ?deb_payload.Diagnostic = null,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .payload_rejected => "archive failed bounded Debian payload validation",
            .unsupported_control_member => "control.tar contains a member outside the supported v1 profile",
            .control_member_not_regular => "control.tar members must be regular files",
            .control_member_limit => "control.tar exceeds the configured member count or byte limit",
            .control_member_unsafe_mode => "control.tar member declares setuid or setgid bits",
            .script_not_executable => "maintainer script is not executable",
            .file_limit => "payload exceeds the configured application entry limit",
            .unsupported_mode_bits => "archive entry declares mode bits outside permission and special bits",
            .invalid_checksums => "md5sums is malformed",
            .checksum_limit => "md5sums exceeds the configured entry or byte limit",
            .duplicate_checksum => "md5sums declares a path more than once",
            .checksum_target_missing => "md5sums names a path that is not a regular payload file",
            .checksum_mismatch => "md5sums does not match the validated payload bytes",
            .conffile_not_shipped => "conffiles names a path the payload does not ship as a regular file",
            .conffile_unexpectedly_shipped => "remove-on-upgrade conffiles must not be shipped in the payload",
            .invalid_triggers => "triggers declares an unsupported directive or target",
            .trigger_limit => "triggers exceeds the configured declaration or byte limit",
            .duplicate_trigger => "triggers declares the same target more than once",
            .invalid_control_record => "control metadata is malformed for application modeling",
            .artifact_binding_mismatch => "artifact bytes no longer match the authenticated size, digest, or origin",
            .model_digest_mismatch => "revalidated archive does not reproduce the authorized application digest",
            .out_of_memory => "archive application modeling allocation failed",
        };
    }

    /// Explicit classification of what the engine refuses to approximate.
    pub fn feature(self: Diagnostic) UnsupportedFeature {
        if (self.payload) |payload| return classifyPayload(payload);
        return switch (self.code) {
            .payload_rejected => .archive_container,
            .unsupported_control_member,
            .control_member_not_regular,
            .control_member_unsafe_mode,
            => .control_member,
            .script_not_executable => .maintainer_script,
            .unsupported_mode_bits => .file_metadata,
            .invalid_checksums,
            .duplicate_checksum,
            .checksum_target_missing,
            .checksum_mismatch,
            => .checksum_manifest,
            .conffile_not_shipped, .conffile_unexpectedly_shipped => .conffile_declaration,
            .invalid_triggers, .duplicate_trigger => .trigger_declaration,
            .invalid_control_record => .control_metadata,
            .artifact_binding_mismatch, .model_digest_mismatch => .identity_binding,
            .control_member_limit,
            .file_limit,
            .checksum_limit,
            .trigger_limit,
            .out_of_memory,
            => .resource_limit,
        };
    }
};

fn classifyPayload(diagnostic: deb_payload.Diagnostic) UnsupportedFeature {
    return switch (diagnostic.code) {
        .outer_archive => .archive_container,
        .decompression_failed => .compression,
        .unsupported_tar_extension => .tar_extension,
        .unsupported_file_type => .file_type,
        .tar_invalid_owner => .file_metadata,
        .tar_truncated,
        .tar_bad_checksum,
        .tar_invalid_number,
        .tar_size_overflow,
        .tar_missing_end,
        .tar_trailing_data,
        => .archive_container,
        .unsafe_path,
        .duplicate_path,
        .conflicting_path,
        .unsafe_link,
        .forward_hardlink,
        => .path_or_link,
        .missing_control,
        .duplicate_control,
        .invalid_control,
        .missing_identity,
        => .control_metadata,
        .size_mismatch,
        .digest_mismatch,
        .identity_mismatch,
        .request_mismatch,
        .filename_mismatch,
        => .identity_binding,
        .invalid_conffiles, .duplicate_conffile => .conffile_declaration,
        .maintainer_script_limit => .maintainer_script,
        .tar_entry_limit,
        .tar_payload_limit,
        .tar_metadata_limit,
        .path_too_long,
        .link_too_long,
        .conffiles_limit,
        .out_of_memory,
        => .resource_limit,
        .descriptor_control_entry,
        .descriptor_payload_path,
        .descriptor_unsafe_mode,
        .descriptor_unsafe_owner,
        .descriptor_link,
        .descriptor_relationship,
        .descriptor_limit,
        .descriptor_missing_source,
        .descriptor_missing_keyring,
        .descriptor_conffile_mismatch,
        => .local_profile,
    };
}

pub const FileAccessError = error{ NotRegularFile, MissingContent };

/// Owns the underlying validation, the borrowed control document, and the
/// modeled arrays. All string fields borrow from those owned buffers.
pub const Model = struct {
    allocator: std.mem.Allocator,
    validation: deb_payload.Validation,
    document: control_record.BorrowedDocument,
    identity: Identity,
    facts: ControlFacts,
    root: ?RootMetadata,
    files: []File,
    scripts: []Script,
    metadata: []MetadataMember,
    conffiles: []Conffile,
    checksums: []Checksum,
    triggers: []Trigger,
    features: Features,
    /// Deterministic digest of the complete modeled application. Stable across
    /// processes and machines for identical archive bytes and expectations.
    digest: [32]u8,

    pub fn deinit(self: *Model) void {
        self.allocator.free(self.files);
        self.allocator.free(self.scripts);
        self.allocator.free(self.metadata);
        self.allocator.free(self.conffiles);
        self.allocator.free(self.checksums);
        self.allocator.free(self.triggers);
        self.document.deinit();
        self.validation.deinit();
        self.* = undefined;
    }

    pub fn provenance(self: *const Model) Provenance {
        return self.validation.provenance;
    }

    pub fn record(self: *const Model) *const control_record.Record {
        return &self.document.records[0];
    }

    pub fn controlBytes(self: *const Model) []const u8 {
        return self.validation.control_bytes;
    }

    pub fn dataBytes(self: *const Model) []const u8 {
        return self.validation.data_bytes;
    }

    /// Exact declared relationship text, or null when the field is absent.
    pub fn relationshipText(self: *const Model, field: RelationshipField) ?[]const u8 {
        const value = self.relationshipValue(field) orelse return null;
        return value.source;
    }

    /// Parsed relationship AST for solver and placement authorization.
    pub fn relationship(self: *const Model, field: RelationshipField) ?*const relation.Relation {
        const value = self.relationshipValue(field) orelse return null;
        return &value.value;
    }

    fn relationshipValue(self: *const Model, field: RelationshipField) ?*const control_record.RelationValue {
        const current = self.record();
        return switch (field) {
            .pre_depends => optionalValue(&current.pre_depends),
            .depends => optionalValue(&current.depends),
            .recommends => optionalValue(&current.recommends),
            .suggests => optionalValue(&current.suggests),
            .enhances => optionalValue(&current.enhances),
            .conflicts => optionalValue(&current.conflicts),
            .breaks => optionalValue(&current.breaks),
            .replaces => optionalValue(&current.replaces),
            .provides => optionalValue(&current.provides),
        };
    }

    /// Bounded borrowed view of one validated regular payload file.
    pub fn fileBytes(self: *const Model, file: File) FileAccessError![]const u8 {
        if (file.kind != .regular) return error.NotRegularFile;
        const content = file.content orelse return error.MissingContent;
        const end = std.math.add(usize, content.offset, content.length) catch
            return error.MissingContent;
        if (end > self.validation.data_bytes.len) return error.MissingContent;
        return self.validation.data_bytes[content.offset..end];
    }

    pub fn scriptBytes(self: *const Model, value: Script) []const u8 {
        return self.validation.control_bytes[value.content.offset..][0..value.content.length];
    }

    pub fn metadataBytes(self: *const Model, member: MetadataMember) []const u8 {
        return self.validation.control_bytes[member.content.offset..][0..member.content.length];
    }

    pub fn findFile(self: *const Model, path: []const u8) ?*const File {
        for (self.files) |*file| {
            if (std.mem.eql(u8, file.path, path)) return file;
        }
        return null;
    }

    pub fn script(self: *const Model, kind: ScriptKind) ?*const Script {
        for (self.scripts) |*value| {
            if (value.kind == kind) return value;
        }
        return null;
    }

    /// Re-checks that in-memory artifact bytes still carry the authenticated
    /// size, digest, and origin binding recorded at acquisition time.
    pub fn verifyArtifactBinding(self: *const Model, bytes: []const u8) error{BindingMismatch}!void {
        const source = self.provenance();
        if (bytes.len != source.size) return error.BindingMismatch;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        if (!std.crypto.timing_safe.eql([32]u8, digest, source.sha256))
            return error.BindingMismatch;
    }
};

fn optionalValue(field: *const ?control_record.RelationValue) ?*const control_record.RelationValue {
    return if (field.*) |*value| value else null;
}

pub const Result = union(enum) {
    model: Model,
    diagnostic: Diagnostic,
};

/// Validates the archive bytes and builds the application model. Callers run
/// this immediately before application so that no unvalidated bytes and no
/// stale inventory can reach a mutation boundary.
pub fn prepare(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    request: Request,
    limits: Limits,
) Result {
    const outcome = switch (request) {
        .repository => |expected| deb_payload.validate(allocator, bytes, expected, limits.payload),
        .local => |expected| deb_payload.inspectLocal(allocator, bytes, expected, limits.payload),
    };
    var validation = switch (outcome) {
        .validation => |value| value,
        .diagnostic => |diagnostic| return .{ .diagnostic = .{
            .stage = .payload,
            .code = .payload_rejected,
            .offset = diagnostic.offset,
            .entry_index = diagnostic.entry_index,
            .payload = diagnostic,
        } },
    };
    return build(allocator, &validation, limits);
}

/// Immediate pre-application revalidation. The authorized model is reproduced
/// from the artifact bytes and must yield the exact recorded application
/// digest; anything else fails closed before mutation.
pub fn revalidate(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    request: Request,
    limits: Limits,
    authorized_digest: [32]u8,
) Result {
    var result = prepare(allocator, bytes, request, limits);
    switch (result) {
        .diagnostic => return result,
        .model => |*model| {
            model.verifyArtifactBinding(bytes) catch {
                model.deinit();
                return .{ .diagnostic = .{
                    .stage = .revalidation,
                    .code = .artifact_binding_mismatch,
                } };
            };
            if (!std.crypto.timing_safe.eql([32]u8, model.digest, authorized_digest)) {
                model.deinit();
                return .{ .diagnostic = .{
                    .stage = .revalidation,
                    .code = .model_digest_mismatch,
                } };
            }
            return result;
        },
    }
}

/// Side-effect-free fuzz boundary. It models the archive and releases every
/// successful result immediately.
pub fn fuzzOne(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    request: Request,
    limits: Limits,
) void {
    switch (prepare(allocator, bytes, request, limits)) {
        .model => |value| {
            var model = value;
            model.verifyArtifactBinding(bytes) catch {};
            model.deinit();
        },
        .diagnostic => |diagnostic| _ = diagnostic.feature(),
    }
}

const ControlMemberClass = enum { interpreted, script, retained };

const ControlMember = struct {
    name: []const u8,
    class: ControlMemberClass,
    script_kind: ?ScriptKind = null,
};

/// The complete v1 control-member profile. Members outside this table are
/// rejected; `alternatives` is deliberately absent because dpkg acts on it and
/// v1 must not silently ignore that behavior.
const control_members = [_]ControlMember{
    .{ .name = "control", .class = .interpreted },
    .{ .name = "conffiles", .class = .interpreted },
    .{ .name = "md5sums", .class = .interpreted },
    .{ .name = "triggers", .class = .interpreted },
    .{ .name = "preinst", .class = .script, .script_kind = .preinst },
    .{ .name = "postinst", .class = .script, .script_kind = .postinst },
    .{ .name = "prerm", .class = .script, .script_kind = .prerm },
    .{ .name = "postrm", .class = .script, .script_kind = .postrm },
    .{ .name = "config", .class = .script, .script_kind = .config },
    .{ .name = "templates", .class = .retained },
    .{ .name = "shlibs", .class = .retained },
    .{ .name = "symbols", .class = .retained },
};

fn classifyControlMember(name: []const u8) ?ControlMember {
    for (control_members) |member| {
        if (std.mem.eql(u8, member.name, name)) return member;
    }
    return null;
}

const Builder = struct {
    allocator: std.mem.Allocator,
    validation: *deb_payload.Validation,
    limits: Limits,
    files: std.ArrayList(File) = .empty,
    scripts: std.ArrayList(Script) = .empty,
    metadata: std.ArrayList(MetadataMember) = .empty,
    conffiles: std.ArrayList(Conffile) = .empty,
    checksums: std.ArrayList(Checksum) = .empty,
    triggers: std.ArrayList(Trigger) = .empty,
    index: std.StringHashMapUnmanaged(usize) = .empty,
    features: Features,

    fn deinit(self: *Builder) void {
        self.files.deinit(self.allocator);
        self.scripts.deinit(self.allocator);
        self.metadata.deinit(self.allocator);
        self.conffiles.deinit(self.allocator);
        self.checksums.deinit(self.allocator);
        self.triggers.deinit(self.allocator);
        self.index.deinit(self.allocator);
    }
};

const BuildError = error{Rejected};

fn build(
    allocator: std.mem.Allocator,
    validation: *deb_payload.Validation,
    limits: Limits,
) Result {
    var builder: Builder = .{
        .allocator = allocator,
        .validation = validation,
        .limits = limits,
        .features = .{
            .control_compression = validation.control.compression,
            .data_compression = validation.data.compression,
        },
    };
    defer builder.deinit();
    var diagnostic: Diagnostic = undefined;

    var document = parseControlDocument(allocator, validation, &diagnostic) catch {
        validation.deinit();
        return .{ .diagnostic = diagnostic };
    };
    var document_owned = true;
    defer if (document_owned) document.deinit();

    buildFiles(&builder, &diagnostic) catch {
        validation.deinit();
        return .{ .diagnostic = diagnostic };
    };
    buildControlMembers(&builder, &diagnostic) catch {
        validation.deinit();
        return .{ .diagnostic = diagnostic };
    };
    buildConffiles(&builder, &diagnostic) catch {
        validation.deinit();
        return .{ .diagnostic = diagnostic };
    };
    buildChecksums(&builder, &diagnostic) catch {
        validation.deinit();
        return .{ .diagnostic = diagnostic };
    };
    buildTriggers(&builder, &diagnostic) catch {
        validation.deinit();
        return .{ .diagnostic = diagnostic };
    };

    const current = &document.records[0];
    builder.features.essential = current.essential orelse false;

    const owned = takeOwnership(&builder) catch return oom(validation);

    var model: Model = .{
        .allocator = allocator,
        .validation = validation.*,
        .document = document,
        .identity = .{
            .package = validation.package,
            .version = validation.version,
            .architecture = validation.architecture,
        },
        .facts = .{
            .package = validation.package,
            .version = validation.version,
            .architecture = validation.architecture,
            .essential = current.essential orelse false,
            .protected = current.protected orelse false,
            .important = current.important orelse false,
            .multi_arch = current.multi_arch orelse .no,
            .priority = current.priority,
            .installed_size = current.installed_size,
        },
        .root = if (validation.data.root) |root| .{
            .mode = root.mode,
            .uid = root.uid,
            .gid = root.gid,
            .mtime = root.mtime,
        } else null,
        .files = owned.files,
        .scripts = owned.scripts,
        .metadata = owned.metadata,
        .conffiles = owned.conffiles,
        .checksums = owned.checksums,
        .triggers = owned.triggers,
        .features = builder.features,
        .digest = undefined,
    };
    model.digest = computeDigest(&model);
    document_owned = false;
    return .{ .model = model };
}

const Owned = struct {
    files: []File,
    scripts: []Script,
    metadata: []MetadataMember,
    conffiles: []Conffile,
    checksums: []Checksum,
    triggers: []Trigger,
};

fn takeOwnership(builder: *Builder) std.mem.Allocator.Error!Owned {
    const allocator = builder.allocator;
    const files = try builder.files.toOwnedSlice(allocator);
    errdefer allocator.free(files);
    const scripts = try builder.scripts.toOwnedSlice(allocator);
    errdefer allocator.free(scripts);
    const metadata = try builder.metadata.toOwnedSlice(allocator);
    errdefer allocator.free(metadata);
    const conffiles = try builder.conffiles.toOwnedSlice(allocator);
    errdefer allocator.free(conffiles);
    const checksums = try builder.checksums.toOwnedSlice(allocator);
    errdefer allocator.free(checksums);
    const triggers = try builder.triggers.toOwnedSlice(allocator);
    return .{
        .files = files,
        .scripts = scripts,
        .metadata = metadata,
        .conffiles = conffiles,
        .checksums = checksums,
        .triggers = triggers,
    };
}

fn oom(validation: *deb_payload.Validation) Result {
    validation.deinit();
    return .{ .diagnostic = .{ .stage = .payload, .code = .out_of_memory } };
}

fn reject(
    diagnostic: *Diagnostic,
    stage: Stage,
    code: Code,
    offset: usize,
    entry_index: ?usize,
) BuildError {
    diagnostic.* = .{
        .stage = stage,
        .code = code,
        .offset = offset,
        .entry_index = entry_index,
    };
    return error.Rejected;
}

fn parseControlDocument(
    allocator: std.mem.Allocator,
    validation: *deb_payload.Validation,
    diagnostic: *Diagnostic,
) BuildError!control_record.BorrowedDocument {
    const entry = for (validation.control.entries) |candidate| {
        if (std.mem.eql(u8, candidate.path, "control")) break candidate;
    } else return reject(diagnostic, .relationships, .invalid_control_record, 0, null);
    const content = entryContent(validation.control_bytes, entry) orelse
        return reject(diagnostic, .relationships, .invalid_control_record, entry.content_offset, null);
    const outcome = control_record.parseBorrowed(allocator, content, .{
        .limits = .{ .max_records = 1 },
    }) catch return reject(diagnostic, .relationships, .out_of_memory, entry.content_offset, null);
    switch (outcome) {
        .document => |value| {
            var document = value;
            if (document.records.len != 1) {
                document.deinit();
                return reject(diagnostic, .relationships, .invalid_control_record, entry.content_offset, null);
            }
            return document;
        },
        .diagnostic => return reject(
            diagnostic,
            .relationships,
            .invalid_control_record,
            entry.content_offset,
            null,
        ),
    }
}

fn buildFiles(builder: *Builder, diagnostic: *Diagnostic) BuildError!void {
    const validation = builder.validation;
    if (validation.data.entries.len > builder.limits.max_files)
        return reject(diagnostic, .files, .file_limit, 0, null);
    builder.features.archive_root_record = validation.data.root != null;
    if (validation.data.root) |root| {
        if (root.mode & ~@as(u32, 0o7777) != 0)
            return reject(diagnostic, .files, .unsupported_mode_bits, root.header_offset, null);
    }
    for (validation.data.entries, 0..) |entry, index| {
        if (entry.mode & ~@as(u32, 0o7777) != 0)
            return reject(diagnostic, .files, .unsupported_mode_bits, entry.header_offset, index);
        const kind: FileKind = switch (entry.kind) {
            .regular => .regular,
            .directory => .directory,
            .symlink => .symlink,
            .hardlink => .hardlink,
        };
        var content: ?Content = null;
        var sha256: ?[32]u8 = null;
        if (kind == .regular) {
            const bytes = entryContent(validation.data_bytes, entry) orelse
                return reject(diagnostic, .files, .file_limit, entry.content_offset, index);
            content = .{ .offset = entry.content_offset, .length = bytes.len };
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
            sha256 = digest;
        }
        switch (kind) {
            .regular => builder.features.regular_files = true,
            .directory => builder.features.directories = true,
            .symlink => builder.features.symlinks = true,
            .hardlink => builder.features.hardlinks = true,
        }
        if (entry.mode & 0o6000 != 0) builder.features.setuid_or_setgid = true;
        if (entry.mode & 0o1000 != 0) builder.features.sticky_bits = true;
        if (entry.uid != 0 or entry.gid != 0) builder.features.non_root_ownership = true;
        builder.files.append(builder.allocator, .{
            .path = entry.path,
            .kind = kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .owner_name = entry.owner_name,
            .group_name = entry.group_name,
            .mtime = entry.mtime,
            .size = entry.size,
            .content = content,
            .sha256 = sha256,
            .md5 = null,
            .link_target = entry.link_target,
            .link_literal = entry.link_literal,
            .conffile = false,
            .entry_index = index,
        }) catch return reject(diagnostic, .files, .out_of_memory, entry.header_offset, index);
        builder.index.put(builder.allocator, entry.path, builder.files.items.len - 1) catch
            return reject(diagnostic, .files, .out_of_memory, entry.header_offset, index);
    }
    builder.features.empty_payload = builder.files.items.len == 0;
}

fn buildControlMembers(builder: *Builder, diagnostic: *Diagnostic) BuildError!void {
    const validation = builder.validation;
    if (validation.control.entries.len > builder.limits.max_control_members)
        return reject(diagnostic, .control_members, .control_member_limit, 0, null);
    for (validation.control.entries, 0..) |entry, index| {
        const member = classifyControlMember(entry.path) orelse
            return reject(diagnostic, .control_members, .unsupported_control_member, entry.header_offset, index);
        if (entry.kind != .regular)
            return reject(diagnostic, .control_members, .control_member_not_regular, entry.header_offset, index);
        if (entry.mode & ~@as(u32, 0o7777) != 0)
            return reject(diagnostic, .control_members, .unsupported_mode_bits, entry.header_offset, index);
        if (entry.mode & 0o6000 != 0)
            return reject(diagnostic, .control_members, .control_member_unsafe_mode, entry.header_offset, index);
        if (entry.size > builder.limits.max_control_member_bytes)
            return reject(diagnostic, .control_members, .control_member_limit, entry.header_offset, index);
        const bytes = entryContent(validation.control_bytes, entry) orelse
            return reject(diagnostic, .control_members, .control_member_limit, entry.content_offset, index);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        const content: Content = .{ .offset = entry.content_offset, .length = bytes.len };
        switch (member.class) {
            .interpreted => {},
            .script => {
                const kind = member.script_kind.?;
                if (entry.mode & 0o111 == 0)
                    return reject(diagnostic, .control_members, .script_not_executable, entry.header_offset, index);
                if (kind.lifecycle())
                    builder.features.lifecycle_scripts = true
                else
                    builder.features.debconf_config_script = true;
                builder.scripts.append(builder.allocator, .{
                    .kind = kind,
                    .name = member.name,
                    .mode = entry.mode,
                    .size = entry.size,
                    .sha256 = digest,
                    .content = content,
                }) catch return reject(diagnostic, .control_members, .out_of_memory, entry.header_offset, index);
            },
            .retained => {
                builder.features.retained_metadata = true;
                builder.metadata.append(builder.allocator, .{
                    .name = member.name,
                    .mode = entry.mode,
                    .size = entry.size,
                    .sha256 = digest,
                    .content = content,
                }) catch return reject(diagnostic, .control_members, .out_of_memory, entry.header_offset, index);
            },
        }
    }
}

fn buildConffiles(builder: *Builder, diagnostic: *Diagnostic) BuildError!void {
    for (builder.validation.conffiles) |conffile| {
        const found = builder.index.get(conffile.path);
        if (conffile.remove_on_upgrade) {
            if (found != null)
                return reject(diagnostic, .conffiles, .conffile_unexpectedly_shipped, 0, found);
            builder.features.remove_on_upgrade_conffiles = true;
        } else {
            const file_index = found orelse
                return reject(diagnostic, .conffiles, .conffile_not_shipped, 0, null);
            if (builder.files.items[file_index].kind != .regular)
                return reject(diagnostic, .conffiles, .conffile_not_shipped, 0, file_index);
            builder.files.items[file_index].conffile = true;
        }
        builder.features.conffiles = true;
        builder.conffiles.append(builder.allocator, .{
            .path = conffile.path,
            .remove_on_upgrade = conffile.remove_on_upgrade,
            .file_index = if (conffile.remove_on_upgrade) null else found,
        }) catch return reject(diagnostic, .conffiles, .out_of_memory, 0, null);
    }
}

fn buildChecksums(builder: *Builder, diagnostic: *Diagnostic) BuildError!void {
    const validation = builder.validation;
    const entry = for (validation.control.entries) |candidate| {
        if (std.mem.eql(u8, candidate.path, "md5sums")) break candidate;
    } else return;
    if (entry.size > builder.limits.max_checksums_bytes)
        return reject(diagnostic, .checksums, .checksum_limit, entry.header_offset, null);
    const content = entryContent(validation.control_bytes, entry) orelse
        return reject(diagnostic, .checksums, .invalid_checksums, entry.content_offset, null);
    if (content.len != 0 and content[content.len - 1] != '\n')
        return reject(diagnostic, .checksums, .invalid_checksums, entry.content_offset, null);
    builder.features.checksums = content.len != 0;
    var offset: usize = 0;
    while (offset < content.len) {
        const line_end = std.mem.indexOfScalarPos(u8, content, offset, '\n').?;
        const line = content[offset..line_end];
        const record_offset = entry.content_offset + offset;
        offset = line_end + 1;
        if (line.len < 32 + 2 + 1)
            return reject(diagnostic, .checksums, .invalid_checksums, record_offset, null);
        var md5: [16]u8 = undefined;
        _ = std.fmt.hexToBytes(&md5, line[0..32]) catch
            return reject(diagnostic, .checksums, .invalid_checksums, record_offset, null);
        for (line[0..32]) |character| {
            if (!std.ascii.isDigit(character) and !(character >= 'a' and character <= 'f'))
                return reject(diagnostic, .checksums, .invalid_checksums, record_offset, null);
        }
        if (!std.mem.eql(u8, line[32..34], "  "))
            return reject(diagnostic, .checksums, .invalid_checksums, record_offset, null);
        const path = line[34..];
        if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/')
            return reject(diagnostic, .checksums, .invalid_checksums, record_offset, null);
        for (path) |character| {
            if (character < 0x20 or character == 0x7f)
                return reject(diagnostic, .checksums, .invalid_checksums, record_offset, null);
        }
        if (builder.checksums.items.len >= builder.limits.max_checksum_entries)
            return reject(diagnostic, .checksums, .checksum_limit, record_offset, null);
        for (builder.checksums.items) |existing| {
            if (std.mem.eql(u8, existing.path, path))
                return reject(diagnostic, .checksums, .duplicate_checksum, record_offset, null);
        }
        const file_index = builder.index.get(path) orelse
            return reject(diagnostic, .checksums, .checksum_target_missing, record_offset, null);
        const content_index = switch (builder.files.items[file_index].kind) {
            .regular => file_index,
            // dpkg records a checksum for every hard-linked payload path; the
            // bytes come from the earlier regular file the link names.
            .hardlink => blk: {
                const target = builder.files.items[file_index].link_target orelse
                    return reject(diagnostic, .checksums, .checksum_target_missing, record_offset, file_index);
                const target_index = builder.index.get(target) orelse
                    return reject(diagnostic, .checksums, .checksum_target_missing, record_offset, file_index);
                if (builder.files.items[target_index].kind != .regular)
                    return reject(diagnostic, .checksums, .checksum_target_missing, record_offset, file_index);
                break :blk target_index;
            },
            .directory, .symlink => return reject(diagnostic, .checksums, .checksum_target_missing, record_offset, file_index),
        };
        const content_location = builder.files.items[content_index].content.?;
        const bytes = validation.data_bytes[content_location.offset..][0..content_location.length];
        var computed: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(bytes, &computed, .{});
        if (!std.mem.eql(u8, &computed, &md5))
            return reject(diagnostic, .checksums, .checksum_mismatch, record_offset, file_index);
        const file = &builder.files.items[file_index];
        file.md5 = md5;
        builder.checksums.append(builder.allocator, .{
            .path = file.path,
            .md5 = md5,
            .file_index = file_index,
        }) catch return reject(diagnostic, .checksums, .out_of_memory, record_offset, null);
    }
}

fn buildTriggers(builder: *Builder, diagnostic: *Diagnostic) BuildError!void {
    const validation = builder.validation;
    const entry = for (validation.control.entries) |candidate| {
        if (std.mem.eql(u8, candidate.path, "triggers")) break candidate;
    } else return;
    if (entry.size > builder.limits.max_triggers_bytes)
        return reject(diagnostic, .triggers, .trigger_limit, entry.header_offset, null);
    const content = entryContent(validation.control_bytes, entry) orelse
        return reject(diagnostic, .triggers, .invalid_triggers, entry.content_offset, null);
    if (content.len != 0 and content[content.len - 1] != '\n')
        return reject(diagnostic, .triggers, .invalid_triggers, entry.content_offset, null);
    var offset: usize = 0;
    while (offset < content.len) {
        const line_end = std.mem.indexOfScalarPos(u8, content, offset, '\n').?;
        const line = content[offset..line_end];
        const record_offset = entry.content_offset + offset;
        offset = line_end + 1;
        const trimmed = std.mem.trim(u8, line, " \t");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        const separator = std.mem.indexOfAny(u8, trimmed, " \t") orelse
            return reject(diagnostic, .triggers, .invalid_triggers, record_offset, null);
        const directive = parseTriggerDirective(trimmed[0..separator]) orelse
            return reject(diagnostic, .triggers, .invalid_triggers, record_offset, null);
        const target = std.mem.trimStart(u8, trimmed[separator..], " \t");
        if (target.len == 0 or target.len > builder.limits.max_trigger_target_bytes)
            return reject(diagnostic, .triggers, .invalid_triggers, record_offset, null);
        if (std.mem.indexOfAny(u8, target, " \t") != null)
            return reject(diagnostic, .triggers, .invalid_triggers, record_offset, null);
        const target_kind: TriggerTargetKind = if (target[0] == '/') .path else .name;
        const valid = switch (target_kind) {
            .path => validTriggerPath(target),
            .name => validTriggerName(target),
        };
        if (!valid)
            return reject(diagnostic, .triggers, .invalid_triggers, record_offset, null);
        const kind = triggerKind(directive);
        if (builder.triggers.items.len >= builder.limits.max_trigger_declarations)
            return reject(diagnostic, .triggers, .trigger_limit, record_offset, null);
        for (builder.triggers.items) |existing| {
            if (existing.kind == kind and std.mem.eql(u8, existing.target, target))
                return reject(diagnostic, .triggers, .duplicate_trigger, record_offset, null);
        }
        switch (kind) {
            .interest => builder.features.trigger_interests = true,
            .activate => builder.features.trigger_activations = true,
        }
        builder.triggers.append(builder.allocator, .{
            .directive = directive,
            .kind = kind,
            .await_policy = awaitPolicy(directive),
            .target_kind = target_kind,
            .target = target,
        }) catch return reject(diagnostic, .triggers, .out_of_memory, record_offset, null);
    }
}

fn parseTriggerDirective(text: []const u8) ?TriggerDirective {
    const directives = std.StaticStringMap(TriggerDirective).initComptime(.{
        .{ "interest", .interest },
        .{ "interest-await", .interest_await },
        .{ "interest-noawait", .interest_noawait },
        .{ "activate", .activate },
        .{ "activate-await", .activate_await },
        .{ "activate-noawait", .activate_noawait },
    });
    return directives.get(text);
}

fn triggerKind(directive: TriggerDirective) TriggerKind {
    return switch (directive) {
        .interest, .interest_await, .interest_noawait => .interest,
        .activate, .activate_await, .activate_noawait => .activate,
    };
}

fn awaitPolicy(directive: TriggerDirective) AwaitPolicy {
    return switch (directive) {
        .interest, .interest_await, .activate, .activate_await => .awaited,
        .interest_noawait, .activate_noawait => .noawait,
    };
}

fn validTriggerName(name: []const u8) bool {
    if (name.len == 0 or !std.ascii.isAlphanumeric(name[0])) return false;
    for (name[1..]) |character| {
        if (std.ascii.isAlphanumeric(character)) continue;
        if (std.mem.indexOfScalar(u8, "-+._:", character) == null) return false;
    }
    return true;
}

fn validTriggerPath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    if (std.mem.indexOf(u8, path, "//") != null) return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0) return false;
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) return false;
        for (component) |character| {
            if (character < 0x20 or character == 0x7f) return false;
        }
    }
    return true;
}

fn entryContent(bytes: []const u8, entry: deb_payload.Entry) ?[]const u8 {
    if (entry.kind != .regular) return null;
    const size = std.math.cast(usize, entry.size) orelse return null;
    const end = std.math.add(usize, entry.content_offset, size) catch return null;
    if (end > bytes.len) return null;
    return bytes[entry.content_offset..end];
}

const DigestWriter = struct {
    hasher: std.crypto.hash.sha2.Sha256,

    fn init() DigestWriter {
        return .{ .hasher = std.crypto.hash.sha2.Sha256.init(.{}) };
    }

    fn text(self: *DigestWriter, value: []const u8) void {
        self.number(value.len);
        self.hasher.update(value);
    }

    fn optionalText(self: *DigestWriter, value: ?[]const u8) void {
        if (value) |present| {
            self.byte(1);
            self.text(present);
        } else self.byte(0);
    }

    fn number(self: *DigestWriter, value: u64) void {
        var buffer: [8]u8 = undefined;
        std.mem.writeInt(u64, &buffer, value, .little);
        self.hasher.update(&buffer);
    }

    fn optionalNumber(self: *DigestWriter, value: ?u64) void {
        if (value) |present| {
            self.byte(1);
            self.number(present);
        } else self.byte(0);
    }

    fn byte(self: *DigestWriter, value: u8) void {
        self.hasher.update(&[_]u8{value});
    }

    fn flag(self: *DigestWriter, value: bool) void {
        self.byte(@intFromBool(value));
    }

    fn tag(self: *DigestWriter, value: anytype) void {
        self.byte(@intCast(@intFromEnum(value)));
    }

    fn optionalTag(self: *DigestWriter, value: anytype) void {
        if (value) |present| {
            self.byte(1);
            self.byte(@intCast(@intFromEnum(present)));
        } else self.byte(0);
    }

    fn digest(self: *DigestWriter, value: []const u8) void {
        self.number(value.len);
        self.hasher.update(value);
    }

    fn optionalDigest(self: *DigestWriter, value: anytype) void {
        if (value) |present| {
            self.byte(1);
            self.digest(&present);
        } else self.byte(0);
    }

    fn final(self: *DigestWriter) [32]u8 {
        var out: [32]u8 = undefined;
        self.hasher.final(&out);
        return out;
    }
};

/// Deterministic, injective encoding of the complete modeled application. The
/// future native program compiler binds this digest into the authorized
/// program so the applied archive cannot drift from the reviewed one.
fn computeDigest(model: *const Model) [32]u8 {
    var writer = DigestWriter.init();
    writer.text(digest_domain);
    writer.number(model_version);

    writer.text(model.identity.package);
    writer.text(model.identity.version);
    writer.text(model.identity.architecture);

    const source = model.validation.provenance;
    writer.tag(source.kind);
    writer.text(source.repository);
    writer.text(source.filename);
    writer.number(source.size);
    writer.digest(&source.sha256);

    writer.flag(model.facts.essential);
    writer.flag(model.facts.protected);
    writer.flag(model.facts.important);
    writer.tag(model.facts.multi_arch);
    writer.optionalTag(model.facts.priority);
    writer.optionalNumber(model.facts.installed_size);

    writer.number(relationship_fields.len);
    for (relationship_fields) |field| {
        writer.text(field.fieldName());
        writer.optionalText(model.relationshipText(field));
    }

    if (model.root) |root| {
        writer.byte(1);
        writer.number(root.mode);
        writer.number(root.uid);
        writer.number(root.gid);
        writer.number(root.mtime);
    } else writer.byte(0);

    writer.tag(model.features.control_compression);
    writer.tag(model.features.data_compression);

    writer.number(model.files.len);
    for (model.files) |file| {
        writer.text(file.path);
        writer.tag(file.kind);
        writer.number(file.mode);
        writer.number(file.uid);
        writer.number(file.gid);
        writer.optionalText(file.owner_name);
        writer.optionalText(file.group_name);
        writer.number(file.mtime);
        writer.number(file.size);
        writer.optionalDigest(file.sha256);
        writer.optionalDigest(file.md5);
        writer.optionalText(file.link_target);
        writer.optionalText(file.link_literal);
        writer.flag(file.conffile);
    }

    writer.number(model.scripts.len);
    for (model.scripts) |script| {
        writer.tag(script.kind);
        writer.text(script.name);
        writer.number(script.mode);
        writer.number(script.size);
        writer.digest(&script.sha256);
    }

    writer.number(model.metadata.len);
    for (model.metadata) |member| {
        writer.text(member.name);
        writer.number(member.mode);
        writer.number(member.size);
        writer.digest(&member.sha256);
    }

    writer.number(model.conffiles.len);
    for (model.conffiles) |conffile| {
        writer.text(conffile.path);
        writer.flag(conffile.remove_on_upgrade);
    }

    writer.number(model.checksums.len);
    for (model.checksums) |checksum| {
        writer.text(checksum.path);
        writer.digest(&checksum.md5);
    }

    writer.number(model.triggers.len);
    for (model.triggers) |trigger| {
        writer.tag(trigger.directive);
        writer.tag(trigger.kind);
        writer.tag(trigger.await_policy);
        writer.tag(trigger.target_kind);
        writer.text(trigger.target);
    }

    return writer.final();
}

const testing = std.testing;

const test_mtime: u64 = 1_700_000_000;

const TestEntry = struct {
    path: []const u8,
    kind: u8 = '0',
    mode: u32 = 0o644,
    link: []const u8 = "",
    content: []const u8 = "",
    uid: u64 = 0,
    gid: u64 = 0,
};

const TestArchive = struct {
    package: []const u8 = "demo",
    version: []const u8 = "1.0",
    architecture: []const u8 = "amd64",
    control_fields: []const u8 = "",
    control: []const TestEntry = &.{},
    data: []const TestEntry = &.{},
};

fn writeOctal(field: []u8, value: u64) void {
    @memset(field, 0);
    var index = field.len - 2;
    var remaining = value;
    while (remaining != 0) {
        field[index] = @intCast('0' + remaining % 8);
        remaining /= 8;
        if (index == 0) break;
        index -= 1;
    }
}

fn appendTarEntry(
    allocator: std.mem.Allocator,
    tar: *std.ArrayList(u8),
    path: []const u8,
    entry: TestEntry,
) !void {
    var header: [512]u8 = @splat(0);
    std.mem.copyForwards(u8, header[0..], path);
    writeOctal(header[100..108], entry.mode);
    writeOctal(header[108..116], entry.uid);
    writeOctal(header[116..124], entry.gid);
    writeOctal(header[124..136], entry.content.len);
    writeOctal(header[136..148], test_mtime);
    @memset(header[148..156], ' ');
    header[156] = entry.kind;
    std.mem.copyForwards(u8, header[157..], entry.link);
    std.mem.copyForwards(u8, header[257..], "ustar\x00");
    std.mem.copyForwards(u8, header[263..], "00");
    std.mem.copyForwards(u8, header[265..297], "root");
    std.mem.copyForwards(u8, header[297..329], "root");
    var checksum: u64 = 0;
    for (header) |byte| checksum += byte;
    writeOctal(header[148..156], checksum);
    try tar.appendSlice(allocator, &header);
    try tar.appendSlice(allocator, entry.content);
    const padding = (512 - (entry.content.len % 512)) % 512;
    try tar.appendNTimes(allocator, 0, padding);
}

fn buildTar(allocator: std.mem.Allocator, entries: []const TestEntry) ![]u8 {
    var tar: std.ArrayList(u8) = .empty;
    errdefer tar.deinit(allocator);
    try appendTarEntry(allocator, &tar, "./", .{ .path = ".", .kind = '5', .mode = 0o755 });
    for (entries) |entry| {
        const path = try std.fmt.allocPrint(allocator, "./{s}", .{entry.path});
        defer allocator.free(path);
        try appendTarEntry(allocator, &tar, path, entry);
    }
    try tar.appendNTimes(allocator, 0, 1024);
    return tar.toOwnedSlice(allocator);
}

fn appendArMember(
    allocator: std.mem.Allocator,
    ar: *std.ArrayList(u8),
    name: []const u8,
    content: []const u8,
) !void {
    var header: [60]u8 = @splat(' ');
    std.mem.copyForwards(u8, &header, name);
    header[16] = '0';
    header[28] = '0';
    header[34] = '0';
    std.mem.copyForwards(u8, header[40..], "100644");
    const size = try std.fmt.bufPrint(header[48..58], "{d}", .{content.len});
    @memset(header[48 + size.len .. 58], ' ');
    header[58] = '`';
    header[59] = '\n';
    try ar.appendSlice(allocator, &header);
    try ar.appendSlice(allocator, content);
    if (content.len % 2 != 0) try ar.append(allocator, '\n');
}

fn buildArchive(allocator: std.mem.Allocator, options: TestArchive) ![]u8 {
    const control_text = try std.fmt.allocPrint(
        allocator,
        "Package: {s}\nVersion: {s}\nArchitecture: {s}\nMaintainer: debz fixture <fixture.invalid>\n{s}Description: fixture\n",
        .{ options.package, options.version, options.architecture, options.control_fields },
    );
    defer allocator.free(control_text);

    var control_entries: std.ArrayList(TestEntry) = .empty;
    defer control_entries.deinit(allocator);
    try control_entries.append(allocator, .{ .path = "control", .content = control_text });
    try control_entries.appendSlice(allocator, options.control);

    const control_tar = try buildTar(allocator, control_entries.items);
    defer allocator.free(control_tar);
    const data_tar = try buildTar(allocator, options.data);
    defer allocator.free(data_tar);

    var ar: std.ArrayList(u8) = .empty;
    errdefer ar.deinit(allocator);
    try ar.appendSlice(allocator, "!<arch>\n");
    try appendArMember(allocator, &ar, "debian-binary", "2.0\n");
    try appendArMember(allocator, &ar, "control.tar", control_tar);
    try appendArMember(allocator, &ar, "data.tar", data_tar);
    return ar.toOwnedSlice(allocator);
}

fn localRequest() Request {
    return .{ .local = .{} };
}

fn testLimits() Limits {
    return .{};
}

fn prepareArchive(options: TestArchive) !Result {
    const bytes = try buildArchive(testing.allocator, options);
    defer testing.allocator.free(bytes);
    return prepare(testing.allocator, bytes, localRequest(), testLimits());
}

fn expectRejected(options: TestArchive, code: Code, feature: UnsupportedFeature) !void {
    var result = try prepareArchive(options);
    switch (result) {
        .model => |*model| {
            model.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| {
            try testing.expectEqual(code, diagnostic.code);
            try testing.expectEqual(feature, diagnostic.feature());
            try testing.expect(diagnostic.message().len != 0);
        },
    }
}

fn md5Line(allocator: std.mem.Allocator, content: []const u8, path: []const u8) ![]u8 {
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(content, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    return std.fmt.allocPrint(allocator, "{s}  {s}\n", .{ &hex, path });
}

test "archive_application.test.model exposes application-ready payload metadata" {
    const payload = "example payload\n";
    const checksums = try md5Line(testing.allocator, payload, "usr/share/demo/file");
    defer testing.allocator.free(checksums);

    const result = try prepareArchive(.{
        .control_fields =
        \\Pre-Depends: base-dep (>= 1.0)
        \\Depends: other-dep
        \\Conflicts: legacy-demo
        \\Breaks: legacy-demo (<< 2.0)
        \\Replaces: legacy-demo
        \\Provides: demo-api (= 1.0)
        \\Essential: yes
        \\Installed-Size: 42
        \\Multi-Arch: foreign
        \\Priority: optional
        \\
        ,
        .control = &.{
            .{ .path = "md5sums", .content = checksums },
            .{ .path = "conffiles", .content = "/etc/demo.conf\n" },
            .{ .path = "triggers", .content = "# comment\ninterest-noawait /usr/share/demo\nactivate-await demo-trigger\n" },
            .{ .path = "preinst", .mode = 0o755, .content = "#!/bin/sh\nexit 0\n" },
            .{ .path = "postinst", .mode = 0o755, .content = "#!/bin/sh\nexit 0\n" },
            .{ .path = "shlibs", .content = "libdemo 1 demo\n" },
        },
        .data = &.{
            .{ .path = "etc", .kind = '5', .mode = 0o755 },
            .{ .path = "etc/demo.conf", .content = "key=value\n" },
            .{ .path = "usr/share/demo", .kind = '5', .mode = 0o755 },
            .{ .path = "usr/share/demo/file", .content = payload },
            .{ .path = "usr/share/demo/link", .kind = '2', .mode = 0o777, .link = "file" },
            .{ .path = "usr/share/demo/hard", .kind = '1', .link = "./usr/share/demo/file" },
            .{ .path = "usr/bin/demo", .mode = 0o4755, .content = "binary\n" },
        },
    });
    var model = switch (result) {
        .model => |value| value,
        .diagnostic => |diagnostic| {
            std.debug.print("unexpected diagnostic: {s}\n", .{diagnostic.message()});
            return error.TestUnexpectedResult;
        },
    };
    defer model.deinit();

    try testing.expectEqualStrings("demo", model.identity.package);
    try testing.expectEqualStrings("1.0", model.identity.version);
    try testing.expectEqualStrings("amd64", model.identity.architecture);
    try testing.expect(model.facts.essential);
    try testing.expectEqual(control_record.MultiArch.foreign, model.facts.multi_arch);
    try testing.expectEqual(@as(?u64, 42), model.facts.installed_size);
    try testing.expectEqual(control_record.Priority.optional, model.facts.priority.?);

    try testing.expectEqualStrings("base-dep (>= 1.0)", model.relationshipText(.pre_depends).?);
    try testing.expectEqualStrings("other-dep", model.relationshipText(.depends).?);
    try testing.expectEqualStrings("legacy-demo", model.relationshipText(.conflicts).?);
    try testing.expectEqualStrings("legacy-demo (<< 2.0)", model.relationshipText(.breaks).?);
    try testing.expectEqualStrings("legacy-demo", model.relationshipText(.replaces).?);
    try testing.expectEqualStrings("demo-api (= 1.0)", model.relationshipText(.provides).?);
    try testing.expect(model.relationshipText(.suggests) == null);
    try testing.expectEqual(@as(usize, 1), model.relationship(.pre_depends).?.groups.len);

    const regular = model.findFile("usr/share/demo/file").?;
    try testing.expectEqual(FileKind.regular, regular.kind);
    try testing.expectEqual(@as(u32, 0o644), regular.mode);
    try testing.expectEqual(@as(u64, 0), regular.uid);
    try testing.expectEqual(@as(u64, 1_700_000_000), regular.mtime);
    try testing.expectEqualStrings(payload, try model.fileBytes(regular.*));
    try testing.expect(regular.md5 != null);
    try testing.expect(regular.sha256 != null);
    try testing.expect(!regular.conffile);

    const directory = model.findFile("usr/share/demo").?;
    try testing.expectEqual(FileKind.directory, directory.kind);
    try testing.expectEqual(@as(u32, 0o755), directory.mode);
    try testing.expectError(error.NotRegularFile, model.fileBytes(directory.*));

    const symlink = model.findFile("usr/share/demo/link").?;
    try testing.expectEqual(FileKind.symlink, symlink.kind);
    try testing.expectEqualStrings("file", symlink.link_literal.?);
    try testing.expectEqualStrings("usr/share/demo/file", symlink.link_target.?);

    const hardlink = model.findFile("usr/share/demo/hard").?;
    try testing.expectEqual(FileKind.hardlink, hardlink.kind);
    try testing.expectEqualStrings("usr/share/demo/file", hardlink.link_target.?);

    const setuid = model.findFile("usr/bin/demo").?;
    try testing.expect(setuid.setuid());
    try testing.expectEqual(@as(u32, 0o755), setuid.permissions());

    const conffile = model.findFile("etc/demo.conf").?;
    try testing.expect(conffile.conffile);
    try testing.expectEqual(@as(usize, 1), model.conffiles.len);
    try testing.expect(!model.conffiles[0].remove_on_upgrade);

    try testing.expectEqual(@as(usize, 2), model.scripts.len);
    try testing.expect(model.script(.preinst).?.kind.lifecycle());
    try testing.expectEqualStrings("#!/bin/sh\nexit 0\n", model.scriptBytes(model.script(.postinst).?.*));
    try testing.expect(model.script(.prerm) == null);

    try testing.expectEqual(@as(usize, 1), model.metadata.len);
    try testing.expectEqualStrings("shlibs", model.metadata[0].name);
    try testing.expectEqualStrings("libdemo 1 demo\n", model.metadataBytes(model.metadata[0]));

    try testing.expectEqual(@as(usize, 2), model.triggers.len);
    try testing.expectEqual(TriggerDirective.interest_noawait, model.triggers[0].directive);
    try testing.expectEqual(TriggerKind.interest, model.triggers[0].kind);
    try testing.expectEqual(AwaitPolicy.noawait, model.triggers[0].await_policy);
    try testing.expectEqual(TriggerTargetKind.path, model.triggers[0].target_kind);
    try testing.expectEqualStrings("/usr/share/demo", model.triggers[0].target);
    try testing.expectEqual(TriggerDirective.activate_await, model.triggers[1].directive);
    try testing.expectEqual(AwaitPolicy.awaited, model.triggers[1].await_policy);
    try testing.expectEqual(TriggerTargetKind.name, model.triggers[1].target_kind);

    try testing.expectEqual(@as(usize, 1), model.checksums.len);
    try testing.expectEqualStrings("usr/share/demo/file", model.checksums[0].path);

    try testing.expect(model.features.regular_files);
    try testing.expect(model.features.directories);
    try testing.expect(model.features.symlinks);
    try testing.expect(model.features.hardlinks);
    try testing.expect(model.features.setuid_or_setgid);
    try testing.expect(model.features.checksums);
    try testing.expect(model.features.conffiles);
    try testing.expect(model.features.lifecycle_scripts);
    try testing.expect(model.features.retained_metadata);
    try testing.expect(model.features.trigger_interests);
    try testing.expect(model.features.trigger_activations);
    try testing.expect(!model.features.debconf_config_script);
    try testing.expectEqual(deb_archive.Compression.uncompressed, model.features.data_compression);
    try testing.expect(model.root != null);
}

test "archive_application.test.digest is deterministic and binds modeled metadata" {
    const options: TestArchive = .{
        .data = &.{.{ .path = "usr/share/demo", .content = "payload\n" }},
    };
    const bytes = try buildArchive(testing.allocator, options);
    defer testing.allocator.free(bytes);

    var first = switch (prepare(testing.allocator, bytes, localRequest(), testLimits())) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer first.deinit();
    var second = switch (prepare(testing.allocator, bytes, localRequest(), testLimits())) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer second.deinit();
    try testing.expectEqualSlices(u8, &first.digest, &second.digest);

    const modified = try buildArchive(testing.allocator, .{
        .data = &.{.{ .path = "usr/share/demo", .mode = 0o600, .content = "payload\n" }},
    });
    defer testing.allocator.free(modified);
    var third = switch (prepare(testing.allocator, modified, localRequest(), testLimits())) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer third.deinit();
    try testing.expect(!std.mem.eql(u8, &first.digest, &third.digest));
}

test "archive_application.test.revalidation preserves the authenticated binding" {
    const options: TestArchive = .{
        .data = &.{.{ .path = "usr/share/demo", .content = "payload\n" }},
    };
    const bytes = try buildArchive(testing.allocator, options);
    defer testing.allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});

    const request: Request = .{ .repository = .{
        .repository = "example",
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
        .requested_package = "demo",
        .filename = "pool/main/d/demo/demo_1.0_amd64.deb",
        .size = bytes.len,
        .sha256 = digest,
    } };

    var authorized = switch (prepare(testing.allocator, bytes, request, testLimits())) {
        .model => |value| value,
        .diagnostic => |diagnostic| {
            std.debug.print("unexpected diagnostic: {s}\n", .{diagnostic.message()});
            return error.TestUnexpectedResult;
        },
    };
    const authorized_digest = authorized.digest;
    try testing.expectEqual(ProvenanceKind.authenticated_repository, authorized.provenance().kind);
    try authorized.verifyArtifactBinding(bytes);
    authorized.deinit();

    var revalidated = switch (revalidate(
        testing.allocator,
        bytes,
        request,
        testLimits(),
        authorized_digest,
    )) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    try testing.expectEqualSlices(u8, &authorized_digest, &revalidated.digest);
    revalidated.deinit();

    var wrong: [32]u8 = authorized_digest;
    wrong[0] ^= 0xff;
    switch (revalidate(testing.allocator, bytes, request, testLimits(), wrong)) {
        .model => |value| {
            var model = value;
            model.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| {
            try testing.expectEqual(Code.model_digest_mismatch, diagnostic.code);
            try testing.expectEqual(UnsupportedFeature.identity_binding, diagnostic.feature());
        },
    }

    const tampered = try testing.allocator.dupe(u8, bytes);
    defer testing.allocator.free(tampered);
    tampered[tampered.len - 1] ^= 0xff;
    var model = switch (prepare(testing.allocator, bytes, request, testLimits())) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer model.deinit();
    try testing.expectError(error.BindingMismatch, model.verifyArtifactBinding(tampered));
}

test "archive_application.test.unsupported control members fail closed" {
    try expectRejected(
        .{ .control = &.{.{ .path = "alternatives", .content = "demo\n" }} },
        .unsupported_control_member,
        .control_member,
    );
    try expectRejected(
        .{ .control = &.{.{ .path = "postinst", .mode = 0o644, .content = "#!/bin/sh\n" }} },
        .script_not_executable,
        .maintainer_script,
    );
    try expectRejected(
        .{ .control = &.{.{ .path = "postinst", .mode = 0o4755, .content = "#!/bin/sh\n" }} },
        .control_member_unsafe_mode,
        .control_member,
    );
    try expectRejected(
        .{ .control = &.{.{ .path = "templates", .kind = '5', .mode = 0o755 }} },
        .control_member_not_regular,
        .control_member,
    );
}

test "archive_application.test.checksum manifests are verified against payload bytes" {
    const payload = "payload\n";
    const valid = try md5Line(testing.allocator, payload, "usr/share/demo");
    defer testing.allocator.free(valid);

    try expectRejected(.{
        .control = &.{.{ .path = "md5sums", .content = "0123456789abcdef0123456789abcdef  usr/share/demo\n" }},
        .data = &.{.{ .path = "usr/share/demo", .content = payload }},
    }, .checksum_mismatch, .checksum_manifest);

    try expectRejected(.{
        .control = &.{.{ .path = "md5sums", .content = valid }},
        .data = &.{.{ .path = "usr/share/other", .content = payload }},
    }, .checksum_target_missing, .checksum_manifest);

    const duplicated = try std.fmt.allocPrint(testing.allocator, "{s}{s}", .{ valid, valid });
    defer testing.allocator.free(duplicated);
    try expectRejected(.{
        .control = &.{.{ .path = "md5sums", .content = duplicated }},
        .data = &.{.{ .path = "usr/share/demo", .content = payload }},
    }, .duplicate_checksum, .checksum_manifest);

    try expectRejected(.{
        .control = &.{.{ .path = "md5sums", .content = "0123456789abcdef0123456789abcdef usr/share/demo\n" }},
        .data = &.{.{ .path = "usr/share/demo", .content = payload }},
    }, .invalid_checksums, .checksum_manifest);

    try expectRejected(.{
        .control = &.{.{ .path = "md5sums", .content = "0123456789ABCDEF0123456789abcdef  usr/share/demo\n" }},
        .data = &.{.{ .path = "usr/share/demo", .content = payload }},
    }, .invalid_checksums, .checksum_manifest);

    try expectRejected(.{
        .control = &.{.{ .path = "md5sums", .content = valid[0 .. valid.len - 1] }},
        .data = &.{.{ .path = "usr/share/demo", .content = payload }},
    }, .invalid_checksums, .checksum_manifest);

    const absolute = try md5Line(testing.allocator, payload, "/usr/share/demo");
    defer testing.allocator.free(absolute);
    try expectRejected(.{
        .control = &.{.{ .path = "md5sums", .content = absolute }},
        .data = &.{.{ .path = "usr/share/demo", .content = payload }},
    }, .invalid_checksums, .checksum_manifest);
}

test "archive_application.test.hard-linked payload checksums verify the linked bytes" {
    const payload = "shared payload\n";
    const first = try md5Line(testing.allocator, payload, "usr/share/demo/file");
    defer testing.allocator.free(first);
    const second = try md5Line(testing.allocator, payload, "usr/share/demo/hard");
    defer testing.allocator.free(second);
    const manifest = try std.fmt.allocPrint(testing.allocator, "{s}{s}", .{ first, second });
    defer testing.allocator.free(manifest);

    const result = try prepareArchive(.{
        .control = &.{.{ .path = "md5sums", .content = manifest }},
        .data = &.{
            .{ .path = "usr/share/demo/file", .content = payload },
            .{ .path = "usr/share/demo/hard", .kind = '1', .link = "./usr/share/demo/file" },
        },
    });
    var model = switch (result) {
        .model => |value| value,
        .diagnostic => |diagnostic| {
            std.debug.print("unexpected diagnostic: {s}\n", .{diagnostic.message()});
            return error.TestUnexpectedResult;
        },
    };
    defer model.deinit();
    try testing.expectEqual(@as(usize, 2), model.checksums.len);
    try testing.expect(model.findFile("usr/share/demo/hard").?.md5 != null);
}

test "archive_application.test.debconf config script is modeled but not a lifecycle script" {
    const result = try prepareArchive(.{
        .control = &.{
            .{ .path = "config", .mode = 0o755, .content = "#!/bin/sh\nexit 0\n" },
            .{ .path = "templates", .content = "Template: demo/question\n" },
        },
        .data = &.{.{ .path = "usr/share/demo", .content = "payload\n" }},
    });
    var model = switch (result) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer model.deinit();
    const config = model.script(.config).?;
    try testing.expect(!config.kind.lifecycle());
    try testing.expectEqualStrings("config", config.name);
    try testing.expect(model.features.debconf_config_script);
    try testing.expect(!model.features.lifecycle_scripts);
    try testing.expect(model.features.retained_metadata);
}

test "archive_application.test.trigger declarations fail closed" {
    try expectRejected(
        .{ .control = &.{.{ .path = "triggers", .content = "interest-maybe demo\n" }} },
        .invalid_triggers,
        .trigger_declaration,
    );
    try expectRejected(
        .{ .control = &.{.{ .path = "triggers", .content = "interest\n" }} },
        .invalid_triggers,
        .trigger_declaration,
    );
    try expectRejected(
        .{ .control = &.{.{ .path = "triggers", .content = "interest ../escape\n" }} },
        .invalid_triggers,
        .trigger_declaration,
    );
    try expectRejected(
        .{ .control = &.{.{ .path = "triggers", .content = "interest /usr/../etc\n" }} },
        .invalid_triggers,
        .trigger_declaration,
    );
    try expectRejected(
        .{ .control = &.{.{ .path = "triggers", .content = "interest demo\ninterest-noawait demo\n" }} },
        .duplicate_trigger,
        .trigger_declaration,
    );
    try expectRejected(
        .{ .control = &.{.{ .path = "triggers", .content = "activate demo" }} },
        .invalid_triggers,
        .trigger_declaration,
    );
}

test "archive_application.test.conffile declarations must match the payload" {
    try expectRejected(.{
        .control = &.{.{ .path = "conffiles", .content = "/etc/demo.conf\n" }},
        .data = &.{.{ .path = "usr/share/demo", .content = "payload\n" }},
    }, .conffile_not_shipped, .conffile_declaration);

    try expectRejected(.{
        .control = &.{.{ .path = "conffiles", .content = "remove-on-upgrade /etc/demo.conf\n" }},
        .data = &.{.{ .path = "etc/demo.conf", .content = "payload\n" }},
    }, .conffile_unexpectedly_shipped, .conffile_declaration);

    const result = try prepareArchive(.{
        .control = &.{.{ .path = "conffiles", .content = "remove-on-upgrade /etc/demo.conf\n" }},
        .data = &.{.{ .path = "usr/share/demo", .content = "payload\n" }},
    });
    var model = switch (result) {
        .model => |value| value,
        .diagnostic => return error.TestUnexpectedResult,
    };
    defer model.deinit();
    try testing.expect(model.features.remove_on_upgrade_conffiles);
    try testing.expect(model.conffiles[0].file_index == null);
}

test "archive_application.test.unsupported archive features are classified" {
    const bytes = try buildArchive(testing.allocator, .{
        .data = &.{.{ .path = "usr/share/demo", .kind = '3' }},
    });
    defer testing.allocator.free(bytes);
    switch (prepare(testing.allocator, bytes, localRequest(), testLimits())) {
        .model => |value| {
            var model = value;
            model.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| {
            try testing.expectEqual(Code.payload_rejected, diagnostic.code);
            try testing.expectEqual(UnsupportedFeature.file_type, diagnostic.feature());
            try testing.expectEqual(
                deb_payload.Code.unsupported_file_type,
                diagnostic.payload.?.code,
            );
        },
    }

    const traversing = try buildArchive(testing.allocator, .{
        .data = &.{.{ .path = "usr/share/link", .kind = '2', .link = "../../../etc/passwd" }},
    });
    defer testing.allocator.free(traversing);
    switch (prepare(testing.allocator, traversing, localRequest(), testLimits())) {
        .model => |value| {
            var model = value;
            model.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| {
            try testing.expectEqual(UnsupportedFeature.path_or_link, diagnostic.feature());
        },
    }

    var truncated = try buildArchive(testing.allocator, .{
        .data = &.{.{ .path = "usr/share/demo", .content = "payload\n" }},
    });
    defer testing.allocator.free(truncated);
    switch (prepare(testing.allocator, truncated[0 .. truncated.len - 600], localRequest(), testLimits())) {
        .model => |value| {
            var model = value;
            model.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| {
            try testing.expectEqual(Stage.payload, diagnostic.stage);
            try testing.expect(diagnostic.payload != null);
        },
    }
}

test "archive_application.test.bounded limits reject oversized modeled metadata" {
    const bytes = try buildArchive(testing.allocator, .{
        .control = &.{.{ .path = "triggers", .content = "interest demo\ninterest other\n" }},
        .data = &.{.{ .path = "usr/share/demo", .content = "payload\n" }},
    });
    defer testing.allocator.free(bytes);

    var limits = testLimits();
    limits.max_trigger_declarations = 1;
    switch (prepare(testing.allocator, bytes, localRequest(), limits)) {
        .model => |value| {
            var model = value;
            model.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| {
            try testing.expectEqual(Code.trigger_limit, diagnostic.code);
            try testing.expectEqual(UnsupportedFeature.resource_limit, diagnostic.feature());
        },
    }

    var file_limits = testLimits();
    file_limits.max_files = 0;
    switch (prepare(testing.allocator, bytes, localRequest(), file_limits)) {
        .model => |value| {
            var model = value;
            model.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| try testing.expectEqual(Code.file_limit, diagnostic.code),
    }

    var member_limits = testLimits();
    member_limits.max_control_members = 1;
    switch (prepare(testing.allocator, bytes, localRequest(), member_limits)) {
        .model => |value| {
            var model = value;
            model.deinit();
            return error.TestUnexpectedResult;
        },
        .diagnostic => |diagnostic| try testing.expectEqual(Code.control_member_limit, diagnostic.code),
    }
}

test "archive_application.test.pinned repository fixtures model without approximation" {
    const fixtures = [_][]const u8{
        @embedFile("fixtures/packages-microsoft-prod_1.1_all.deb"),
        @embedFile("fixtures/packages-microsoft-prod-depends_1.1_all.deb"),
    };
    for (fixtures) |bytes| {
        var model = switch (prepare(testing.allocator, bytes, localRequest(), testLimits())) {
            .model => |value| value,
            .diagnostic => |diagnostic| {
                std.debug.print("unexpected diagnostic: {s}\n", .{diagnostic.message()});
                return error.TestUnexpectedResult;
            },
        };
        defer model.deinit();
        try testing.expect(model.features.regular_files);
        try testing.expect(model.features.directories);
        try testing.expect(!model.features.symlinks);
        try testing.expect(!model.features.hardlinks);
        try testing.expect(!model.features.checksums);
        try testing.expect(!model.features.lifecycle_scripts);
        try testing.expect(!model.features.conffiles);
        try testing.expectEqual(@as(usize, 0), model.triggers.len);
        try testing.expectEqual(ProvenanceKind.local_artifact, model.provenance().kind);
        try model.verifyArtifactBinding(bytes);
    }
}

test "archive_application.test.fuzz boundary releases every result" {
    const bytes = try buildArchive(testing.allocator, .{
        .data = &.{.{ .path = "usr/share/demo", .content = "payload\n" }},
    });
    defer testing.allocator.free(bytes);
    fuzzOne(testing.allocator, bytes, localRequest(), testLimits());
    fuzzOne(testing.allocator, bytes[0..8], localRequest(), testLimits());
    fuzzOne(testing.allocator, "", localRequest(), testLimits());
}
