const std = @import("std");
const deb_archive = @import("deb_archive.zig");
const metadata_decompression = @import("metadata_decompression.zig");
const control_record = @import("control_record.zig");

pub const Limits = struct {
    outer: deb_archive.Limits = .{},
    max_control_compressed_bytes: usize = 16 * 1024 * 1024,
    max_control_decompressed_bytes: usize = 64 * 1024 * 1024,
    max_data_compressed_bytes: usize = 1024 * 1024 * 1024,
    max_data_decompressed_bytes: usize = 4 * 1024 * 1024 * 1024,
    max_decoder_memory: u64 = 64 * 1024 * 1024,
    max_entries_per_tar: usize = 250_000,
    max_path_bytes: usize = 4096,
    max_link_bytes: usize = 4096,
    max_inventory_bytes_per_tar: usize = 128 * 1024 * 1024,
    max_control_file_bytes: usize = 4 * 1024 * 1024,
    max_conffiles_bytes: usize = 4 * 1024 * 1024,
    max_conffiles: usize = 100_000,
    max_maintainer_scripts: usize = 5,
    max_maintainer_script_bytes: usize = 64 * 1024 * 1024,
    max_total_maintainer_script_bytes: usize = 64 * 1024 * 1024,
    max_descriptor_entries: usize = 4096,
    max_descriptor_file_bytes: usize = 16 * 1024 * 1024,
    max_descriptor_source_bytes: usize = 1024 * 1024,
    max_descriptor_keyring_bytes: usize = 16 * 1024 * 1024,
    max_descriptor_scripts: usize = 4,
    max_descriptor_script_bytes: usize = 1024 * 1024,
    max_descriptor_total_script_bytes: u64 = 4 * 1024 * 1024,
    max_descriptor_total_bytes: u64 = 64 * 1024 * 1024,
    max_total_entry_bytes: u64 = 4 * 1024 * 1024 * 1024,
};

pub const Expected = struct {
    repository: []const u8,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    requested_package: []const u8,
    requested_version: ?[]const u8 = null,
    requested_architecture: ?[]const u8 = null,
    filename: []const u8,
    size: u64,
    sha256: [32]u8,
    require_conventional_filename: bool = true,
};

pub const Identity = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
};

pub const LocalProfile = enum {
    general,
    repository_descriptor,
};

pub const LocalExpected = struct {
    source: []const u8 = "local-artifact",
    filename: []const u8 = "",
    size: ?u64 = null,
    sha256: ?[32]u8 = null,
    identity: ?Identity = null,
    profile: LocalProfile = .general,
};

pub const Stage = enum {
    outer,
    digest,
    control_decompression,
    data_decompression,
    control_tar,
    data_tar,
    control_metadata,
    identity,
    conffiles,
    descriptor_profile,
};

pub const Code = enum {
    outer_archive,
    size_mismatch,
    digest_mismatch,
    decompression_failed,
    tar_truncated,
    tar_bad_checksum,
    tar_invalid_number,
    tar_size_overflow,
    tar_entry_limit,
    tar_payload_limit,
    tar_metadata_limit,
    tar_missing_end,
    tar_trailing_data,
    unsupported_tar_extension,
    unsafe_path,
    path_too_long,
    duplicate_path,
    conflicting_path,
    unsafe_link,
    link_too_long,
    forward_hardlink,
    unsupported_file_type,
    missing_control,
    duplicate_control,
    invalid_control,
    missing_identity,
    identity_mismatch,
    request_mismatch,
    filename_mismatch,
    invalid_conffiles,
    conffiles_limit,
    duplicate_conffile,
    maintainer_script_limit,
    descriptor_control_entry,
    descriptor_payload_path,
    descriptor_unsafe_mode,
    descriptor_link,
    descriptor_relationship,
    descriptor_limit,
    descriptor_missing_source,
    descriptor_missing_keyring,
    descriptor_conffile_mismatch,
    out_of_memory,
};

pub const Diagnostic = struct {
    stage: Stage,
    code: Code,
    offset: usize,
    inner_offset: ?usize = null,
    entry_index: ?usize = null,
    decompression_error: ?metadata_decompression.Error = null,
    outer: ?deb_archive.Diagnostic = null,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .outer_archive => "invalid outer Debian archive",
            .size_mismatch => "archive byte count does not match the supplied expectation",
            .digest_mismatch => "archive SHA-256 does not match the supplied expectation",
            .decompression_failed => "compressed tar member is corrupt, unsupported, trailing, or exceeds a resource limit",
            .tar_truncated => "tar header, entry content, or padding is truncated",
            .tar_bad_checksum => "tar header checksum is invalid",
            .tar_invalid_number => "tar numeric metadata is malformed or unsupported",
            .tar_size_overflow => "tar metadata arithmetic overflowed",
            .tar_entry_limit => "tar entry count exceeds the configured limit",
            .tar_payload_limit => "tar payload bytes exceed the configured limit",
            .tar_metadata_limit => "tar inventory metadata exceeds the configured memory limit",
            .tar_missing_end => "tar archive lacks two zero end blocks",
            .tar_trailing_data => "tar archive has malformed trailing data",
            .unsupported_tar_extension => "unsupported or malformed GNU/PAX tar extension metadata",
            .unsafe_path => "tar path is absolute, traversing, ambiguous, or contains an invalid component",
            .path_too_long => "tar path exceeds the configured limit",
            .duplicate_path => "tar contains duplicate or normalization-colliding paths",
            .conflicting_path => "tar paths or links conflict under archive interpretation",
            .unsafe_link => "tar link target is traversing, ambiguous, or symlink-mediated",
            .link_too_long => "tar link target exceeds the configured limit",
            .forward_hardlink => "hard links must reference an earlier regular file",
            .unsupported_file_type => "devices, FIFOs, sockets, and other special tar entries are rejected",
            .missing_control => "control.tar does not contain a control file",
            .duplicate_control => "control.tar contains more than one normalized control file",
            .invalid_control => "control metadata is malformed or exceeds its configured limit",
            .missing_identity => "control metadata lacks exactly one package identity record",
            .identity_mismatch => "control package, version, or architecture differs from authenticated metadata",
            .request_mismatch => "authenticated selection differs from the solver request",
            .filename_mismatch => "repository filename does not match the accepted package filename convention",
            .invalid_conffiles => "conffiles contains an unsafe or malformed path",
            .conffiles_limit => "conffiles exceeds the configured entry limit",
            .duplicate_conffile => "conffiles contains a duplicate normalized path",
            .maintainer_script_limit => "maintainer scripts exceed configured count or byte limits",
            .descriptor_control_entry => "repository descriptor contains an unsupported control archive entry",
            .descriptor_payload_path => "repository descriptor payload is outside approved repository configuration locations",
            .descriptor_unsafe_mode => "repository descriptor contains a setuid, setgid, or writable trust-bearing entry",
            .descriptor_link => "repository descriptor payload must not contain symbolic or hard links",
            .descriptor_relationship => "repository descriptor declares a disallowed package relationship or system importance flag",
            .descriptor_limit => "repository descriptor exceeds configured entry or byte limits",
            .descriptor_missing_source => "repository descriptor contains no static .list or .sources file",
            .descriptor_missing_keyring => "repository descriptor contains no static repository keyring",
            .descriptor_conffile_mismatch => "repository descriptor conffiles entry does not name a regular payload file",
            .out_of_memory => "validation allocation failed",
        };
    }
};

pub const EntryKind = enum { regular, directory, symlink, hardlink };

pub const Entry = struct {
    path: []u8,
    link_target: ?[]u8,
    kind: EntryKind,
    mode: u32,
    size: u64,
    header_offset: usize,
    content_offset: usize,
};

pub const TarInventory = struct {
    compression: deb_archive.Compression,
    compressed_bytes: usize,
    decompressed_bytes: usize,
    entries: []Entry,
    entry_headers: usize,
    inventory_bytes: usize,
    regular_bytes: u64,
};

pub const Script = struct {
    name: []const u8,
    mode: u32,
    size: u64,
};

pub const Conffile = struct {
    path: []u8,
    remove_on_upgrade: bool,
};

pub const ProvenanceKind = enum {
    authenticated_repository,
    local_artifact,
};

pub const Provenance = struct {
    kind: ProvenanceKind,
    repository: []u8,
    filename: []u8,
    size: u64,
    sha256: [32]u8,
};

pub const Relationships = struct {
    depends: ?[]u8,
    pre_depends: ?[]u8,
};

pub const PayloadFile = struct {
    path: []u8,
    bytes: []u8,
};

pub const PayloadFiles = struct {
    allocator: std.mem.Allocator,
    files: []PayloadFile,

    pub fn deinit(self: *PayloadFiles) void {
        for (self.files) |file| {
            self.allocator.free(file.path);
            self.allocator.free(file.bytes);
        }
        self.allocator.free(self.files);
        self.* = undefined;
    }
};

pub const PayloadCopyLimits = struct {
    max_files: usize = 16,
    max_file_bytes: usize = 4 * 1024 * 1024,
    max_total_bytes: usize = 16 * 1024 * 1024,
};

pub const PayloadAccessError = error{
    InvalidPath,
    MissingPath,
    NotRegularFile,
    FileTooLarge,
    TooManyFiles,
    TotalTooLarge,
    DuplicateRequest,
};

/// Owns all returned strings, inventories, and decompressed tar bytes. Entry
/// paths are canonical archive-root-relative paths; no filesystem is touched.
pub const Validation = struct {
    allocator: std.mem.Allocator,
    package: []u8,
    version: []u8,
    architecture: []u8,
    provenance: Provenance,
    relationships: Relationships,
    control: TarInventory,
    data: TarInventory,
    scripts: []Script,
    conffiles: []Conffile,
    control_bytes: []u8,
    data_bytes: []u8,

    pub fn deinit(self: *Validation) void {
        freeInventory(self.allocator, &self.control);
        freeInventory(self.allocator, &self.data);
        for (self.conffiles) |conffile| self.allocator.free(conffile.path);
        self.allocator.free(self.conffiles);
        self.allocator.free(self.scripts);
        self.allocator.free(self.package);
        self.allocator.free(self.version);
        self.allocator.free(self.architecture);
        self.allocator.free(self.provenance.repository);
        self.allocator.free(self.provenance.filename);
        if (self.relationships.depends) |value| self.allocator.free(value);
        if (self.relationships.pre_depends) |value| self.allocator.free(value);
        self.allocator.free(self.control_bytes);
        self.allocator.free(self.data_bytes);
        self.* = undefined;
    }

    /// Returns a bounded borrowed view of one validated regular data.tar file.
    /// `path` must be canonical and archive-root-relative (for example,
    /// `etc/apt/sources.list.d/vendor.list`).
    pub fn regularPayloadBytes(
        self: *const Validation,
        path: []const u8,
        maximum_bytes: usize,
    ) PayloadAccessError![]const u8 {
        if (!canonicalLookupPath(path)) return error.InvalidPath;
        for (self.data.entries) |entry| {
            if (!std.mem.eql(u8, entry.path, path)) continue;
            if (entry.kind != .regular) return error.NotRegularFile;
            if (entry.size > maximum_bytes) return error.FileTooLarge;
            return entryContent(self.data_bytes, entry) orelse error.MissingPath;
        }
        return error.MissingPath;
    }

    /// Copies a bounded, caller-selected set of validated regular data.tar
    /// files without unpacking the package or touching the filesystem.
    pub fn copyRegularPayloadFiles(
        self: *const Validation,
        allocator: std.mem.Allocator,
        paths: []const []const u8,
        limits: PayloadCopyLimits,
    ) (PayloadAccessError || std.mem.Allocator.Error)!PayloadFiles {
        if (paths.len > limits.max_files) return error.TooManyFiles;
        var files: std.ArrayList(PayloadFile) = .empty;
        errdefer {
            for (files.items) |file| {
                allocator.free(file.path);
                allocator.free(file.bytes);
            }
            files.deinit(allocator);
        }
        var total: usize = 0;
        for (paths, 0..) |path, index| {
            for (paths[0..index]) |previous| {
                if (std.mem.eql(u8, previous, path)) return error.DuplicateRequest;
            }
            const bytes = try self.regularPayloadBytes(path, limits.max_file_bytes);
            total = std.math.add(usize, total, bytes.len) catch return error.TotalTooLarge;
            if (total > limits.max_total_bytes) return error.TotalTooLarge;
            const owned_path = try allocator.dupe(u8, path);
            const owned_bytes = allocator.dupe(u8, bytes) catch |err| {
                allocator.free(owned_path);
                return err;
            };
            files.append(allocator, .{ .path = owned_path, .bytes = owned_bytes }) catch |err| {
                allocator.free(owned_path);
                allocator.free(owned_bytes);
                return err;
            };
        }
        return .{ .allocator = allocator, .files = try files.toOwnedSlice(allocator) };
    }
};

pub const Result = union(enum) {
    validation: Validation,
    diagnostic: Diagnostic,
};

pub fn validate(allocator: std.mem.Allocator, bytes: []const u8, expected: Expected, limits: Limits) Result {
    return validateInternal(allocator, bytes, .{ .repository = expected }, limits);
}

/// Validates a standalone `.deb` without pretending it was selected from
/// authenticated repository metadata. Identity is derived from the validated
/// control record. Optional size, digest, and identity expectations still fail
/// closed when supplied.
pub fn inspectLocal(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    expected: LocalExpected,
    limits: Limits,
) Result {
    return validateInternal(allocator, bytes, .{ .local = expected }, limits);
}

const ValidationRequest = union(enum) {
    repository: Expected,
    local: LocalExpected,
};

fn validateInternal(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    request: ValidationRequest,
    limits: Limits,
) Result {
    var ownership_transferred = false;
    const descriptor_profile = switch (request) {
        .repository => false,
        .local => |expected| expected.profile == .repository_descriptor,
    };
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    switch (request) {
        .repository => |expected| {
            if (bytes.len != expected.size) return fail(.digest, .size_mismatch, 0, null, null);
            if (!std.mem.eql(u8, &digest, &expected.sha256))
                return fail(.digest, .digest_mismatch, 0, null, null);
        },
        .local => |expected| {
            if (expected.size) |size| {
                if (bytes.len != size) return fail(.digest, .size_mismatch, 0, null, null);
            }
            if (expected.sha256) |sha256| {
                if (!std.mem.eql(u8, &digest, &sha256))
                    return fail(.digest, .digest_mismatch, 0, null, null);
            }
        },
    }

    const outer = switch (deb_archive.parse(bytes, limits.outer)) {
        .archive => |archive| archive,
        .diagnostic => |diagnostic| return .{ .diagnostic = .{
            .stage = .outer,
            .code = .outer_archive,
            .offset = diagnostic.offset,
            .outer = diagnostic,
        } },
    };

    var control_limits = limits;
    if (descriptor_profile) applyInitialDescriptorLimits(&control_limits);
    const control_bytes = decompressMember(allocator, outer, outer.control, true, control_limits) catch |err|
        return decompressionFailure(.control_decompression, outer.control.content.start, err);
    defer if (!ownership_transferred) allocator.free(control_bytes);

    var tar_diagnostic: Diagnostic = undefined;
    var control_tar = parseTar(allocator, control_bytes, outer.control, .control_tar, control_limits, &tar_diagnostic) catch
        return .{ .diagnostic = tar_diagnostic };
    defer if (!ownership_transferred) freeInventory(allocator, &control_tar);

    var data_limits = limits;
    if (descriptor_profile) applyRemainingDescriptorLimits(
        &data_limits,
        control_bytes.len,
        control_tar.entry_headers,
        control_tar.inventory_bytes,
        control_tar.regular_bytes,
    );
    const data_bytes = decompressMember(allocator, outer, outer.data, false, data_limits) catch |err|
        return decompressionFailure(.data_decompression, outer.data.content.start, err);
    defer if (!ownership_transferred) allocator.free(data_bytes);
    var data_tar = parseTar(allocator, data_bytes, outer.data, .data_tar, data_limits, &tar_diagnostic) catch
        return .{ .diagnostic = tar_diagnostic };
    defer if (!ownership_transferred) freeInventory(allocator, &data_tar);

    const control_entry = findControl(control_tar.entries) orelse
        return fail(.control_metadata, .missing_control, outer.control.content.start, null, null);
    const control_content = entryContent(control_bytes, control_entry) orelse
        return fail(.control_metadata, .invalid_control, outer.control.content.start + control_entry.header_offset, control_entry.header_offset, null);
    if (control_content.len > limits.max_control_file_bytes)
        return fail(.control_metadata, .invalid_control, outer.control.content.start + control_entry.content_offset, control_entry.content_offset, null);

    var document = switch (control_record.parseBorrowed(allocator, control_content, .{
        .limits = .{ .max_records = 1 },
    }) catch return fail(.control_metadata, .out_of_memory, outer.control.content.start, null, null)) {
        .document => |value| value,
        .diagnostic => |diagnostic| return fail(
            .control_metadata,
            .invalid_control,
            outer.control.content.start + control_entry.content_offset + diagnostic.span.start.offset,
            control_entry.content_offset + diagnostic.span.start.offset,
            null,
        ),
    };
    defer document.deinit();
    if (document.records.len != 1)
        return fail(.control_metadata, .missing_identity, outer.control.content.start + control_entry.content_offset, control_entry.content_offset, null);
    const record = &document.records[0];
    switch (request) {
        .repository => |expected| {
            if (!std.mem.eql(u8, record.package.text, expected.package) or
                !std.mem.eql(u8, record.version.value.original, expected.version) or
                !std.mem.eql(u8, record.architecture.text, expected.architecture))
                return fail(.identity, .identity_mismatch, outer.control.content.start + control_entry.content_offset, control_entry.content_offset, null);
            if (!std.mem.eql(u8, expected.requested_package, expected.package) or
                (expected.requested_version != null and !std.mem.eql(u8, expected.requested_version.?, expected.version)) or
                (expected.requested_architecture != null and !std.mem.eql(u8, expected.requested_architecture.?, expected.architecture)))
                return fail(.identity, .request_mismatch, 0, null, null);
            if (expected.require_conventional_filename and !validFilename(expected))
                return fail(.identity, .filename_mismatch, 0, null, null);
        },
        .local => |expected| {
            if (expected.identity) |identity| {
                if (!std.mem.eql(u8, record.package.text, identity.package) or
                    !std.mem.eql(u8, record.version.value.original, identity.version) or
                    !std.mem.eql(u8, record.architecture.text, identity.architecture))
                    return fail(.identity, .identity_mismatch, outer.control.content.start + control_entry.content_offset, control_entry.content_offset, null);
            }
        },
    }

    const package = allocator.dupe(u8, record.package.text) catch return oom();
    defer if (!ownership_transferred) allocator.free(package);
    const version = allocator.dupe(u8, record.version.value.original) catch return oom();
    defer if (!ownership_transferred) allocator.free(version);
    const architecture = allocator.dupe(u8, record.architecture.text) catch return oom();
    defer if (!ownership_transferred) allocator.free(architecture);
    const repository = allocator.dupe(u8, switch (request) {
        .repository => |expected| expected.repository,
        .local => |expected| expected.source,
    }) catch return oom();
    defer if (!ownership_transferred) allocator.free(repository);
    const filename = allocator.dupe(u8, switch (request) {
        .repository => |expected| expected.filename,
        .local => |expected| expected.filename,
    }) catch return oom();
    defer if (!ownership_transferred) allocator.free(filename);
    const depends = duplicateOptional(allocator, if (record.depends) |value| value.source else null) catch return oom();
    defer if (!ownership_transferred) if (depends) |value| allocator.free(value);
    const pre_depends = duplicateOptional(allocator, if (record.pre_depends) |value| value.source else null) catch return oom();
    defer if (!ownership_transferred) if (pre_depends) |value| allocator.free(value);

    var script_list: std.ArrayList(Script) = .empty;
    defer script_list.deinit(allocator);
    var total_script_bytes: usize = 0;
    for (control_tar.entries) |entry| {
        if (entry.kind == .regular and isScript(entry.path)) {
            if (script_list.items.len >= limits.max_maintainer_scripts or
                entry.size > limits.max_maintainer_script_bytes)
                return fail(.control_metadata, .maintainer_script_limit, outer.control.content.start + entry.header_offset, entry.header_offset, null);
            const script_size = std.math.cast(usize, entry.size) orelse
                return fail(.control_metadata, .maintainer_script_limit, outer.control.content.start + entry.header_offset, entry.header_offset, null);
            total_script_bytes = std.math.add(usize, total_script_bytes, script_size) catch
                return fail(.control_metadata, .maintainer_script_limit, outer.control.content.start + entry.header_offset, entry.header_offset, null);
            if (total_script_bytes > limits.max_total_maintainer_script_bytes)
                return fail(.control_metadata, .maintainer_script_limit, outer.control.content.start + entry.header_offset, entry.header_offset, null);
            script_list.append(allocator, .{ .name = scriptName(entry.path).?, .mode = entry.mode, .size = entry.size }) catch return oom();
        }
    }
    const scripts = script_list.toOwnedSlice(allocator) catch return oom();
    defer if (!ownership_transferred) allocator.free(scripts);
    var conffiles_diagnostic: Diagnostic = undefined;
    const conffiles = parseConffiles(allocator, control_bytes, control_tar.entries, limits, outer.control.content.start, &conffiles_diagnostic) catch
        return .{ .diagnostic = conffiles_diagnostic };
    defer if (!ownership_transferred) {
        for (conffiles) |conffile| allocator.free(conffile.path);
        allocator.free(conffiles);
    };
    switch (request) {
        .repository => {},
        .local => |expected| if (expected.profile == .repository_descriptor) {
            if (validateDescriptorProfile(
                record,
                package,
                control_tar.entries,
                data_tar.entries,
                scripts,
                conffiles,
                outer.control,
                outer.data,
                limits,
            )) |diagnostic| return .{ .diagnostic = diagnostic };
        },
    }

    ownership_transferred = true;
    return .{ .validation = .{
        .allocator = allocator,
        .package = package,
        .version = version,
        .architecture = architecture,
        .provenance = .{
            .kind = switch (request) {
                .repository => .authenticated_repository,
                .local => .local_artifact,
            },
            .repository = repository,
            .filename = filename,
            .size = bytes.len,
            .sha256 = digest,
        },
        .relationships = .{
            .depends = depends,
            .pre_depends = pre_depends,
        },
        .control = control_tar,
        .data = data_tar,
        .scripts = scripts,
        .conffiles = conffiles,
        .control_bytes = control_bytes,
        .data_bytes = data_bytes,
    } };
}

fn duplicateOptional(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) std.mem.Allocator.Error!?[]u8 {
    return if (value) |bytes| try allocator.dupe(u8, bytes) else null;
}

fn validateDescriptorProfile(
    record: *const control_record.Record,
    package: []const u8,
    control_entries: []const Entry,
    data_entries: []const Entry,
    scripts: []const Script,
    conffiles: []const Conffile,
    control_member: deb_archive.Member,
    data_member: deb_archive.Member,
    limits: Limits,
) ?Diagnostic {
    if (record.essential == true or
        record.protected == true or
        record.important == true or
        record.built_using != null or
        record.pre_depends != null or
        record.recommends != null or
        record.suggests != null or
        record.enhances != null or
        record.provides != null or
        record.conflicts != null or
        record.breaks != null or
        record.replaces != null)
    {
        return fail(.descriptor_profile, .descriptor_relationship, control_member.content.start, null, null).diagnostic;
    }

    if (control_entries.len +| data_entries.len > limits.max_descriptor_entries) {
        return fail(.descriptor_profile, .descriptor_limit, control_member.content.start, null, null).diagnostic;
    }
    if (scripts.len > limits.max_descriptor_scripts) {
        return fail(.descriptor_profile, .descriptor_limit, control_member.content.start, null, null).diagnostic;
    }
    var total_script_bytes: u64 = 0;
    for (scripts) |script| {
        if (script.size > limits.max_descriptor_script_bytes) {
            return fail(.descriptor_profile, .descriptor_limit, control_member.content.start, null, null).diagnostic;
        }
        total_script_bytes = std.math.add(u64, total_script_bytes, script.size) catch
            return fail(.descriptor_profile, .descriptor_limit, control_member.content.start, null, null).diagnostic;
        if (total_script_bytes > limits.max_descriptor_total_script_bytes) {
            return fail(.descriptor_profile, .descriptor_limit, control_member.content.start, null, null).diagnostic;
        }
    }
    for (control_entries, 0..) |entry, index| {
        if (entry.mode & 0o6000 != 0) {
            return profileFailure(.descriptor_unsafe_mode, control_member, entry, index);
        }
        if (!descriptorControlEntryAllowed(entry)) {
            return profileFailure(.descriptor_control_entry, control_member, entry, index);
        }
    }

    var source_count: usize = 0;
    var keyring_count: usize = 0;
    var total_bytes: u64 = 0;
    for (data_entries, 0..) |entry, index| {
        if (entry.mode & 0o6000 != 0) {
            return profileFailure(.descriptor_unsafe_mode, data_member, entry, index);
        }
        if (entry.kind == .symlink or entry.kind == .hardlink) {
            return profileFailure(.descriptor_link, data_member, entry, index);
        }
        const classification = classifyDescriptorPath(entry.path, entry.kind, package);
        if (!classification.allowed) {
            return profileFailure(.descriptor_payload_path, data_member, entry, index);
        }
        if (classification.trust_bearing and entry.mode & 0o022 != 0) {
            return profileFailure(.descriptor_unsafe_mode, data_member, entry, index);
        }
        if (entry.kind == .regular) {
            if (entry.size > limits.max_descriptor_file_bytes or
                (classification.source and entry.size > limits.max_descriptor_source_bytes) or
                (classification.keyring and entry.size > limits.max_descriptor_keyring_bytes))
            {
                return profileFailure(.descriptor_limit, data_member, entry, index);
            }
            total_bytes = std.math.add(u64, total_bytes, entry.size) catch
                return profileFailure(.descriptor_limit, data_member, entry, index);
            if (total_bytes > limits.max_descriptor_total_bytes)
                return profileFailure(.descriptor_limit, data_member, entry, index);
            if (classification.source) source_count += 1;
            if (classification.keyring) keyring_count += 1;
        }
    }
    if (source_count == 0) {
        return fail(.descriptor_profile, .descriptor_missing_source, data_member.content.start, null, null).diagnostic;
    }
    if (keyring_count == 0) {
        return fail(.descriptor_profile, .descriptor_missing_keyring, data_member.content.start, null, null).diagnostic;
    }

    for (conffiles) |conffile| {
        var matched = false;
        for (data_entries) |entry| {
            if (entry.kind == .regular and std.mem.eql(u8, entry.path, conffile.path)) {
                matched = true;
                break;
            }
        }
        if (!matched) {
            return fail(.descriptor_profile, .descriptor_conffile_mismatch, data_member.content.start, null, null).diagnostic;
        }
    }
    return null;
}

fn descriptorControlEntryAllowed(entry: Entry) bool {
    if (entry.kind != .regular) return false;
    inline for (.{ "control", "md5sums", "conffiles", "preinst", "postinst", "prerm", "postrm" }) |allowed| {
        if (std.mem.eql(u8, entry.path, allowed)) return true;
    }
    return false;
}

const DescriptorPathClassification = struct {
    allowed: bool = false,
    source: bool = false,
    keyring: bool = false,
    trust_bearing: bool = false,
};

fn classifyDescriptorPath(path: []const u8, kind: EntryKind, package: []const u8) DescriptorPathClassification {
    const source_roots = [_][]const u8{"etc/apt/sources.list.d"};
    const keyring_roots = [_][]const u8{
        "etc/apt/keyrings",
        "etc/apt/trusted.gpg.d",
        "usr/share/keyrings",
    };
    const tree_roots = [_][]const u8{
        "etc/debsig/policies",
        "usr/share/debsig/keyrings",
    };

    if (kind == .directory) {
        for (source_roots ++ keyring_roots ++ tree_roots) |root| {
            if (isPathAncestorOrEqual(path, root) or isPathWithin(path, root))
                return .{ .allowed = true, .trust_bearing = true };
        }
        if (isPackageDocPath(path, package, true))
            return .{ .allowed = true, .trust_bearing = true };
        if (isLintianPath(path, package, true)) return .{ .allowed = true };
        return .{};
    }

    for (source_roots) |root| {
        if (isDirectChild(path, root) and
            (std.mem.endsWith(u8, path, ".list") or std.mem.endsWith(u8, path, ".sources")))
            return .{ .allowed = true, .source = true, .trust_bearing = true };
    }
    for (keyring_roots) |root| {
        if (isDirectChild(path, root) and
            (std.mem.endsWith(u8, path, ".gpg") or
                std.mem.endsWith(u8, path, ".pgp") or
                std.mem.endsWith(u8, path, ".asc")))
            return .{ .allowed = true, .keyring = true, .trust_bearing = true };
    }
    for (tree_roots) |root| {
        if (isPathWithin(path, root)) return .{ .allowed = true, .trust_bearing = true };
    }
    if (isPackageDocPath(path, package, false))
        return .{ .allowed = true, .trust_bearing = trustFileSuffix(path) };
    if (isLintianPath(path, package, false)) return .{ .allowed = true };
    return .{};
}

fn trustFileSuffix(path: []const u8) bool {
    inline for (.{ ".list", ".sources", ".gpg", ".pgp", ".asc", ".pol" }) |suffix| {
        if (std.mem.endsWith(u8, path, suffix)) return true;
    }
    return false;
}

fn isPathAncestorOrEqual(path: []const u8, root: []const u8) bool {
    return std.mem.eql(u8, path, root) or
        (path.len < root.len and std.mem.startsWith(u8, root, path) and root[path.len] == '/');
}

fn isPathWithin(path: []const u8, root: []const u8) bool {
    return path.len > root.len and std.mem.startsWith(u8, path, root) and path[root.len] == '/';
}

fn isDirectChild(path: []const u8, root: []const u8) bool {
    if (!isPathWithin(path, root)) return false;
    return std.mem.indexOfScalar(u8, path[root.len + 1 ..], '/') == null;
}

fn isPackageDocPath(path: []const u8, package: []const u8, directory: bool) bool {
    const prefix = "usr/share/doc/";
    if (isPathAncestorOrEqual(path, "usr/share/doc")) return directory;
    if (!std.mem.startsWith(u8, path, prefix)) return false;
    const remainder = path[prefix.len..];
    if (remainder.len < package.len or !std.mem.startsWith(u8, remainder, package)) return false;
    if (remainder.len == package.len) return directory;
    return remainder[package.len] == '/';
}

fn isLintianPath(path: []const u8, package: []const u8, directory: bool) bool {
    const root = "usr/share/lintian/overrides";
    if (isPathAncestorOrEqual(path, root)) return directory;
    if (!isDirectChild(path, root)) return false;
    return std.mem.eql(u8, path[root.len + 1 ..], package);
}

fn profileFailure(
    code: Code,
    member: deb_archive.Member,
    entry: Entry,
    index: usize,
) Diagnostic {
    return .{
        .stage = .descriptor_profile,
        .code = code,
        .offset = member.content.start + entry.header_offset,
        .inner_offset = entry.header_offset,
        .entry_index = index,
    };
}

fn applyInitialDescriptorLimits(limits: *Limits) void {
    const maximum_bytes = descriptorBytesAsUsize(limits.max_descriptor_total_bytes);
    limits.max_control_compressed_bytes = @min(limits.max_control_compressed_bytes, maximum_bytes);
    limits.max_control_decompressed_bytes = @min(limits.max_control_decompressed_bytes, maximum_bytes);
    limits.max_entries_per_tar = @min(limits.max_entries_per_tar, limits.max_descriptor_entries);
    limits.max_inventory_bytes_per_tar = @min(limits.max_inventory_bytes_per_tar, maximum_bytes);
    limits.max_total_entry_bytes = @min(limits.max_total_entry_bytes, limits.max_descriptor_total_bytes);
}

fn applyRemainingDescriptorLimits(
    limits: *Limits,
    control_decompressed_bytes: usize,
    control_entry_headers: usize,
    control_inventory_bytes: usize,
    control_regular_bytes: u64,
) void {
    const maximum_bytes = descriptorBytesAsUsize(limits.max_descriptor_total_bytes);
    const remaining_decompressed = maximum_bytes -| control_decompressed_bytes;
    const remaining_entries = limits.max_descriptor_entries -| control_entry_headers;
    const remaining_inventory = maximum_bytes -| control_inventory_bytes;
    const remaining_regular = limits.max_descriptor_total_bytes -| control_regular_bytes;
    limits.max_data_compressed_bytes = @min(limits.max_data_compressed_bytes, maximum_bytes);
    limits.max_data_decompressed_bytes = @min(limits.max_data_decompressed_bytes, remaining_decompressed);
    limits.max_entries_per_tar = @min(limits.max_entries_per_tar, remaining_entries);
    limits.max_inventory_bytes_per_tar = @min(limits.max_inventory_bytes_per_tar, remaining_inventory);
    limits.max_total_entry_bytes = @min(limits.max_total_entry_bytes, remaining_regular);
}

fn descriptorBytesAsUsize(maximum: u64) usize {
    return std.math.cast(usize, maximum) orelse std.math.maxInt(usize);
}

fn decompressMember(allocator: std.mem.Allocator, archive: deb_archive.Archive, member: deb_archive.Member, is_control: bool, limits: Limits) metadata_decompression.Error![]u8 {
    const input = archive.memberBytes(member);
    const max_compressed = if (is_control) limits.max_control_compressed_bytes else limits.max_data_compressed_bytes;
    const max_decompressed = if (is_control) limits.max_control_decompressed_bytes else limits.max_data_decompressed_bytes;
    if (input.len > max_compressed) return error.InputLimitExceeded;
    return switch (member.compression) {
        .uncompressed => blk: {
            if (input.len > max_decompressed) return error.OutputLimitExceeded;
            break :blk allocator.dupe(u8, input) catch error.OutOfMemory;
        },
        .gzip, .xz, .zstd => metadata_decompression.decompress(allocator, switch (member.compression) {
            .gzip => .gzip,
            .xz => .xz,
            .zstd => .zstd,
            else => unreachable,
        }, input, .{
            .maximum_compressed_bytes = max_compressed,
            .maximum_decompressed_bytes = max_decompressed,
            .maximum_decoder_memory = limits.max_decoder_memory,
        }),
    };
}

fn decompressionFailure(stage: Stage, offset: usize, err: metadata_decompression.Error) Result {
    return .{ .diagnostic = .{ .stage = stage, .code = .decompression_failed, .offset = offset, .decompression_error = err } };
}

fn parseTar(allocator: std.mem.Allocator, bytes: []const u8, member: deb_archive.Member, stage: Stage, limits: Limits, diagnostic: *Diagnostic) error{Invalid}!TarInventory {
    var entries: std.ArrayList(Entry) = .empty;
    errdefer {
        for (entries.items) |entry| freeEntry(allocator, entry);
        entries.deinit(allocator);
    }
    var paths = std.StringHashMap(EntryKind).init(allocator);
    defer paths.deinit();
    var regular_bytes: u64 = 0;
    var inventory_bytes: usize = 0;
    var offset: usize = 0;
    var zero_blocks: usize = 0;
    var header_count: usize = 0;
    var pending_long_name: ?[]u8 = null;
    defer if (pending_long_name) |value| allocator.free(value);
    var pending_long_link: ?[]u8 = null;
    defer if (pending_long_link) |value| allocator.free(value);

    while (offset < bytes.len) {
        const end = std.math.add(usize, offset, 512) catch return setTarFailure(diagnostic, stage, .tar_size_overflow, member, offset, entries.items.len);
        if (end > bytes.len) return setTarFailure(diagnostic, stage, .tar_truncated, member, offset, entries.items.len);
        const header = bytes[offset..end];
        if (allZero(header)) {
            zero_blocks += 1;
            offset = end;
            if (zero_blocks == 2) break;
            continue;
        }
        if (zero_blocks != 0) return setTarFailure(diagnostic, stage, .tar_missing_end, member, offset, entries.items.len);
        if (header_count >= limits.max_entries_per_tar)
            return setTarFailure(diagnostic, stage, .tar_entry_limit, member, offset, entries.items.len);
        header_count += 1;
        if (!validChecksum(header))
            return setTarFailure(diagnostic, stage, .tar_bad_checksum, member, offset, entries.items.len);
        const tar_format: TarFormat = if (std.mem.eql(u8, header[257..263], "ustar\x00") and
            std.mem.eql(u8, header[263..265], "00"))
            .posix
        else if (std.mem.eql(u8, header[257..265], "ustar  \x00"))
            .gnu
        else
            return setTarFailure(diagnostic, stage, .unsupported_tar_extension, member, offset + 257, entries.items.len);
        const size = parseOctal(header[124..136]) orelse
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 124, entries.items.len);
        const content_offset = end;
        const size_usize: usize = std.math.cast(usize, size) orelse
            return setTarFailure(diagnostic, stage, .tar_size_overflow, member, offset + 124, entries.items.len);
        const content_end = std.math.add(usize, content_offset, size_usize) catch
            return setTarFailure(diagnostic, stage, .tar_size_overflow, member, content_offset, entries.items.len);
        if (content_end > bytes.len)
            return setTarFailure(diagnostic, stage, .tar_truncated, member, content_offset, entries.items.len);
        const padded = std.math.add(usize, content_end, (512 - (size_usize % 512)) % 512) catch
            return setTarFailure(diagnostic, stage, .tar_size_overflow, member, content_end, entries.items.len);
        if (padded > bytes.len)
            return setTarFailure(diagnostic, stage, .tar_truncated, member, content_end, entries.items.len);
        for (bytes[content_end..padded]) |byte| if (byte != 0)
            return setTarFailure(diagnostic, stage, .tar_trailing_data, member, content_end, entries.items.len);
        const mode_u64 = parseOctal(header[100..108]) orelse
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 100, entries.items.len);
        _ = parseOctal(header[108..116]) orelse
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 108, entries.items.len);
        _ = parseOctal(header[116..124]) orelse
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 116, entries.items.len);
        _ = parseOctal(header[136..148]) orelse
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 136, entries.items.len);
        _ = parseOctal(header[329..337]) orelse
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 329, entries.items.len);
        _ = parseOctal(header[337..345]) orelse
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 337, entries.items.len);
        if (mode_u64 > std.math.maxInt(u32))
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 100, entries.items.len);
        const typeflag = header[156];
        if (typeflag == 'x' or typeflag == 'g')
            return setTarFailure(diagnostic, stage, .unsupported_tar_extension, member, offset + 156, entries.items.len);
        if (typeflag == 'L' or typeflag == 'K') {
            if (tar_format != .gnu)
                return setTarFailure(diagnostic, stage, .unsupported_tar_extension, member, offset + 156, entries.items.len);
            const maximum = if (typeflag == 'L') limits.max_path_bytes else limits.max_link_bytes;
            const content = bytes[content_offset..content_end];
            if (content.len < 2 or content.len - 1 > maximum or content[content.len - 1] != 0 or
                std.mem.indexOfScalar(u8, content[0 .. content.len - 1], 0) != null)
                return setTarFailure(diagnostic, stage, if (typeflag == 'L') .unsafe_path else .unsafe_link, member, content_offset, entries.items.len);
            const destination = if (typeflag == 'L') &pending_long_name else &pending_long_link;
            if (destination.* != null)
                return setTarFailure(diagnostic, stage, .unsupported_tar_extension, member, offset + 156, entries.items.len);
            destination.* = allocator.dupe(u8, content[0 .. content.len - 1]) catch
                return setTarFailure(diagnostic, stage, .out_of_memory, member, content_offset, entries.items.len);
            regular_bytes = std.math.add(u64, regular_bytes, size) catch
                return setTarFailure(diagnostic, stage, .tar_payload_limit, member, offset + 124, entries.items.len);
            if (regular_bytes > limits.max_total_entry_bytes)
                return setTarFailure(diagnostic, stage, .tar_payload_limit, member, offset + 124, entries.items.len);
            offset = padded;
            continue;
        }
        const kind: EntryKind = switch (typeflag) {
            0, '0' => .regular,
            '5' => .directory,
            '2' => .symlink,
            '1' => .hardlink,
            else => return setTarFailure(diagnostic, stage, .unsupported_file_type, member, offset + 156, entries.items.len),
        };
        if (kind != .regular and size != 0)
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 124, entries.items.len);
        const raw_name = if (pending_long_name) |value| value else fieldString(header[0..100]) orelse
            return setTarFailure(diagnostic, stage, .unsafe_path, member, offset, entries.items.len);
        if (kind == .directory and
            (std.mem.eql(u8, raw_name, ".") or std.mem.eql(u8, raw_name, "./")))
        {
            const raw_link = if (pending_long_link) |value| value else fieldString(header[157..257]) orelse
                return setTarFailure(diagnostic, stage, .unsafe_link, member, offset + 157, entries.items.len);
            if (raw_link.len != 0)
                return setTarFailure(diagnostic, stage, .unsafe_link, member, offset + 157, entries.items.len);
            if (pending_long_name) |value| {
                allocator.free(value);
                pending_long_name = null;
            }
            if (pending_long_link) |value| {
                allocator.free(value);
                pending_long_link = null;
            }
            offset = padded;
            continue;
        }
        const path = canonicalTarPath(allocator, header, tar_format, pending_long_name, limits.max_path_bytes) catch |err| switch (err) {
            error.OutOfMemory => return setTarFailure(diagnostic, stage, .out_of_memory, member, offset, entries.items.len),
            error.TooLong => return setTarFailure(diagnostic, stage, .path_too_long, member, offset, entries.items.len),
            else => return setTarFailure(diagnostic, stage, .unsafe_path, member, offset, entries.items.len),
        };
        errdefer allocator.free(path);
        if (paths.contains(path))
            return setTarFailure(diagnostic, stage, .duplicate_path, member, offset, entries.items.len);
        if (pathConflict(&paths, path, kind))
            return setTarFailure(diagnostic, stage, .conflicting_path, member, offset, entries.items.len);

        var link_target: ?[]u8 = null;
        if (kind == .symlink or kind == .hardlink) {
            const raw_link = if (pending_long_link) |value| value else fieldString(header[157..257]) orelse
                return setTarFailure(diagnostic, stage, .unsafe_link, member, offset + 157, entries.items.len);
            if (raw_link.len > limits.max_link_bytes)
                return setTarFailure(diagnostic, stage, .link_too_long, member, offset + 157, entries.items.len);
            const target = resolveLink(allocator, path, raw_link, kind == .hardlink, limits.max_path_bytes) catch |err| switch (err) {
                error.OutOfMemory => return setTarFailure(diagnostic, stage, .out_of_memory, member, offset + 157, entries.items.len),
                error.TooLong => return setTarFailure(diagnostic, stage, .link_too_long, member, offset + 157, entries.items.len),
                else => return setTarFailure(diagnostic, stage, .unsafe_link, member, offset + 157, entries.items.len),
            };
            if (kind == .hardlink) {
                const target_kind = paths.get(target) orelse {
                    allocator.free(target);
                    return setTarFailure(diagnostic, stage, .forward_hardlink, member, offset + 157, entries.items.len);
                };
                if (target_kind != .regular) {
                    allocator.free(target);
                    return setTarFailure(diagnostic, stage, .unsafe_link, member, offset + 157, entries.items.len);
                }
            } else if (hasSymlinkAncestor(&paths, target)) {
                allocator.free(target);
                return setTarFailure(diagnostic, stage, .conflicting_path, member, offset + 157, entries.items.len);
            }
            link_target = target;
        } else if (pending_long_link != null)
            return setTarFailure(diagnostic, stage, .unsupported_tar_extension, member, offset + 156, entries.items.len);
        errdefer if (link_target) |target| allocator.free(target);
        if (hasSymlinkAncestor(&paths, path))
            return setTarFailure(diagnostic, stage, .conflicting_path, member, offset, entries.items.len);
        if (kind == .symlink and makesExistingLinkTargetSymlinkMediated(entries.items, path))
            return setTarFailure(diagnostic, stage, .conflicting_path, member, offset, entries.items.len);
        inventory_bytes = std.math.add(usize, inventory_bytes, @sizeOf(Entry)) catch
            return setTarFailure(diagnostic, stage, .tar_metadata_limit, member, offset, entries.items.len);
        inventory_bytes = std.math.add(usize, inventory_bytes, path.len) catch
            return setTarFailure(diagnostic, stage, .tar_metadata_limit, member, offset, entries.items.len);
        if (link_target) |target| {
            inventory_bytes = std.math.add(usize, inventory_bytes, target.len) catch
                return setTarFailure(diagnostic, stage, .tar_metadata_limit, member, offset, entries.items.len);
        }
        if (inventory_bytes > limits.max_inventory_bytes_per_tar)
            return setTarFailure(diagnostic, stage, .tar_metadata_limit, member, offset, entries.items.len);

        regular_bytes = std.math.add(u64, regular_bytes, size) catch
            return setTarFailure(diagnostic, stage, .tar_payload_limit, member, offset + 124, entries.items.len);
        if (regular_bytes > limits.max_total_entry_bytes)
            return setTarFailure(diagnostic, stage, .tar_payload_limit, member, offset + 124, entries.items.len);

        paths.put(path, kind) catch return setTarFailure(diagnostic, stage, .out_of_memory, member, offset, entries.items.len);
        entries.append(allocator, .{
            .path = path,
            .link_target = link_target,
            .kind = kind,
            .mode = @intCast(mode_u64),
            .size = size,
            .header_offset = offset,
            .content_offset = content_offset,
        }) catch return setTarFailure(diagnostic, stage, .out_of_memory, member, offset, entries.items.len);
        if (pending_long_name) |value| {
            allocator.free(value);
            pending_long_name = null;
        }
        if (pending_long_link) |value| {
            allocator.free(value);
            pending_long_link = null;
        }
        offset = padded;
    }
    if (pending_long_name != null or pending_long_link != null)
        return setTarFailure(diagnostic, stage, .unsupported_tar_extension, member, offset, entries.items.len);
    if (zero_blocks < 2) return setTarFailure(diagnostic, stage, .tar_missing_end, member, offset, entries.items.len);
    while (offset < bytes.len) : (offset += 512) {
        if (bytes.len - offset < 512 or !allZero(bytes[offset .. offset + 512]))
            return setTarFailure(diagnostic, stage, .tar_trailing_data, member, offset, entries.items.len);
    }
    return .{
        .compression = member.compression,
        .compressed_bytes = member.size,
        .decompressed_bytes = bytes.len,
        .entries = entries.toOwnedSlice(allocator) catch return setTarFailure(diagnostic, stage, .out_of_memory, member, 0, null),
        .entry_headers = header_count,
        .inventory_bytes = inventory_bytes,
        .regular_bytes = regular_bytes,
    };
}

fn setTarFailure(diagnostic: *Diagnostic, stage: Stage, code: Code, member: deb_archive.Member, inner: usize, entry: ?usize) error{Invalid} {
    diagnostic.* = .{ .stage = stage, .code = code, .offset = member.content.start + inner, .inner_offset = inner, .entry_index = entry };
    return error.Invalid;
}

const TarFormat = enum { posix, gnu };

fn canonicalTarPath(allocator: std.mem.Allocator, header: []const u8, format: TarFormat, long_name: ?[]const u8, maximum: usize) ![]u8 {
    if (long_name) |name| return canonicalPath(allocator, name, maximum, false);
    const name = fieldString(header[0..100]) orelse return error.Unsafe;
    if (format == .gnu) return canonicalPath(allocator, name, maximum, false);
    const prefix = fieldString(header[345..500]) orelse return error.Unsafe;
    if (prefix.len == 0) return canonicalPath(allocator, name, maximum, false);
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(allocator);
    try joined.appendSlice(allocator, prefix);
    try joined.append(allocator, '/');
    try joined.appendSlice(allocator, name);
    return canonicalPath(allocator, joined.items, maximum, false);
}

fn fieldString(field: []const u8) ?[]const u8 {
    const end = std.mem.indexOfScalar(u8, field, 0) orelse field.len;
    for (field[end..]) |byte| if (byte != 0) return null;
    return field[0..end];
}

fn canonicalPath(allocator: std.mem.Allocator, raw_input: []const u8, maximum: usize, allow_dotdot: bool) ![]u8 {
    if (raw_input.len == 0 or raw_input[0] == '/') return error.Unsafe;
    var raw = raw_input;
    if (std.mem.startsWith(u8, raw, "./")) raw = raw[2..];
    while (raw.len > 1 and raw[raw.len - 1] == '/') raw = raw[0 .. raw.len - 1];
    if (raw.len == 0 or raw.len > maximum) return if (raw.len > maximum) error.TooLong else error.Unsafe;
    var components = std.mem.splitScalar(u8, raw, '/');
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".")) return error.Unsafe;
        if (std.mem.eql(u8, component, "..")) {
            if (!allow_dotdot) return error.Unsafe;
            const slash = std.mem.lastIndexOfScalar(u8, output.items, '/') orelse {
                if (output.items.len == 0) return error.Unsafe;
                output.clearRetainingCapacity();
                continue;
            };
            output.shrinkRetainingCapacity(slash);
            continue;
        }
        for (component) |byte| if (byte < 0x20 or byte == 0x7f) return error.Unsafe;
        if (output.items.len != 0) try output.append(allocator, '/');
        try output.appendSlice(allocator, component);
        if (output.items.len > maximum) return error.TooLong;
    }
    if (output.items.len == 0) return error.Unsafe;
    return output.toOwnedSlice(allocator);
}

fn canonicalLookupPath(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path, '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return false;
        for (component) |byte| {
            if (byte < 0x20 or byte == 0x7f) return false;
        }
    }
    return true;
}

fn resolveLink(allocator: std.mem.Allocator, path: []const u8, raw: []const u8, hardlink: bool, maximum: usize) ![]u8 {
    if (hardlink) return canonicalPath(allocator, raw, maximum, false);
    if (raw.len == 0) return error.Unsafe;
    if (raw[0] == '/') return canonicalPath(allocator, raw[1..], maximum, false);
    const parent_end = std.mem.lastIndexOfScalar(u8, path, '/') orelse 0;
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(allocator);
    if (parent_end != 0) {
        try joined.appendSlice(allocator, path[0..parent_end]);
        try joined.append(allocator, '/');
    }
    try joined.appendSlice(allocator, raw);
    return canonicalPath(allocator, joined.items, maximum, true);
}

fn pathConflict(paths: *const std.StringHashMap(EntryKind), path: []const u8, kind: EntryKind) bool {
    var cursor: usize = 0;
    while (std.mem.indexOfScalarPos(u8, path, cursor, '/')) |slash| {
        if (paths.get(path[0..slash])) |ancestor| if (ancestor != .directory) return true;
        cursor = slash + 1;
    }
    var iterator = paths.iterator();
    while (iterator.next()) |entry| {
        if (std.mem.startsWith(u8, entry.key_ptr.*, path) and entry.key_ptr.*.len > path.len and entry.key_ptr.*[path.len] == '/' and kind != .directory)
            return true;
    }
    return false;
}

fn hasSymlinkAncestor(paths: *const std.StringHashMap(EntryKind), path: []const u8) bool {
    var cursor: usize = 0;
    while (std.mem.indexOfScalarPos(u8, path, cursor, '/')) |slash| {
        if (paths.get(path[0..slash]) == .symlink) return true;
        cursor = slash + 1;
    }
    return false;
}

fn makesExistingLinkTargetSymlinkMediated(entries: []const Entry, path: []const u8) bool {
    for (entries) |entry| {
        if (entry.kind != .symlink) continue;
        const target = entry.link_target.?;
        if (std.mem.eql(u8, target, path) or
            (target.len > path.len and std.mem.startsWith(u8, target, path) and target[path.len] == '/'))
            return true;
    }
    return false;
}

fn validChecksum(header: []const u8) bool {
    const declared = parseOctal(header[148..156]) orelse return false;
    var sum: u64 = 0;
    for (header, 0..) |byte, index| sum += if (index >= 148 and index < 156) ' ' else byte;
    return sum == declared;
}

fn parseOctal(field: []const u8) ?u64 {
    if (field.len == 0 or field[0] & 0x80 != 0) return null;
    var index: usize = 0;
    while (index < field.len and (field[index] == 0 or field[index] == ' ')) index += 1;
    var value: u64 = 0;
    var digit_seen = false;
    while (index < field.len and field[index] >= '0' and field[index] <= '7') : (index += 1) {
        digit_seen = true;
        value = std.math.mul(u64, value, 8) catch return null;
        value = std.math.add(u64, value, field[index] - '0') catch return null;
    }
    while (index < field.len) : (index += 1) if (field[index] != 0 and field[index] != ' ') return null;
    return if (digit_seen) value else 0;
}

fn allZero(bytes: []const u8) bool {
    for (bytes) |byte| if (byte != 0) return false;
    return true;
}

fn findControl(entries: []const Entry) ?Entry {
    var found: ?Entry = null;
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.path, "control")) {
            if (entry.kind != .regular or found != null) return null;
            found = entry;
        }
    }
    return found;
}

fn entryContent(bytes: []const u8, entry: Entry) ?[]const u8 {
    const size: usize = std.math.cast(usize, entry.size) orelse return null;
    const end = std.math.add(usize, entry.content_offset, size) catch return null;
    if (end > bytes.len) return null;
    return bytes[entry.content_offset..end];
}

fn isScript(path: []const u8) bool {
    return scriptName(path) != null;
}

fn scriptName(path: []const u8) ?[]const u8 {
    inline for (.{ "preinst", "postinst", "prerm", "postrm", "config" }) |name|
        if (std.mem.eql(u8, path, name)) return name;
    return null;
}

fn parseConffiles(allocator: std.mem.Allocator, bytes: []const u8, entries: []const Entry, limits: Limits, member_offset: usize, diagnostic: *Diagnostic) error{Invalid}![]Conffile {
    var result: std.ArrayList(Conffile) = .empty;
    var paths = std.StringHashMap(void).init(allocator);
    defer paths.deinit();
    errdefer {
        for (result.items) |conffile| allocator.free(conffile.path);
        result.deinit(allocator);
    }
    for (entries) |entry| {
        if (!std.mem.eql(u8, entry.path, "conffiles")) continue;
        if (entry.kind != .regular or entry.size > limits.max_conffiles_bytes)
            return setFailure(diagnostic, .conffiles, .invalid_conffiles, member_offset + entry.header_offset);
        const content = entryContent(bytes, entry) orelse
            return setFailure(diagnostic, .conffiles, .invalid_conffiles, member_offset + entry.content_offset);
        var lines = std.mem.splitScalar(u8, content, '\n');
        while (lines.next()) |raw_line| {
            const line = std.mem.trim(u8, raw_line, " \t\r");
            if (line.len == 0) continue;
            const remove_on_upgrade = !std.mem.startsWith(u8, line, "/");
            const path_text = if (remove_on_upgrade) blk: {
                const separator = std.mem.indexOfAny(u8, line, " \t") orelse
                    return setFailure(diagnostic, .conffiles, .invalid_conffiles, member_offset + entry.content_offset);
                if (!std.mem.eql(u8, line[0..separator], "remove-on-upgrade"))
                    return setFailure(diagnostic, .conffiles, .invalid_conffiles, member_offset + entry.content_offset);
                const value = std.mem.trimStart(u8, line[separator..], " \t");
                if (value.len == 0 or std.mem.indexOfAny(u8, value, " \t") != null)
                    return setFailure(diagnostic, .conffiles, .invalid_conffiles, member_offset + entry.content_offset);
                break :blk value;
            } else line;
            if (path_text[0] != '/' or std.mem.indexOfAny(u8, path_text, " \t") != null)
                return setFailure(diagnostic, .conffiles, .invalid_conffiles, member_offset + entry.content_offset);
            if (result.items.len >= limits.max_conffiles)
                return setFailure(diagnostic, .conffiles, .conffiles_limit, member_offset + entry.content_offset);
            const path = canonicalPath(allocator, path_text[1..], limits.max_path_bytes, false) catch |err| switch (err) {
                error.OutOfMemory => return setFailure(diagnostic, .conffiles, .out_of_memory, member_offset + entry.content_offset),
                else => return setFailure(diagnostic, .conffiles, .invalid_conffiles, member_offset + entry.content_offset),
            };
            if (paths.contains(path)) {
                allocator.free(path);
                return setFailure(diagnostic, .conffiles, .duplicate_conffile, member_offset + entry.content_offset);
            }
            paths.put(path, {}) catch {
                allocator.free(path);
                return setFailure(diagnostic, .conffiles, .out_of_memory, member_offset + entry.content_offset);
            };
            result.append(allocator, .{ .path = path, .remove_on_upgrade = remove_on_upgrade }) catch {
                _ = paths.remove(path);
                allocator.free(path);
                return setFailure(diagnostic, .conffiles, .out_of_memory, member_offset + entry.content_offset);
            };
        }
    }
    return result.toOwnedSlice(allocator) catch
        return setFailure(diagnostic, .conffiles, .out_of_memory, member_offset);
}

fn setFailure(diagnostic: *Diagnostic, stage: Stage, code: Code, offset: usize) error{Invalid} {
    diagnostic.* = .{ .stage = stage, .code = code, .offset = offset };
    return error.Invalid;
}

fn validFilename(expected: Expected) bool {
    const basename = std.fs.path.basename(expected.filename);
    const version = if (std.mem.indexOfScalar(u8, expected.version, ':')) |colon|
        expected.version[colon + 1 ..]
    else
        expected.version;
    var buffer: [8192]u8 = undefined;
    const conventional = std.fmt.bufPrint(&buffer, "{s}_{s}_{s}.deb", .{
        expected.package, version, expected.architecture,
    }) catch return false;
    return std.mem.eql(u8, basename, conventional);
}

fn freeEntry(allocator: std.mem.Allocator, entry: Entry) void {
    allocator.free(entry.path);
    if (entry.link_target) |target| allocator.free(target);
}

fn freeInventory(allocator: std.mem.Allocator, inventory: *TarInventory) void {
    for (inventory.entries) |entry| freeEntry(allocator, entry);
    allocator.free(inventory.entries);
    inventory.* = undefined;
}

fn fail(stage: Stage, code: Code, offset: usize, inner: ?usize, entry: ?usize) Result {
    return .{ .diagnostic = .{ .stage = stage, .code = code, .offset = offset, .inner_offset = inner, .entry_index = entry } };
}

fn oom() Result {
    return fail(.identity, .out_of_memory, 0, null, null);
}

/// Fuzz-friendly, side-effect-free boundary. It performs full validation and
/// releases a successful result immediately.
pub fn fuzzOne(allocator: std.mem.Allocator, bytes: []const u8, expected: Expected, limits: Limits) void {
    var result = validate(allocator, bytes, expected, limits);
    switch (result) {
        .validation => |*value| value.deinit(),
        .diagnostic => {},
    }
}

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

fn appendTarEntry(allocator: std.mem.Allocator, tar: *std.ArrayList(u8), path: []const u8, kind: u8, mode: u32, link: []const u8, content: []const u8) !void {
    var header: [512]u8 = @splat(0);
    std.mem.copyForwards(u8, header[0..], path);
    writeOctal(header[100..108], mode);
    writeOctal(header[108..116], 0);
    writeOctal(header[116..124], 0);
    writeOctal(header[124..136], content.len);
    writeOctal(header[136..148], 0);
    @memset(header[148..156], ' ');
    header[156] = kind;
    std.mem.copyForwards(u8, header[157..], link);
    std.mem.copyForwards(u8, header[257..], "ustar\x00");
    std.mem.copyForwards(u8, header[263..], "00");
    var checksum: u64 = 0;
    for (header) |byte| checksum += byte;
    writeOctal(header[148..156], checksum);
    try tar.appendSlice(allocator, &header);
    try tar.appendSlice(allocator, content);
    const padding = (512 - (content.len % 512)) % 512;
    try tar.appendNTimes(allocator, 0, padding);
}

fn appendGnuTarEntry(allocator: std.mem.Allocator, tar: *std.ArrayList(u8), path: []const u8, kind: u8, mode: u32, link: []const u8, content: []const u8) !void {
    const header_offset = tar.items.len;
    try appendTarEntry(allocator, tar, path, kind, mode, link, content);
    const header = tar.items[header_offset .. header_offset + 512];
    std.mem.copyForwards(u8, header[257..265], "ustar  \x00");
    @memset(header[148..156], ' ');
    var checksum: u64 = 0;
    for (header) |byte| checksum += byte;
    writeOctal(header[148..156], checksum);
}

fn finishTar(allocator: std.mem.Allocator, tar: *std.ArrayList(u8)) !void {
    try tar.appendNTimes(allocator, 0, 1024);
}

fn appendAr(allocator: std.mem.Allocator, ar: *std.ArrayList(u8), name: []const u8, content: []const u8) !void {
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

fn testDebWithConffiles(allocator: std.mem.Allocator, bad_data_path: ?[]const u8, conffiles: []const u8) ![]u8 {
    var control: std.ArrayList(u8) = .empty;
    defer control.deinit(allocator);
    try appendTarEntry(allocator, &control, "./control", '0', 0o644, "", "Package: demo\nVersion: 1.0\nArchitecture: amd64\n");
    try appendTarEntry(allocator, &control, "./postinst", '0', 0o755, "", "#!/bin/sh\n");
    try appendTarEntry(allocator, &control, "./conffiles", '0', 0o644, "", conffiles);
    try finishTar(allocator, &control);
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    try appendTarEntry(allocator, &data, bad_data_path orelse "./usr/bin/demo", '0', 0o755, "", "ok");
    try finishTar(allocator, &data);
    var ar: std.ArrayList(u8) = .empty;
    errdefer ar.deinit(allocator);
    try ar.appendSlice(allocator, "!<arch>\n");
    try appendAr(allocator, &ar, "debian-binary/", "2.0\n");
    try appendAr(allocator, &ar, "control.tar/", control.items);
    try appendAr(allocator, &ar, "data.tar/", data.items);
    return ar.toOwnedSlice(allocator);
}

fn testDeb(allocator: std.mem.Allocator, bad_data_path: ?[]const u8) ![]u8 {
    return testDebWithConffiles(allocator, bad_data_path, "/etc/demo.conf\n");
}

const DescriptorTestOptions = struct {
    extra_control_fields: []const u8 = "",
    extra_data_path: ?[]const u8 = null,
    source_mode: u32 = 0o644,
    source_kind: u8 = '0',
    keyring_mode: u32 = 0o644,
    doc_trust_mode: u32 = 0o644,
    source_parent_mode: u32 = 0o755,
    keyring_parent_mode: u32 = 0o755,
};

fn descriptorTestDeb(allocator: std.mem.Allocator, options: DescriptorTestOptions) ![]u8 {
    var control: std.ArrayList(u8) = .empty;
    defer control.deinit(allocator);
    const metadata = try std.fmt.allocPrint(
        allocator,
        "Package: repo-config\nVersion: 2.0\nArchitecture: all\nDepends: ca-certificates\n{s}",
        .{options.extra_control_fields},
    );
    defer allocator.free(metadata);
    try appendTarEntry(allocator, &control, "./control", '0', 0o644, "", metadata);
    try appendTarEntry(allocator, &control, "./md5sums", '0', 0o644, "", "");
    try appendTarEntry(
        allocator,
        &control,
        "./conffiles",
        '0',
        0o644,
        "",
        "/etc/" ++ "apt/sources.list.d/vendor.list\n" ++
            "/usr/share/keyrings/vendor.gpg\n" ++
            "/etc/debsig/policies/ABC/vendor.pol\n",
    );
    try appendTarEntry(allocator, &control, "./preinst", '0', 0o755, "", "#!/bin/sh\nexit 0\n");
    try appendTarEntry(allocator, &control, "./postinst", '0', 0o755, "", "#!/bin/sh\nexit 0\n");
    try appendTarEntry(allocator, &control, "./prerm", '0', 0o755, "", "#!/bin/sh\nexit 0\n");
    try finishTar(allocator, &control);

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);
    try appendTarEntry(allocator, &data, "./etc", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./etc/" ++ "apt", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./etc/" ++ "apt/sources.list.d", '5', options.source_parent_mode, "", "");
    try appendTarEntry(
        allocator,
        &data,
        "./etc/" ++ "apt/sources.list.d/vendor.list",
        options.source_kind,
        options.source_mode,
        if (options.source_kind == '2') "other.list" else "",
        if (options.source_kind == '0') "deb [signed-by=/usr/share/keyrings/vendor.gpg] https://example.test stable main\n" else "",
    );
    try appendTarEntry(allocator, &data, "./usr", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./usr/share", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./usr/share/keyrings", '5', options.keyring_parent_mode, "", "");
    try appendTarEntry(allocator, &data, "./usr/share/keyrings/vendor.gpg", '0', options.keyring_mode, "", "keyring");
    try appendTarEntry(allocator, &data, "./etc/debsig", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./etc/debsig/policies", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./etc/debsig/policies/ABC", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./etc/debsig/policies/ABC/vendor.pol", '0', 0o644, "", "policy");
    try appendTarEntry(allocator, &data, "./usr/share/debsig", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./usr/share/debsig/keyrings", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./usr/share/debsig/keyrings/ABC", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./usr/share/debsig/keyrings/ABC/vendor.gpg", '0', 0o644, "", "debsig-key");
    try appendTarEntry(allocator, &data, "./usr/share/doc", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./usr/share/doc/repo-config", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./usr/share/doc/repo-config/copyright", '0', 0o644, "", "copyright");
    try appendTarEntry(allocator, &data, "./usr/share/doc/repo-config/vendor.list", '0', options.doc_trust_mode, "", "deb https://example.test stable main\n");
    try appendTarEntry(allocator, &data, "./usr/share/lintian", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./usr/share/lintian/overrides", '5', 0o755, "", "");
    try appendTarEntry(allocator, &data, "./usr/share/lintian/overrides/repo-config", '0', 0o644, "", "override");
    if (options.extra_data_path) |path|
        try appendTarEntry(allocator, &data, path, '0', 0o644, "", "unexpected");
    try finishTar(allocator, &data);

    var ar: std.ArrayList(u8) = .empty;
    errdefer ar.deinit(allocator);
    try ar.appendSlice(allocator, "!<arch>\n");
    try appendAr(allocator, &ar, "debian-binary/", "2.0\n");
    try appendAr(allocator, &ar, "control.tar/", control.items);
    try appendAr(allocator, &ar, "data.tar/", data.items);
    try appendAr(allocator, &ar, "_gpgorigin/", "structural signature only");
    return ar.toOwnedSlice(allocator);
}

fn expectedFor(bytes: []const u8) Expected {
    const digest = metadataDigest(bytes);
    return .{
        .repository = "stable",
        .package = "demo",
        .version = "1.0",
        .architecture = "amd64",
        .requested_package = "demo",
        .filename = "pool/demo_1.0_amd64.deb",
        .size = bytes.len,
        .sha256 = digest,
    };
}

fn metadataDigest(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

test "full validation inventories scripts conffiles and payload without unpacking" {
    const allocator = std.testing.allocator;
    const bytes = try testDeb(allocator, null);
    defer allocator.free(bytes);
    const result = validate(allocator, bytes, expectedFor(bytes), .{});
    var validation = switch (result) {
        .validation => |value| value,
        .diagnostic => |diagnostic| {
            std.debug.print("{s} at {d}\n", .{ diagnostic.message(), diagnostic.offset });
            return error.UnexpectedDiagnostic;
        },
    };
    defer validation.deinit();
    try std.testing.expectEqualStrings("demo", validation.package);
    try std.testing.expectEqual(@as(usize, 1), validation.scripts.len);
    try std.testing.expectEqualStrings("postinst", validation.scripts[0].name);
    try std.testing.expectEqualStrings("etc/demo.conf", validation.conffiles[0].path);
    try std.testing.expectEqual(@as(usize, 1), validation.data.entries.len);
}

test "local inspection derives identity and copies selected static repository files" {
    const allocator = std.testing.allocator;
    const bytes = try descriptorTestDeb(allocator, .{});
    defer allocator.free(bytes);
    const digest = metadataDigest(bytes);
    const result = inspectLocal(allocator, bytes, .{
        .source = "https://example.test/repo-config.deb",
        .filename = "repo-config.deb",
        .size = bytes.len,
        .sha256 = digest,
        .profile = .repository_descriptor,
    }, .{});
    var validation = switch (result) {
        .validation => |value| value,
        .diagnostic => |diagnostic| {
            std.debug.print("{s} at {d}\n", .{ diagnostic.message(), diagnostic.offset });
            return error.UnexpectedDiagnostic;
        },
    };
    defer validation.deinit();

    try std.testing.expectEqualStrings("repo-config", validation.package);
    try std.testing.expectEqualStrings("2.0", validation.version);
    try std.testing.expectEqualStrings("all", validation.architecture);
    try std.testing.expectEqual(ProvenanceKind.local_artifact, validation.provenance.kind);
    try std.testing.expectEqualStrings("ca-certificates", validation.relationships.depends.?);
    try std.testing.expectEqual(@as(usize, 3), validation.scripts.len);

    const source_bytes = try validation.regularPayloadBytes(
        "etc/apt/sources.list.d/vendor.list",
        1024,
    );
    try std.testing.expect(std.mem.startsWith(u8, source_bytes, "deb "));
    try std.testing.expectError(
        error.FileTooLarge,
        validation.regularPayloadBytes("usr/share/keyrings/vendor.gpg", 3),
    );
    try std.testing.expectError(
        error.InvalidPath,
        validation.regularPayloadBytes("../vendor.gpg", 1024),
    );

    var selected = try validation.copyRegularPayloadFiles(allocator, &.{
        "etc/apt/sources.list.d/vendor.list",
        "usr/share/keyrings/vendor.gpg",
    }, .{ .max_files = 2, .max_file_bytes = 1024, .max_total_bytes = 2048 });
    defer selected.deinit();
    try std.testing.expectEqual(@as(usize, 2), selected.files.len);
    try std.testing.expectEqualStrings("keyring", selected.files[1].bytes);
    try std.testing.expectError(
        error.DuplicateRequest,
        validation.copyRegularPayloadFiles(allocator, &.{
            "usr/share/keyrings/vendor.gpg",
            "usr/share/keyrings/vendor.gpg",
        }, .{}),
    );
    try std.testing.expectError(
        error.TooManyFiles,
        validation.copyRegularPayloadFiles(allocator, &.{
            "etc/apt/sources.list.d/vendor.list",
            "usr/share/keyrings/vendor.gpg",
        }, .{ .max_files = 1 }),
    );
    try std.testing.expectError(
        error.TotalTooLarge,
        validation.copyRegularPayloadFiles(allocator, &.{
            "etc/apt/sources.list.d/vendor.list",
            "usr/share/keyrings/vendor.gpg",
        }, .{ .max_total_bytes = 8 }),
    );
    try std.testing.expectError(
        error.MissingPath,
        validation.regularPayloadBytes("usr/share/keyrings/missing.gpg", 1024),
    );
}

test "local inspection enforces optional digest size and identity expectations" {
    const allocator = std.testing.allocator;
    const bytes = try descriptorTestDeb(allocator, .{});
    defer allocator.free(bytes);
    var bad_digest = metadataDigest(bytes);
    bad_digest[0] ^= 1;
    try std.testing.expectEqual(Code.digest_mismatch, inspectLocal(allocator, bytes, .{
        .sha256 = bad_digest,
    }, .{}).diagnostic.code);
    try std.testing.expectEqual(Code.size_mismatch, inspectLocal(allocator, bytes, .{
        .size = bytes.len + 1,
    }, .{}).diagnostic.code);
    try std.testing.expectEqual(Code.identity_mismatch, inspectLocal(allocator, bytes, .{
        .identity = .{ .package = "other", .version = "2.0", .architecture = "all" },
    }, .{}).diagnostic.code);
}

test "repository descriptor profile rejects unsafe payloads relationships and script excess" {
    const allocator = std.testing.allocator;

    const outside = try descriptorTestDeb(allocator, .{ .extra_data_path = "./usr/bin/tool" });
    defer allocator.free(outside);
    try std.testing.expectEqual(Code.descriptor_payload_path, inspectLocal(allocator, outside, .{
        .profile = .repository_descriptor,
    }, .{}).diagnostic.code);

    const setuid = try descriptorTestDeb(allocator, .{ .source_mode = 0o4644 });
    defer allocator.free(setuid);
    try std.testing.expectEqual(Code.descriptor_unsafe_mode, inspectLocal(allocator, setuid, .{
        .profile = .repository_descriptor,
    }, .{}).diagnostic.code);

    const linked = try descriptorTestDeb(allocator, .{ .source_mode = 0o777, .source_kind = '2' });
    defer allocator.free(linked);
    try std.testing.expectEqual(Code.descriptor_link, inspectLocal(allocator, linked, .{
        .profile = .repository_descriptor,
    }, .{}).diagnostic.code);

    const conflicting = try descriptorTestDeb(allocator, .{ .extra_control_fields = "Conflicts: apt\n" });
    defer allocator.free(conflicting);
    try std.testing.expectEqual(Code.descriptor_relationship, inspectLocal(allocator, conflicting, .{
        .profile = .repository_descriptor,
    }, .{}).diagnostic.code);

    const scripts = try descriptorTestDeb(allocator, .{});
    defer allocator.free(scripts);
    try std.testing.expectEqual(Code.maintainer_script_limit, inspectLocal(allocator, scripts, .{
        .profile = .repository_descriptor,
    }, .{ .max_maintainer_scripts = 2 }).diagnostic.code);
    try std.testing.expectEqual(Code.descriptor_limit, inspectLocal(allocator, scripts, .{
        .profile = .repository_descriptor,
    }, .{ .max_descriptor_source_bytes = 8 }).diagnostic.code);
}

test "repository descriptor rejects writable trust files and parent directories" {
    const allocator = std.testing.allocator;
    const cases = [_]DescriptorTestOptions{
        .{ .source_mode = 0o664 },
        .{ .keyring_mode = 0o646 },
        .{ .doc_trust_mode = 0o666 },
        .{ .source_parent_mode = 0o775 },
        .{ .keyring_parent_mode = 0o757 },
    };
    for (cases) |options| {
        const bytes = try descriptorTestDeb(allocator, options);
        defer allocator.free(bytes);
        const result = inspectLocal(allocator, bytes, .{
            .profile = .repository_descriptor,
        }, .{});
        try std.testing.expectEqual(Stage.descriptor_profile, result.diagnostic.stage);
        try std.testing.expectEqual(Code.descriptor_unsafe_mode, result.diagnostic.code);
    }
}

test "repository descriptor bounds apply before data decompression and inventory materialization" {
    const allocator = std.testing.allocator;
    const bytes = try descriptorTestDeb(allocator, .{});
    defer allocator.free(bytes);
    const archive = deb_archive.parse(bytes, .{}).archive;

    const decompression_result = inspectLocal(allocator, bytes, .{
        .profile = .repository_descriptor,
    }, .{
        .max_descriptor_total_bytes = archive.control.size + 512,
    });
    try std.testing.expectEqual(Stage.data_decompression, decompression_result.diagnostic.stage);
    try std.testing.expectEqual(Code.decompression_failed, decompression_result.diagnostic.code);

    const inventory_result = inspectLocal(allocator, bytes, .{
        .profile = .repository_descriptor,
    }, .{
        .max_descriptor_entries = 6,
    });
    try std.testing.expectEqual(Stage.data_tar, inventory_result.diagnostic.stage);
    try std.testing.expectEqual(Code.tar_entry_limit, inventory_result.diagnostic.code);
}

test "validates plain gzip xz and zstd payload members" {
    const allocator = std.testing.allocator;
    const cases = .{
        .{ "control.tar/", "data.tar/", @embedFile("fixtures/deb-payload/control.tar"), @embedFile("fixtures/deb-payload/data.tar") },
        .{ "control.tar.gz/", "data.tar.gz/", @embedFile("fixtures/deb-payload/control.tar.gz"), @embedFile("fixtures/deb-payload/data.tar.gz") },
        .{ "control.tar.xz/", "data.tar.xz/", @embedFile("fixtures/deb-payload/control.tar.xz"), @embedFile("fixtures/deb-payload/data.tar.xz") },
        .{ "control.tar.zst/", "data.tar.zst/", @embedFile("fixtures/deb-payload/control.tar.zst"), @embedFile("fixtures/deb-payload/data.tar.zst") },
    };
    inline for (cases) |case| {
        var ar: std.ArrayList(u8) = .empty;
        defer ar.deinit(allocator);
        try ar.appendSlice(allocator, "!<arch>\n");
        try appendAr(allocator, &ar, "debian-binary/", "2.0\n");
        try appendAr(allocator, &ar, case[0], case[2]);
        try appendAr(allocator, &ar, case[1], case[3]);
        var result = validate(allocator, ar.items, expectedFor(ar.items), .{});
        switch (result) {
            .validation => |*validation| validation.deinit(),
            .diagnostic => |diagnostic| {
                std.debug.print("{s} at {d}\n", .{ diagnostic.message(), diagnostic.offset });
                return error.UnexpectedDiagnostic;
            },
        }
    }
}

test "compressed payload corruption and truncation fail without partial success" {
    const allocator = std.testing.allocator;
    inline for (.{
        .{ "control.tar.gz/", @embedFile("fixtures/deb-payload/control.tar.gz") },
        .{ "control.tar.xz/", @embedFile("fixtures/deb-payload/control.tar.xz") },
        .{ "control.tar.zst/", @embedFile("fixtures/deb-payload/control.tar.zst") },
    }) |case| {
        var ar: std.ArrayList(u8) = .empty;
        defer ar.deinit(allocator);
        try ar.appendSlice(allocator, "!<arch>\n");
        try appendAr(allocator, &ar, "debian-binary/", "2.0\n");
        try appendAr(allocator, &ar, case[0], case[1][0 .. case[1].len - 1]);
        try appendAr(allocator, &ar, "data.tar/", @embedFile("fixtures/deb-payload/data.tar"));
        try std.testing.expectEqual(Code.decompression_failed, validate(allocator, ar.items, expectedFor(ar.items), .{}).diagnostic.code);
    }
}

test "rejects traversal identity digest limits and corrupt tar" {
    const allocator = std.testing.allocator;
    const traversal = try testDeb(allocator, "../evil");
    defer allocator.free(traversal);
    try std.testing.expectEqual(Code.unsafe_path, validate(allocator, traversal, expectedFor(traversal), .{}).diagnostic.code);

    const bytes = try testDeb(allocator, null);
    defer allocator.free(bytes);
    var bad_identity = expectedFor(bytes);
    bad_identity.package = "other";
    bad_identity.requested_package = "other";
    try std.testing.expectEqual(Code.identity_mismatch, validate(allocator, bytes, bad_identity, .{}).diagnostic.code);
    var bad_digest = expectedFor(bytes);
    bad_digest.sha256[0] ^= 1;
    try std.testing.expectEqual(Code.digest_mismatch, validate(allocator, bytes, bad_digest, .{}).diagnostic.code);
    try std.testing.expectEqual(Code.decompression_failed, validate(allocator, bytes, expectedFor(bytes), .{
        .max_data_decompressed_bytes = 1,
    }).diagnostic.code);

    var corrupt = try allocator.dupe(u8, bytes);
    defer allocator.free(corrupt);
    const outer = deb_archive.parse(corrupt, .{}).archive;
    corrupt[outer.data.content.start] ^= 1;
    const expected = expectedFor(corrupt);
    try std.testing.expectEqual(Code.tar_bad_checksum, validate(allocator, corrupt, expected, .{}).diagnostic.code);
}

test "conffiles inventory rejects duplicates and entry bombs" {
    const allocator = std.testing.allocator;
    const flagged = try testDebWithConffiles(allocator, null, "remove-on-upgrade /etc/demo.conf\n");
    defer allocator.free(flagged);
    const flagged_result = validate(allocator, flagged, expectedFor(flagged), .{});
    var flagged_validation = switch (flagged_result) {
        .validation => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer flagged_validation.deinit();
    try std.testing.expect(flagged_validation.conffiles[0].remove_on_upgrade);

    const unknown_flag = try testDebWithConffiles(allocator, null, "unknown /etc/demo.conf\n");
    defer allocator.free(unknown_flag);
    try std.testing.expectEqual(Code.invalid_conffiles, validate(allocator, unknown_flag, expectedFor(unknown_flag), .{}).diagnostic.code);

    const duplicate = try testDebWithConffiles(allocator, null, "/etc/demo.conf\n/etc/demo.conf\n");
    defer allocator.free(duplicate);
    try std.testing.expectEqual(Code.duplicate_conffile, validate(allocator, duplicate, expectedFor(duplicate), .{}).diagnostic.code);

    const limited = try testDebWithConffiles(allocator, null, "/etc/a\n/etc/b\n");
    defer allocator.free(limited);
    try std.testing.expectEqual(Code.conffiles_limit, validate(allocator, limited, expectedFor(limited), .{
        .max_conffiles = 1,
    }).diagnostic.code);
}

test "rejects duplicate paths special files unsafe links and entry bombs" {
    const allocator = std.testing.allocator;
    var tar: std.ArrayList(u8) = .empty;
    defer tar.deinit(allocator);
    try appendTarEntry(allocator, &tar, "./a", '0', 0o644, "", "");
    try appendTarEntry(allocator, &tar, "a", '0', 0o644, "", "");
    try finishTar(allocator, &tar);
    const member: deb_archive.Member = .{ .kind = .data, .compression = .uncompressed, .name = "data.tar", .header = .{ .start = 0, .end = 0 }, .content = .{ .start = 20, .end = 20 + tar.items.len }, .timestamp = 0, .size = tar.items.len };
    try std.testing.expectError(error.DuplicatePath, parseTarTest(allocator, tar.items, member, .{}));

    inline for (.{ '3', '4', '6', '7', 's' }) |typeflag| {
        tar.clearRetainingCapacity();
        try appendTarEntry(allocator, &tar, "dev/x", typeflag, 0, "", "");
        try finishTar(allocator, &tar);
        try std.testing.expectError(error.Unsupported, parseTarTest(allocator, tar.items, member, .{}));
    }

    tar.clearRetainingCapacity();
    try appendTarEntry(allocator, &tar, "x", '2', 0o777, "../../etc", "");
    try finishTar(allocator, &tar);
    try std.testing.expectError(error.UnsafeLink, parseTarTest(allocator, tar.items, member, .{}));

    tar.clearRetainingCapacity();
    try appendTarEntry(allocator, &tar, "a", '0', 0, "", "");
    try appendTarEntry(allocator, &tar, "b", '0', 0, "", "");
    try finishTar(allocator, &tar);
    try std.testing.expectError(error.EntryLimit, parseTarTest(allocator, tar.items, member, .{ .max_entries_per_tar = 1 }));
    try std.testing.expectError(error.MetadataLimit, parseTarTest(allocator, tar.items, member, .{ .max_inventory_bytes_per_tar = 1 }));

    tar.clearRetainingCapacity();
    try appendTarEntry(allocator, &tar, "link", '1', 0o644, "future", "");
    try appendTarEntry(allocator, &tar, "future", '0', 0o644, "", "");
    try finishTar(allocator, &tar);
    try std.testing.expectError(error.ForwardHardlink, parseTarTest(allocator, tar.items, member, .{}));

    tar.clearRetainingCapacity();
    try appendTarEntry(allocator, &tar, "root", '2', 0o777, "safe", "");
    try appendTarEntry(allocator, &tar, "root/file", '0', 0o644, "", "");
    try finishTar(allocator, &tar);
    try std.testing.expectError(error.Conflict, parseTarTest(allocator, tar.items, member, .{}));
    tar.clearRetainingCapacity();
    try appendTarEntry(allocator, &tar, "a", '2', 0o777, "b", "");
    try appendTarEntry(allocator, &tar, "b", '2', 0o777, "a", "");
    try finishTar(allocator, &tar);
    try std.testing.expectError(error.Conflict, parseTarTest(allocator, tar.items, member, .{}));

    tar.clearRetainingCapacity();
    try appendTarEntry(allocator, &tar, "a", '2', 0o777, "b/c", "");
    try appendTarEntry(allocator, &tar, "b", '2', 0o777, "safe", "");
    try finishTar(allocator, &tar);
    try std.testing.expectError(error.Conflict, parseTarTest(allocator, tar.items, member, .{}));

    tar.clearRetainingCapacity();
    try appendTarEntry(allocator, &tar, "a", '0', 0o644, "", "");
    try finishTar(allocator, &tar);
    @memset(tar.items[257..265], 0);
    var checksum_header = tar.items[0..512];
    @memset(checksum_header[148..156], ' ');
    var checksum: u64 = 0;
    for (checksum_header) |byte| checksum += byte;
    writeOctal(checksum_header[148..156], checksum);
    try std.testing.expectError(error.Unsupported, parseTarTest(allocator, tar.items, member, .{}));
}

test "accepts GNU base headers but rejects GNU and PAX extension records" {
    const allocator = std.testing.allocator;
    var tar: std.ArrayList(u8) = .empty;
    defer tar.deinit(allocator);
    try appendGnuTarEntry(allocator, &tar, "./", '5', 0o755, "", "");
    try appendGnuTarEntry(allocator, &tar, "usr", '5', 0o755, "", "");
    try appendGnuTarEntry(allocator, &tar, "usr/file", '0', 0o644, "", "content");
    try appendGnuTarEntry(allocator, &tar, "usr/link", '2', 0o777, "file", "");
    try appendGnuTarEntry(allocator, &tar, "usr/link2", '2', 0o777, "link", "");
    try appendGnuTarEntry(allocator, &tar, "usr/config", '2', 0o777, "/etc/config", "");
    try appendGnuTarEntry(allocator, &tar, "usr/system-systemd\\x2dmute.slice", '0', 0o644, "", "");
    try finishTar(allocator, &tar);
    const member: deb_archive.Member = .{ .kind = .data, .compression = .uncompressed, .name = "data.tar", .header = .{ .start = 0, .end = 0 }, .content = .{ .start = 20, .end = 20 + tar.items.len }, .timestamp = 0, .size = tar.items.len };
    try parseTarTest(allocator, tar.items, member, .{});

    inline for (.{ 'x', 'g' }) |typeflag| {
        tar.clearRetainingCapacity();
        try appendGnuTarEntry(allocator, &tar, "extension", typeflag, 0, "", "");
        try finishTar(allocator, &tar);
        try std.testing.expectError(error.Unsupported, parseTarTest(allocator, tar.items, member, .{}));
    }

    tar.clearRetainingCapacity();
    try appendGnuTarEntry(allocator, &tar, "././@LongLink", 'L', 0, "", "usr/share/a-very-long-directory-name-used-to-cover-safe-gnu-long-name-records/another-directory/file\x00");
    try appendGnuTarEntry(allocator, &tar, "placeholder", '0', 0o644, "", "");
    try appendGnuTarEntry(allocator, &tar, "././@LongLink", 'K', 0, "", "/etc/a-very-long-link-target-used-to-cover-safe-gnu-long-link-records/target\x00");
    try appendGnuTarEntry(allocator, &tar, "long-link", '2', 0o777, "placeholder", "");
    try finishTar(allocator, &tar);
    try parseTarTest(allocator, tar.items, member, .{});

    tar.clearRetainingCapacity();
    try appendGnuTarEntry(allocator, &tar, "./", '5', 0o755, "", "");
    try appendGnuTarEntry(allocator, &tar, "./", '5', 0o755, "", "");
    try finishTar(allocator, &tar);
    try std.testing.expectError(error.EntryLimit, parseTarTest(allocator, tar.items, member, .{ .max_entries_per_tar = 1 }));
}

fn parseTarTest(allocator: std.mem.Allocator, bytes: []const u8, member: deb_archive.Member, limits: Limits) !void {
    var diagnostic: Diagnostic = undefined;
    var inventory = parseTar(allocator, bytes, member, .data_tar, limits, &diagnostic) catch switch (diagnostic.code) {
        .duplicate_path => return error.DuplicatePath,
        .unsupported_file_type, .unsupported_tar_extension => return error.Unsupported,
        .unsafe_link => return error.UnsafeLink,
        .tar_entry_limit => return error.EntryLimit,
        .tar_metadata_limit => return error.MetadataLimit,
        .forward_hardlink => return error.ForwardHardlink,
        .conflicting_path => return error.Conflict,
        else => return error.Other,
    };
    defer freeInventory(allocator, &inventory);
}
