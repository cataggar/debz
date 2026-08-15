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

pub const Stage = enum { outer, digest, control_decompression, data_decompression, control_tar, data_tar, control_metadata, identity, conffiles };

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
            .size_mismatch => "archive byte count does not match authenticated repository metadata",
            .digest_mismatch => "archive SHA-256 does not match authenticated repository metadata",
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
            .unsupported_tar_extension => "GNU/PAX tar extension metadata is not accepted by this policy",
            .unsafe_path => "tar path is absolute, traversing, ambiguous, or contains an invalid component",
            .path_too_long => "tar path exceeds the configured limit",
            .duplicate_path => "tar contains duplicate or normalization-colliding paths",
            .conflicting_path => "tar paths or links conflict under archive interpretation",
            .unsafe_link => "tar link target is absolute, traversing, ambiguous, or symlink-mediated",
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
    regular_bytes: u64,
};

pub const Script = struct {
    name: []const u8,
    mode: u32,
    size: u64,
};

pub const Conffile = struct {
    path: []u8,
    obsolete: bool,
};

pub const Provenance = struct {
    repository: []u8,
    filename: []u8,
    size: u64,
    sha256: [32]u8,
};

/// Owns all returned strings, inventories, and decompressed tar bytes. Entry
/// paths are canonical archive-root-relative paths; no filesystem is touched.
pub const Validation = struct {
    allocator: std.mem.Allocator,
    package: []u8,
    version: []u8,
    architecture: []u8,
    provenance: Provenance,
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
        self.allocator.free(self.control_bytes);
        self.allocator.free(self.data_bytes);
        self.* = undefined;
    }
};

pub const Result = union(enum) {
    validation: Validation,
    diagnostic: Diagnostic,
};

pub fn validate(allocator: std.mem.Allocator, bytes: []const u8, expected: Expected, limits: Limits) Result {
    var ownership_transferred = false;
    if (bytes.len != expected.size) return fail(.digest, .size_mismatch, 0, null, null);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    if (!std.mem.eql(u8, &digest, &expected.sha256)) return fail(.digest, .digest_mismatch, 0, null, null);

    const outer = switch (deb_archive.parse(bytes, limits.outer)) {
        .archive => |archive| archive,
        .diagnostic => |diagnostic| return .{ .diagnostic = .{
            .stage = .outer,
            .code = .outer_archive,
            .offset = diagnostic.offset,
            .outer = diagnostic,
        } },
    };

    const control_bytes = decompressMember(allocator, outer, outer.control, true, limits) catch |err|
        return decompressionFailure(.control_decompression, outer.control.content.start, err);
    defer if (!ownership_transferred) allocator.free(control_bytes);
    const data_bytes = decompressMember(allocator, outer, outer.data, false, limits) catch |err|
        return decompressionFailure(.data_decompression, outer.data.content.start, err);
    defer if (!ownership_transferred) allocator.free(data_bytes);

    var tar_diagnostic: Diagnostic = undefined;
    var control_tar = parseTar(allocator, control_bytes, outer.control, .control_tar, limits, &tar_diagnostic) catch
        return .{ .diagnostic = tar_diagnostic };
    defer if (!ownership_transferred) freeInventory(allocator, &control_tar);
    var data_tar = parseTar(allocator, data_bytes, outer.data, .data_tar, limits, &tar_diagnostic) catch
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

    const package = allocator.dupe(u8, record.package.text) catch return oom();
    defer if (!ownership_transferred) allocator.free(package);
    const version = allocator.dupe(u8, record.version.value.original) catch return oom();
    defer if (!ownership_transferred) allocator.free(version);
    const architecture = allocator.dupe(u8, record.architecture.text) catch return oom();
    defer if (!ownership_transferred) allocator.free(architecture);
    const repository = allocator.dupe(u8, expected.repository) catch return oom();
    defer if (!ownership_transferred) allocator.free(repository);
    const filename = allocator.dupe(u8, expected.filename) catch return oom();
    defer if (!ownership_transferred) allocator.free(filename);

    var script_list: std.ArrayList(Script) = .empty;
    defer script_list.deinit(allocator);
    for (control_tar.entries) |entry| {
        if (entry.kind == .regular and isScript(entry.path))
            script_list.append(allocator, .{ .name = scriptName(entry.path).?, .mode = entry.mode, .size = entry.size }) catch return oom();
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

    ownership_transferred = true;
    return .{ .validation = .{
        .allocator = allocator,
        .package = package,
        .version = version,
        .architecture = architecture,
        .provenance = .{ .repository = repository, .filename = filename, .size = expected.size, .sha256 = expected.sha256 },
        .control = control_tar,
        .data = data_tar,
        .scripts = scripts,
        .conffiles = conffiles,
        .control_bytes = control_bytes,
        .data_bytes = data_bytes,
    } };
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
        if (entries.items.len >= limits.max_entries_per_tar)
            return setTarFailure(diagnostic, stage, .tar_entry_limit, member, offset, entries.items.len);
        if (!validChecksum(header))
            return setTarFailure(diagnostic, stage, .tar_bad_checksum, member, offset, entries.items.len);
        if (!std.mem.eql(u8, header[257..263], "ustar\x00") or
            !std.mem.eql(u8, header[263..265], "00"))
            return setTarFailure(diagnostic, stage, .unsupported_tar_extension, member, offset + 257, entries.items.len);
        const size = parseOctal(header[124..136]) orelse
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 124, entries.items.len);
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
        if (typeflag == 'x' or typeflag == 'g' or typeflag == 'L' or typeflag == 'K')
            return setTarFailure(diagnostic, stage, .unsupported_tar_extension, member, offset + 156, entries.items.len);
        const kind: EntryKind = switch (typeflag) {
            0, '0' => .regular,
            '5' => .directory,
            '2' => .symlink,
            '1' => .hardlink,
            else => return setTarFailure(diagnostic, stage, .unsupported_file_type, member, offset + 156, entries.items.len),
        };
        if (kind != .regular and size != 0)
            return setTarFailure(diagnostic, stage, .tar_invalid_number, member, offset + 124, entries.items.len);
        const path = canonicalTarPath(allocator, header, limits.max_path_bytes) catch |err| switch (err) {
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
            const raw_link = fieldString(header[157..257]) orelse
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
            } else if (hasSymlinkAtOrAbove(&paths, target)) {
                allocator.free(target);
                return setTarFailure(diagnostic, stage, .conflicting_path, member, offset + 157, entries.items.len);
            }
            link_target = target;
        }
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
        offset = padded;
    }
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
        .regular_bytes = regular_bytes,
    };
}

fn setTarFailure(diagnostic: *Diagnostic, stage: Stage, code: Code, member: deb_archive.Member, inner: usize, entry: ?usize) error{Invalid} {
    diagnostic.* = .{ .stage = stage, .code = code, .offset = member.content.start + inner, .inner_offset = inner, .entry_index = entry };
    return error.Invalid;
}

fn canonicalTarPath(allocator: std.mem.Allocator, header: []const u8, maximum: usize) ![]u8 {
    const name = fieldString(header[0..100]) orelse return error.Unsafe;
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
    if (raw_input.len == 0 or raw_input[0] == '/' or std.mem.indexOfScalar(u8, raw_input, '\\') != null)
        return error.Unsafe;
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

fn resolveLink(allocator: std.mem.Allocator, path: []const u8, raw: []const u8, hardlink: bool, maximum: usize) ![]u8 {
    if (hardlink) return canonicalPath(allocator, raw, maximum, false);
    if (raw.len == 0 or raw[0] == '/') return error.Unsafe;
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

fn hasSymlinkAtOrAbove(paths: *const std.StringHashMap(EntryKind), path: []const u8) bool {
    if (paths.get(path) == .symlink) return true;
    return hasSymlinkAncestor(paths, path);
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
            if (line[0] != '/')
                return setFailure(diagnostic, .conffiles, .invalid_conffiles, member_offset + entry.content_offset);
            const separator = std.mem.indexOfAny(u8, line, " \t");
            const path_text = if (separator) |index| line[0..index] else line;
            const qualifier = if (separator) |index| std.mem.trim(u8, line[index..], " \t") else "";
            if (qualifier.len != 0 and !std.mem.eql(u8, qualifier, "obsolete"))
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
            result.append(allocator, .{ .path = path, .obsolete = qualifier.len != 0 }) catch {
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

fn expectedFor(bytes: []const u8) Expected {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
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
