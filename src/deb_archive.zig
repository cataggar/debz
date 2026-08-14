const std = @import("std");

pub const Span = struct {
    start: usize,
    end: usize,

    pub fn slice(self: Span, source: []const u8) []const u8 {
        return source[self.start..self.end];
    }
};

pub const Compression = enum {
    uncompressed,
    gzip,
    xz,
    zstd,
};

pub const MemberKind = enum {
    debian_binary,
    control,
    data,
};

pub const Member = struct {
    kind: MemberKind,
    compression: Compression,
    name: []const u8,
    header: Span,
    content: Span,
    timestamp: u64,
    size: usize,
};

/// Borrows member names and byte ranges from the input passed to `parse`.
pub const Archive = struct {
    source: []const u8,
    debian_binary: Member,
    control: Member,
    data: Member,
    member_count: usize,

    pub fn memberBytes(self: Archive, member: Member) []const u8 {
        return member.content.slice(self.source);
    }
};

pub const DebianBinaryNewlinePolicy = enum {
    /// Accept only the canonical `2.0\n`.
    lf_only,
    /// Accept `2.0\n` or `2.0`.
    lf_or_none,
    /// Accept `2.0\n` or `2.0\r\n`.
    lf_or_crlf,
};

pub const Limits = struct {
    max_archive_bytes: usize = 1024 * 1024 * 1024,
    max_member_bytes: usize = 512 * 1024 * 1024,
    max_members: usize = 16,
    debian_binary_newline: DebianBinaryNewlinePolicy = .lf_only,
};

pub const DiagnosticCode = enum {
    archive_too_large,
    invalid_global_magic,
    truncated_member_header,
    invalid_member_header_trailer,
    invalid_member_name,
    unsafe_member_name,
    unsupported_gnu_long_name,
    unsupported_bsd_long_name,
    invalid_timestamp,
    invalid_member_size,
    member_too_large,
    too_many_members,
    truncated_member_content,
    invalid_padding,
    trailing_data,
    unexpected_member,
    duplicate_debian_binary,
    duplicate_control,
    duplicate_data,
    missing_debian_binary,
    missing_control,
    missing_data,
    invalid_debian_binary,
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    offset: usize,
    member_index: ?usize = null,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .archive_too_large => "archive exceeds the configured size limit",
            .invalid_global_magic => "expected the ar global magic \"!<arch>\\n\"",
            .truncated_member_header => "truncated ar member header",
            .invalid_member_header_trailer => "ar member header must end with \"`\\n\"",
            .invalid_member_name => "ar member name is empty or malformed",
            .unsafe_member_name => "ar member name contains an unsafe path or control character",
            .unsupported_gnu_long_name => "GNU ar long-name tables and references are not supported",
            .unsupported_bsd_long_name => "BSD ar extended names are not supported",
            .invalid_timestamp => "ar member timestamp is not a valid unsigned decimal integer",
            .invalid_member_size => "ar member size is not a valid unsigned decimal integer",
            .member_too_large => "ar member exceeds the configured size limit",
            .too_many_members => "archive exceeds the configured member-count limit",
            .truncated_member_content => "ar member content extends beyond the archive",
            .invalid_padding => "odd-sized ar member must be followed by a newline padding byte",
            .trailing_data => "unexpected trailing bytes follow the required archive members",
            .unexpected_member => "archive contains a member other than debian-binary, control.tar, or data.tar",
            .duplicate_debian_binary => "archive contains more than one debian-binary member",
            .duplicate_control => "archive contains more than one supported control.tar member",
            .duplicate_data => "archive contains more than one supported data.tar member",
            .missing_debian_binary => "archive is missing debian-binary",
            .missing_control => "archive is missing a supported control.tar member",
            .missing_data => "archive is missing a supported data.tar member",
            .invalid_debian_binary => "debian-binary must contain version 2.0 with the configured newline policy",
        };
    }
};

pub const ParseResult = union(enum) {
    archive: Archive,
    diagnostic: Diagnostic,
};

const global_magic = "!<arch>\n";
const header_len = 60;

/// Validates only the outer ar archive. Compression streams and tar contents
/// are intentionally left untouched for a separate validation stage.
pub fn parse(source: []const u8, limits: Limits) ParseResult {
    if (source.len > limits.max_archive_bytes) {
        return failure(.archive_too_large, limits.max_archive_bytes, null);
    }
    if (source.len < global_magic.len or
        !std.mem.eql(u8, source[0..global_magic.len], global_magic))
    {
        return failure(.invalid_global_magic, 0, null);
    }

    var offset: usize = global_magic.len;
    var member_count: usize = 0;
    var debian_binary: ?Member = null;
    var control: ?Member = null;
    var data: ?Member = null;

    while (offset < source.len) {
        if (member_count >= limits.max_members) {
            return failure(.too_many_members, offset, member_count);
        }

        const header_end = std.math.add(usize, offset, header_len) catch
            return failure(.truncated_member_header, offset, member_count);
        if (header_end > source.len) {
            if (debian_binary != null and control != null and data != null) {
                return failure(.trailing_data, offset, null);
            }
            return failure(.truncated_member_header, offset, member_count);
        }
        const header = source[offset..header_end];
        if (!std.mem.eql(u8, header[58..60], "`\n")) {
            return failure(.invalid_member_header_trailer, offset + 58, member_count);
        }

        const parsed_name = switch (parseName(header[0..16], offset)) {
            .name => |name| name,
            .diagnostic => |value| return .{ .diagnostic = withMember(value, member_count) },
        };
        const timestamp = parseDecimal(header[16..28]) orelse
            return failure(.invalid_timestamp, offset + 16, member_count);
        const size_u64 = parseDecimal(header[48..58]) orelse
            return failure(.invalid_member_size, offset + 48, member_count);
        if (size_u64 > limits.max_member_bytes or size_u64 > std.math.maxInt(usize)) {
            return failure(.member_too_large, offset + 48, member_count);
        }
        const size: usize = @intCast(size_u64);
        const content_end = std.math.add(usize, header_end, size) catch
            return failure(.truncated_member_content, header_end, member_count);
        if (content_end > source.len) {
            return failure(.truncated_member_content, header_end, member_count);
        }

        const classified = classify(parsed_name.name) orelse
            return failure(.unexpected_member, offset, member_count);
        const member: Member = .{
            .kind = classified.kind,
            .compression = classified.compression,
            .name = source[offset + parsed_name.start .. offset + parsed_name.end],
            .header = .{ .start = offset, .end = header_end },
            .content = .{ .start = header_end, .end = content_end },
            .timestamp = timestamp,
            .size = size,
        };

        switch (classified.kind) {
            .debian_binary => {
                if (debian_binary != null) {
                    return failure(.duplicate_debian_binary, offset, member_count);
                }
                if (!validDebianBinary(source[header_end..content_end], limits.debian_binary_newline)) {
                    return failure(.invalid_debian_binary, header_end, member_count);
                }
                debian_binary = member;
            },
            .control => {
                if (control != null) return failure(.duplicate_control, offset, member_count);
                control = member;
            },
            .data => {
                if (data != null) return failure(.duplicate_data, offset, member_count);
                data = member;
            },
        }

        member_count += 1;
        offset = content_end;
        if (size % 2 == 1) {
            if (offset >= source.len) {
                return failure(.invalid_padding, offset, member_count - 1);
            }
            if (source[offset] != '\n') {
                return failure(.invalid_padding, offset, member_count - 1);
            }
            offset = std.math.add(usize, offset, 1) catch
                return failure(.invalid_padding, offset, member_count - 1);
        }
    }

    if (debian_binary == null) return failure(.missing_debian_binary, source.len, null);
    if (control == null) return failure(.missing_control, source.len, null);
    if (data == null) return failure(.missing_data, source.len, null);

    return .{ .archive = .{
        .source = source,
        .debian_binary = debian_binary.?,
        .control = control.?,
        .data = data.?,
        .member_count = member_count,
    } };
}

const ParsedName = struct {
    name: []const u8,
    start: usize,
    end: usize,
};

const NameResult = union(enum) {
    name: ParsedName,
    diagnostic: Diagnostic,
};

fn parseName(field: []const u8, header_offset: usize) NameResult {
    var end = field.len;
    while (end > 0 and field[end - 1] == ' ') end -= 1;
    if (end == 0) return nameFailure(.invalid_member_name, header_offset);

    const raw = field[0..end];
    if (std.mem.eql(u8, raw, "/") or std.mem.eql(u8, raw, "//") or
        (raw[0] == '/' and raw.len > 1))
    {
        return nameFailure(.unsupported_gnu_long_name, header_offset);
    }
    if (std.mem.startsWith(u8, raw, "#1/")) {
        return nameFailure(.unsupported_bsd_long_name, header_offset);
    }

    var name_end = end;
    if (raw[raw.len - 1] == '/') name_end -= 1;
    if (name_end == 0) return nameFailure(.invalid_member_name, header_offset);
    const name = field[0..name_end];
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) {
        return nameFailure(.unsafe_member_name, header_offset);
    }
    for (name, 0..) |byte, index| {
        if (byte < 0x21 or byte > 0x7e or byte == '/' or byte == '\\') {
            return nameFailure(.unsafe_member_name, header_offset + index);
        }
    }

    return .{ .name = .{ .name = name, .start = 0, .end = name_end } };
}

fn parseDecimal(field: []const u8) ?u64 {
    var end = field.len;
    while (end > 0 and field[end - 1] == ' ') end -= 1;
    if (end == 0) return null;

    var value: u64 = 0;
    for (field[0..end]) |byte| {
        if (byte < '0' or byte > '9') return null;
        value = std.math.mul(u64, value, 10) catch return null;
        value = std.math.add(u64, value, byte - '0') catch return null;
    }
    return value;
}

const Classification = struct {
    kind: MemberKind,
    compression: Compression,
};

fn classify(name: []const u8) ?Classification {
    if (std.mem.eql(u8, name, "debian-binary")) {
        return .{ .kind = .debian_binary, .compression = .uncompressed };
    }
    inline for (.{
        .{ "control.tar", MemberKind.control, Compression.uncompressed },
        .{ "control.tar.gz", MemberKind.control, Compression.gzip },
        .{ "control.tar.xz", MemberKind.control, Compression.xz },
        .{ "control.tar.zst", MemberKind.control, Compression.zstd },
        .{ "data.tar", MemberKind.data, Compression.uncompressed },
        .{ "data.tar.gz", MemberKind.data, Compression.gzip },
        .{ "data.tar.xz", MemberKind.data, Compression.xz },
        .{ "data.tar.zst", MemberKind.data, Compression.zstd },
    }) |entry| {
        if (std.mem.eql(u8, name, entry[0])) {
            return .{ .kind = entry[1], .compression = entry[2] };
        }
    }
    return null;
}

fn validDebianBinary(content: []const u8, policy: DebianBinaryNewlinePolicy) bool {
    return switch (policy) {
        .lf_only => std.mem.eql(u8, content, "2.0\n"),
        .lf_or_none => std.mem.eql(u8, content, "2.0\n") or std.mem.eql(u8, content, "2.0"),
        .lf_or_crlf => std.mem.eql(u8, content, "2.0\n") or std.mem.eql(u8, content, "2.0\r\n"),
    };
}

fn nameFailure(code: DiagnosticCode, offset: usize) NameResult {
    return .{ .diagnostic = .{ .code = code, .offset = offset } };
}

fn failure(code: DiagnosticCode, offset: usize, member_index: ?usize) ParseResult {
    return .{ .diagnostic = .{ .code = code, .offset = offset, .member_index = member_index } };
}

fn withMember(value: anytype, member_index: usize) Diagnostic {
    var result = value;
    result.member_index = member_index;
    return result;
}

fn appendTestMember(
    allocator: std.mem.Allocator,
    bytes: *std.ArrayList(u8),
    name: []const u8,
    content: []const u8,
) !void {
    var header: [header_len]u8 = @splat(' ');
    std.mem.copyForwards(u8, header[0..], name);
    header[16] = '0';
    header[28] = '0';
    header[34] = '0';
    std.mem.copyForwards(u8, header[40..], "100644");
    var size_buffer: [20]u8 = undefined;
    const size = try std.fmt.bufPrint(&size_buffer, "{d}", .{content.len});
    std.mem.copyForwards(u8, header[48..], size);
    header[58] = '`';
    header[59] = '\n';
    try bytes.appendSlice(allocator, &header);
    try bytes.appendSlice(allocator, content);
    if (content.len % 2 == 1) try bytes.append(allocator, '\n');
}

fn validTestArchive(allocator: std.mem.Allocator) ![]u8 {
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "debian-binary/", "2.0\n");
    try appendTestMember(allocator, &bytes, "control.tar.xz/", "ctrl");
    try appendTestMember(allocator, &bytes, "data.tar.zst/", "payload");
    return bytes.toOwnedSlice(allocator);
}

fn expectDiagnostic(code: DiagnosticCode, result: ParseResult) !Diagnostic {
    return switch (result) {
        .archive => error.ExpectedDiagnostic,
        .diagnostic => |value| blk: {
            try std.testing.expectEqual(code, value.code);
            break :blk value;
        },
    };
}

test "parses supported members as borrowed typed ranges" {
    const allocator = std.testing.allocator;
    const bytes = try validTestArchive(allocator);
    defer allocator.free(bytes);

    const archive = switch (parse(bytes, .{})) {
        .archive => |value| value,
        .diagnostic => |value| {
            std.debug.print("unexpected diagnostic {s} at {d}\n", .{ value.message(), value.offset });
            return error.UnexpectedDiagnostic;
        },
    };
    try std.testing.expectEqual(@as(usize, 3), archive.member_count);
    try std.testing.expectEqual(Compression.xz, archive.control.compression);
    try std.testing.expectEqual(Compression.zstd, archive.data.compression);
    try std.testing.expectEqualStrings("2.0\n", archive.memberBytes(archive.debian_binary));
    try std.testing.expectEqualStrings("control.tar.xz", archive.control.name);
    try std.testing.expectEqualStrings("ctrl", archive.memberBytes(archive.control));
}

test "recognizes every supported control and data compression suffix" {
    const allocator = std.testing.allocator;
    const cases = .{
        .{ "control.tar/", "data.tar/", Compression.uncompressed },
        .{ "control.tar.gz/", "data.tar.gz/", Compression.gzip },
        .{ "control.tar.xz/", "data.tar.xz/", Compression.xz },
        .{ "control.tar.zst/", "data.tar.zst/", Compression.zstd },
    };
    inline for (cases) |case| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try bytes.appendSlice(allocator, global_magic);
        try appendTestMember(allocator, &bytes, "debian-binary/", "2.0\n");
        try appendTestMember(allocator, &bytes, case[0], "");
        try appendTestMember(allocator, &bytes, case[1], "");
        const archive = parse(bytes.items, .{}).archive;
        try std.testing.expectEqual(case[2], archive.control.compression);
        try std.testing.expectEqual(case[2], archive.data.compression);
    }
}

test "rejects magic and header truncation with offsets" {
    const bad_magic = parse("not ar", .{});
    const magic_diagnostic = try expectDiagnostic(.invalid_global_magic, bad_magic);
    try std.testing.expectEqual(@as(usize, 0), magic_diagnostic.offset);

    const diagnostic_value = try expectDiagnostic(
        .truncated_member_header,
        parse(global_magic ++ "short", .{}),
    );
    try std.testing.expectEqual(global_magic.len, diagnostic_value.offset);
    try std.testing.expectEqual(@as(?usize, 0), diagnostic_value.member_index);
}

test "rejects malformed numeric fields and header trailer" {
    const allocator = std.testing.allocator;
    const original = try validTestArchive(allocator);
    defer allocator.free(original);

    var bytes = try allocator.dupe(u8, original);
    defer allocator.free(bytes);
    bytes[8 + 16] = '-';
    _ = try expectDiagnostic(.invalid_timestamp, parse(bytes, .{}));

    std.mem.copyForwards(u8, bytes, original);
    bytes[8 + 48] = 'x';
    _ = try expectDiagnostic(.invalid_member_size, parse(bytes, .{}));

    std.mem.copyForwards(u8, bytes, original);
    bytes[8 + 58] = '!';
    _ = try expectDiagnostic(.invalid_member_header_trailer, parse(bytes, .{}));
}

test "rejects truncated content and corrupt or missing padding" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "debian-binary/", "2.0\n");
    bytes.items[8 + 48] = '9';
    _ = try expectDiagnostic(.truncated_member_content, parse(bytes.items, .{}));

    bytes.clearRetainingCapacity();
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "debian-binary/", "2.0\n");
    try appendTestMember(allocator, &bytes, "control.tar/", "x");
    bytes.items[bytes.items.len - 1] = 0;
    _ = try expectDiagnostic(.invalid_padding, parse(bytes.items, .{}));

    _ = bytes.pop();
    _ = try expectDiagnostic(.invalid_padding, parse(bytes.items, .{}));
}

test "rejects trailing bytes after a complete archive" {
    const allocator = std.testing.allocator;
    var bytes = try validTestArchive(allocator);
    defer allocator.free(bytes);
    bytes = try allocator.realloc(bytes, bytes.len + 1);
    bytes[bytes.len - 1] = 0xff;
    const value = try expectDiagnostic(.trailing_data, parse(bytes, .{}));
    try std.testing.expectEqual(bytes.len - 1, value.offset);
}

test "rejects GNU and BSD names and unsafe paths explicitly" {
    const allocator = std.testing.allocator;
    const cases = .{
        .{ "//", DiagnosticCode.unsupported_gnu_long_name },
        .{ "/12", DiagnosticCode.unsupported_gnu_long_name },
        .{ "#1/20", DiagnosticCode.unsupported_bsd_long_name },
        .{ "../evil/", DiagnosticCode.unsafe_member_name },
        .{ "dir/file/", DiagnosticCode.unsafe_member_name },
    };
    inline for (cases) |case| {
        var bytes: std.ArrayList(u8) = .empty;
        defer bytes.deinit(allocator);
        try bytes.appendSlice(allocator, global_magic);
        try appendTestMember(allocator, &bytes, case[0], "");
        _ = try expectDiagnostic(case[1], parse(bytes.items, .{}));
    }
}

test "rejects duplicate, missing, and unexpected members" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "debian-binary/", "2.0\n");
    try appendTestMember(allocator, &bytes, "debian-binary/", "2.0\n");
    _ = try expectDiagnostic(.duplicate_debian_binary, parse(bytes.items, .{}));

    bytes.clearRetainingCapacity();
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "control.tar.gz/", "");
    try appendTestMember(allocator, &bytes, "control.tar.xz/", "");
    _ = try expectDiagnostic(.duplicate_control, parse(bytes.items, .{}));

    bytes.clearRetainingCapacity();
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "data.tar/", "");
    try appendTestMember(allocator, &bytes, "data.tar.zst/", "");
    _ = try expectDiagnostic(.duplicate_data, parse(bytes.items, .{}));

    bytes.clearRetainingCapacity();
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "debian-binary/", "2.0\n");
    try appendTestMember(allocator, &bytes, "control.tar/", "");
    _ = try expectDiagnostic(.missing_data, parse(bytes.items, .{}));

    bytes.clearRetainingCapacity();
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "debian-binary/", "2.0\n");
    try appendTestMember(allocator, &bytes, "metadata/", "");
    _ = try expectDiagnostic(.unexpected_member, parse(bytes.items, .{}));
}

test "validates debian-binary newline policy" {
    const allocator = std.testing.allocator;
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "debian-binary/", "2.0");
    try appendTestMember(allocator, &bytes, "control.tar.gz/", "");
    try appendTestMember(allocator, &bytes, "data.tar.xz/", "");

    _ = try expectDiagnostic(.invalid_debian_binary, parse(bytes.items, .{}));
    _ = parse(bytes.items, .{ .debian_binary_newline = .lf_or_none }).archive;

    bytes.clearRetainingCapacity();
    try bytes.appendSlice(allocator, global_magic);
    try appendTestMember(allocator, &bytes, "debian-binary/", "2.0\r\n");
    try appendTestMember(allocator, &bytes, "control.tar.gz/", "");
    try appendTestMember(allocator, &bytes, "data.tar.xz/", "");
    _ = parse(bytes.items, .{ .debian_binary_newline = .lf_or_crlf }).archive;
}

test "enforces archive member and count limits" {
    const allocator = std.testing.allocator;
    const bytes = try validTestArchive(allocator);
    defer allocator.free(bytes);

    _ = try expectDiagnostic(.archive_too_large, parse(bytes, .{ .max_archive_bytes = bytes.len - 1 }));
    _ = try expectDiagnostic(.member_too_large, parse(bytes, .{ .max_member_bytes = 3 }));
    _ = try expectDiagnostic(.too_many_members, parse(bytes, .{ .max_members = 2 }));
}
