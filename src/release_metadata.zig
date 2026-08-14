const std = @import("std");
const deb822 = @import("deb822.zig");

pub const Span = struct {
    start: usize,
    end: usize,

    pub fn slice(self: Span, source: []const u8) []const u8 {
        return source[self.start..self.end];
    }
};

pub const LocatedString = struct {
    value: []const u8,
    span: Span,
};

pub const LocatedBool = struct {
    value: bool,
    span: Span,
};

pub const Weekday = enum {
    monday,
    tuesday,
    wednesday,
    thursday,
    friday,
    saturday,
    sunday,
};

/// A parsed civil timestamp and its declared UTC offset. This type deliberately
/// does not read a clock or decide whether metadata is current or expired.
pub const Timestamp = struct {
    weekday: ?Weekday,
    year: u16,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    utc_offset_minutes: i16,
};

pub const LocatedTimestamp = struct {
    value: Timestamp,
    span: Span,
};

pub const Sha256Digest = struct {
    bytes: [32]u8,

    pub fn eql(left: Sha256Digest, right: Sha256Digest) bool {
        return std.mem.eql(u8, &left.bytes, &right.bytes);
    }
};

pub const Sha256Entry = struct {
    digest: Sha256Digest,
    size: u64,
    path: LocatedString,
    digest_span: Span,
    size_span: Span,
    span: Span,
};

/// Owns its arrays; string values and spans borrow `source`.
pub const ReleaseMetadata = struct {
    source: []const u8,
    origin: ?LocatedString,
    label: ?LocatedString,
    suite: ?LocatedString,
    codename: ?LocatedString,
    version: ?LocatedString,
    date: ?LocatedTimestamp,
    valid_until: ?LocatedTimestamp,
    architectures: []LocatedString,
    components: []LocatedString,
    acquire_by_hash: ?LocatedBool,
    /// The only checksum records exposed as trusted index metadata.
    sha256_entries: []Sha256Entry,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ReleaseMetadata) void {
        self.allocator.free(self.architectures);
        self.allocator.free(self.components);
        self.allocator.free(self.sha256_entries);
        self.* = undefined;
    }
};

pub const Limits = struct {
    max_input_bytes: usize = 4 * 1024 * 1024,
    max_fields: usize = 128,
    max_field_bytes: usize = 2 * 1024 * 1024,
    max_list_items: usize = 1024,
    max_checksum_rows: usize = 100_000,
};

pub const DiagnosticCode = enum {
    input_too_long,
    malformed_deb822,
    too_many_paragraphs,
    too_many_fields,
    field_too_long,
    duplicate_field,
    empty_scalar,
    multiline_scalar,
    too_many_list_items,
    invalid_list_item,
    invalid_boolean,
    invalid_timestamp,
    invalid_timestamp_weekday,
    too_many_checksum_rows,
    malformed_checksum_row,
    invalid_sha256_digest,
    invalid_checksum_size,
    invalid_checksum_path,
    duplicate_checksum_path,
    conflicting_checksum_path,
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    span: Span,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .input_too_long => "Release metadata exceeds the configured byte limit",
            .malformed_deb822 => "Release metadata is not valid DEB822",
            .too_many_paragraphs => "Release metadata must contain exactly one paragraph",
            .too_many_fields => "Release metadata exceeds the configured field limit",
            .field_too_long => "Release metadata field exceeds the configured byte limit",
            .duplicate_field => "Release metadata fields must not be repeated",
            .empty_scalar => "Release metadata scalar field must not be empty",
            .multiline_scalar => "Release metadata scalar field must occupy one line",
            .too_many_list_items => "Release metadata list exceeds the configured item limit",
            .invalid_list_item => "Release metadata list contains an invalid token",
            .invalid_boolean => "Acquire-By-Hash must be exactly 'yes' or 'no'",
            .invalid_timestamp => "timestamp must use an RFC-style date, time, and UTC offset",
            .invalid_timestamp_weekday => "timestamp weekday does not match its calendar date",
            .too_many_checksum_rows => "SHA256 exceeds the configured row limit",
            .malformed_checksum_row => "checksum row must contain digest, decimal size, and relative path",
            .invalid_sha256_digest => "SHA256 digest must contain exactly 64 hexadecimal digits",
            .invalid_checksum_size => "checksum size must be an unsigned 64-bit decimal integer",
            .invalid_checksum_path => "checksum path must be a normalized relative path",
            .duplicate_checksum_path => "SHA256 repeats an identical path record",
            .conflicting_checksum_path => "SHA256 contains conflicting records for one path",
        };
    }
};

pub const ParseResult = union(enum) {
    metadata: ReleaseMetadata,
    diagnostic: Diagnostic,
};

pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
    limits: Limits,
) std.mem.Allocator.Error!ParseResult {
    if (source.len > limits.max_input_bytes) {
        return .{ .diagnostic = .{
            .code = .input_too_long,
            .span = .{ .start = limits.max_input_bytes, .end = source.len },
        } };
    }

    const outcome = try deb822.parseBorrowed(allocator, source, .{
        .limits = .{
            .max_total_bytes = limits.max_input_bytes,
            .max_paragraphs = 2,
            .max_fields_per_paragraph = limits.max_fields,
            .max_field_bytes = limits.max_field_bytes,
        },
    });
    var document = switch (outcome) {
        .document => |value| value,
        .failure => |failure| return .{ .diagnostic = .{
            .code = switch (failure.kind) {
                .total_bytes_limit => .input_too_long,
                .paragraph_limit => .too_many_paragraphs,
                .fields_limit => .too_many_fields,
                .field_size_limit => .field_too_long,
                .duplicate_field => .duplicate_field,
                else => .malformed_deb822,
            },
            .span = pointSpan(failure.position.offset, source.len),
        } },
    };
    defer document.deinit();

    if (document.paragraphs.len != 1) {
        const span = if (document.paragraphs.len > 1)
            fromDeb822Span(document.paragraphs[1].span)
        else
            Span{ .start = 0, .end = source.len };
        return .{ .diagnostic = .{ .code = .too_many_paragraphs, .span = span } };
    }

    const paragraph = document.paragraphs[0];
    var architectures: std.ArrayList(LocatedString) = .empty;
    defer architectures.deinit(allocator);
    var components: std.ArrayList(LocatedString) = .empty;
    defer components.deinit(allocator);
    var checksums: std.ArrayList(Sha256Entry) = .empty;
    defer checksums.deinit(allocator);
    var checksum_paths = std.StringHashMap(usize).init(allocator);
    defer checksum_paths.deinit();

    var origin: ?LocatedString = null;
    var label: ?LocatedString = null;
    var suite: ?LocatedString = null;
    var codename: ?LocatedString = null;
    var version: ?LocatedString = null;
    var date: ?LocatedTimestamp = null;
    var valid_until: ?LocatedTimestamp = null;
    var acquire_by_hash: ?LocatedBool = null;

    for (paragraph.fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, "Origin")) {
            origin = switch (scalar(field)) {
                .value => |value| value,
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            };
        } else if (std.ascii.eqlIgnoreCase(field.name, "Label")) {
            label = switch (scalar(field)) {
                .value => |value| value,
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            };
        } else if (std.ascii.eqlIgnoreCase(field.name, "Suite")) {
            suite = switch (scalar(field)) {
                .value => |value| value,
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            };
        } else if (std.ascii.eqlIgnoreCase(field.name, "Codename")) {
            codename = switch (scalar(field)) {
                .value => |value| value,
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            };
        } else if (std.ascii.eqlIgnoreCase(field.name, "Version")) {
            version = switch (scalar(field)) {
                .value => |value| value,
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            };
        } else if (std.ascii.eqlIgnoreCase(field.name, "Date")) {
            date = switch (parseTimestampField(field)) {
                .value => |value| value,
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            };
        } else if (std.ascii.eqlIgnoreCase(field.name, "Valid-Until")) {
            valid_until = switch (parseTimestampField(field)) {
                .value => |value| value,
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            };
        } else if (std.ascii.eqlIgnoreCase(field.name, "Architectures")) {
            if (try parseList(&architectures, allocator, field, limits.max_list_items, validArchitecture)) |diagnostic| {
                return .{ .diagnostic = diagnostic };
            }
        } else if (std.ascii.eqlIgnoreCase(field.name, "Components")) {
            if (try parseList(&components, allocator, field, limits.max_list_items, validComponent)) |diagnostic| {
                return .{ .diagnostic = diagnostic };
            }
        } else if (std.ascii.eqlIgnoreCase(field.name, "Acquire-By-Hash")) {
            const value = switch (scalar(field)) {
                .value => |parsed| parsed,
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            };
            acquire_by_hash = .{
                .value = if (std.mem.eql(u8, value.value, "yes"))
                    true
                else if (std.mem.eql(u8, value.value, "no"))
                    false
                else
                    return .{ .diagnostic = .{ .code = .invalid_boolean, .span = value.span } },
                .span = value.span,
            };
        } else if (std.ascii.eqlIgnoreCase(field.name, "SHA256")) {
            if (try parseSha256(
                allocator,
                &checksums,
                &checksum_paths,
                field,
                limits.max_checksum_rows,
            )) |diagnostic| {
                return .{ .diagnostic = diagnostic };
            }
        }
        // MD5Sum, SHA1, and unknown fields are intentionally not promoted into
        // trusted metadata. The DEB822 bounds still apply to their input.
    }

    const owned_architectures = try architectures.toOwnedSlice(allocator);
    errdefer allocator.free(owned_architectures);
    const owned_components = try components.toOwnedSlice(allocator);
    errdefer allocator.free(owned_components);
    const owned_checksums = try checksums.toOwnedSlice(allocator);
    errdefer allocator.free(owned_checksums);

    return .{ .metadata = .{
        .source = source,
        .origin = origin,
        .label = label,
        .suite = suite,
        .codename = codename,
        .version = version,
        .date = date,
        .valid_until = valid_until,
        .architectures = owned_architectures,
        .components = owned_components,
        .acquire_by_hash = acquire_by_hash,
        .sha256_entries = owned_checksums,
        .allocator = allocator,
    } };
}

const ScalarResult = union(enum) {
    value: LocatedString,
    diagnostic: Diagnostic,
};

fn scalar(field: deb822.Field) ScalarResult {
    if (field.value_lines.len != 1) {
        return .{ .diagnostic = .{
            .code = .multiline_scalar,
            .span = fromDeb822Span(field.span),
        } };
    }
    const line = field.value_lines[0];
    const trimmed = trimLocated(line.text, line.span.start.offset);
    if (trimmed.value.len == 0) {
        return .{ .diagnostic = .{ .code = .empty_scalar, .span = trimmed.span } };
    }
    return .{ .value = trimmed };
}

fn trimLocated(text: []const u8, base: usize) LocatedString {
    var start: usize = 0;
    while (start < text.len and isHorizontalWhitespace(text[start])) : (start += 1) {}
    var end = text.len;
    while (end > start and isHorizontalWhitespace(text[end - 1])) : (end -= 1) {}
    return .{
        .value = text[start..end],
        .span = .{ .start = base + start, .end = base + end },
    };
}

fn parseList(
    output: *std.ArrayList(LocatedString),
    allocator: std.mem.Allocator,
    field: deb822.Field,
    limit: usize,
    comptime validator: fn ([]const u8) bool,
) std.mem.Allocator.Error!?Diagnostic {
    for (field.value_lines) |line| {
        var index: usize = 0;
        while (nextToken(line.text, &index)) |token| {
            const located = LocatedString{
                .value = token.text,
                .span = .{
                    .start = line.span.start.offset + token.start,
                    .end = line.span.start.offset + token.end,
                },
            };
            if (output.items.len >= limit) {
                return .{ .code = .too_many_list_items, .span = located.span };
            }
            if (!validator(located.value)) {
                return .{ .code = .invalid_list_item, .span = located.span };
            }
            try output.append(allocator, located);
        }
    }
    return null;
}

const Token = struct {
    text: []const u8,
    start: usize,
    end: usize,
};

fn nextToken(text: []const u8, index: *usize) ?Token {
    while (index.* < text.len and isWhitespace(text[index.*])) : (index.* += 1) {}
    if (index.* == text.len) return null;
    const start = index.*;
    while (index.* < text.len and !isWhitespace(text[index.*])) : (index.* += 1) {}
    return .{ .text = text[start..index.*], .start = start, .end = index.* };
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
    }
    return true;
}

fn validComponent(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '-' and byte != '+' and byte != '.' and byte != '_')
        {
            return false;
        }
    }
    return true;
}

fn parseSha256(
    allocator: std.mem.Allocator,
    entries: *std.ArrayList(Sha256Entry),
    paths: *std.StringHashMap(usize),
    field: deb822.Field,
    limit: usize,
) std.mem.Allocator.Error!?Diagnostic {
    for (field.value_lines) |line| {
        var token_index: usize = 0;
        const digest_token = nextToken(line.text, &token_index) orelse continue;
        const size_token = nextToken(line.text, &token_index) orelse
            return .{ .code = .malformed_checksum_row, .span = fromDeb822Span(line.span) };
        const path_token = nextToken(line.text, &token_index) orelse
            return .{ .code = .malformed_checksum_row, .span = fromDeb822Span(line.span) };
        if (nextToken(line.text, &token_index) != null) {
            return .{ .code = .malformed_checksum_row, .span = fromDeb822Span(line.span) };
        }
        if (entries.items.len >= limit) {
            return .{ .code = .too_many_checksum_rows, .span = fromDeb822Span(line.span) };
        }

        const digest_span = tokenSpan(line, digest_token);
        const digest = parseDigest(digest_token.text) orelse
            return .{ .code = .invalid_sha256_digest, .span = digest_span };
        const size_span = tokenSpan(line, size_token);
        if (!allDecimal(size_token.text)) {
            return .{ .code = .invalid_checksum_size, .span = size_span };
        }
        const size = std.fmt.parseUnsigned(u64, size_token.text, 10) catch
            return .{ .code = .invalid_checksum_size, .span = size_span };
        const path = LocatedString{
            .value = path_token.text,
            .span = tokenSpan(line, path_token),
        };
        if (!validRelativePath(path.value)) {
            return .{ .code = .invalid_checksum_path, .span = path.span };
        }

        if (paths.get(path.value)) |existing_index| {
            const existing = entries.items[existing_index];
            return .{
                .code = if (existing.size == size and existing.digest.eql(digest))
                    .duplicate_checksum_path
                else
                    .conflicting_checksum_path,
                .span = path.span,
            };
        }

        try entries.append(allocator, .{
            .digest = digest,
            .size = size,
            .path = path,
            .digest_span = digest_span,
            .size_span = size_span,
            .span = fromDeb822Span(line.span),
        });
        errdefer _ = entries.pop();
        try paths.put(path.value, entries.items.len - 1);
    }
    return null;
}

fn parseDigest(text: []const u8) ?Sha256Digest {
    if (text.len != 64) return null;
    var result: Sha256Digest = undefined;
    for (0..32) |index| {
        const high = hexValue(text[index * 2]) orelse return null;
        const low = hexValue(text[index * 2 + 1]) orelse return null;
        result.bytes[index] = (high << 4) | low;
    }
    return result;
}

fn hexValue(byte: u8) ?u8 {
    return switch (byte) {
        '0'...'9' => byte - '0',
        'a'...'f' => byte - 'a' + 10,
        'A'...'F' => byte - 'A' + 10,
        else => null,
    };
}

fn allDecimal(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |byte| if (!std.ascii.isDigit(byte)) return false;
    return true;
}

fn validRelativePath(path: []const u8) bool {
    if (path.len == 0 or path[0] == '/' or path[path.len - 1] == '/') return false;
    if (std.mem.indexOfScalar(u8, path, '\\') != null) return false;

    var segments = std.mem.splitScalar(u8, path, '/');
    while (segments.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, "..")) {
            return false;
        }
        for (segment) |byte| {
            if (byte <= 0x20 or byte == 0x7f) return false;
        }
    }
    return true;
}

const TimestampResult = union(enum) {
    value: LocatedTimestamp,
    diagnostic: Diagnostic,
};

fn parseTimestampField(field: deb822.Field) TimestampResult {
    const located = switch (scalar(field)) {
        .value => |value| value,
        .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
    };
    return parseTimestamp(located);
}

fn parseTimestamp(located: LocatedString) TimestampResult {
    var tokens: [7]Token = undefined;
    var count: usize = 0;
    var index: usize = 0;
    while (nextToken(located.value, &index)) |token| {
        if (count == tokens.len) return timestampFailure(located.span);
        tokens[count] = token;
        count += 1;
    }
    if (count != 5 and count != 6) return timestampFailure(located.span);

    var token_offset: usize = 0;
    var weekday: ?Weekday = null;
    if (count == 6) {
        const weekday_text = tokens[0].text;
        if (weekday_text.len != 4 or weekday_text[3] != ',') return timestampFailure(located.span);
        weekday = parseWeekday(weekday_text[0..3]) orelse return timestampFailure(located.span);
        token_offset = 1;
    }

    const day = parseFixedOrVariableUnsigned(u8, tokens[token_offset].text, 1, 2) orelse
        return timestampFailure(located.span);
    const month = parseMonth(tokens[token_offset + 1].text) orelse
        return timestampFailure(located.span);
    const year = parseFixedOrVariableUnsigned(u16, tokens[token_offset + 2].text, 4, 4) orelse
        return timestampFailure(located.span);
    const time = parseTime(tokens[token_offset + 3].text) orelse
        return timestampFailure(located.span);
    const offset = parseZone(tokens[token_offset + 4].text) orelse
        return timestampFailure(located.span);

    if (!validCalendarDate(year, month, day)) return timestampFailure(located.span);
    if (weekday) |declared| {
        if (calendarWeekday(year, month, day) != declared) {
            return .{ .diagnostic = .{
                .code = .invalid_timestamp_weekday,
                .span = located.span,
            } };
        }
    }

    return .{ .value = .{
        .value = .{
            .weekday = weekday,
            .year = year,
            .month = month,
            .day = day,
            .hour = time.hour,
            .minute = time.minute,
            .second = time.second,
            .utc_offset_minutes = offset,
        },
        .span = located.span,
    } };
}

fn timestampFailure(span: Span) TimestampResult {
    return .{ .diagnostic = .{ .code = .invalid_timestamp, .span = span } };
}

fn parseWeekday(text: []const u8) ?Weekday {
    if (std.ascii.eqlIgnoreCase(text, "Mon")) return .monday;
    if (std.ascii.eqlIgnoreCase(text, "Tue")) return .tuesday;
    if (std.ascii.eqlIgnoreCase(text, "Wed")) return .wednesday;
    if (std.ascii.eqlIgnoreCase(text, "Thu")) return .thursday;
    if (std.ascii.eqlIgnoreCase(text, "Fri")) return .friday;
    if (std.ascii.eqlIgnoreCase(text, "Sat")) return .saturday;
    if (std.ascii.eqlIgnoreCase(text, "Sun")) return .sunday;
    return null;
}

fn parseMonth(text: []const u8) ?u8 {
    const months = [_][]const u8{
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    };
    for (months, 1..) |month, number| {
        if (std.ascii.eqlIgnoreCase(text, month)) return @intCast(number);
    }
    return null;
}

const Time = struct { hour: u8, minute: u8, second: u8 };

fn parseTime(text: []const u8) ?Time {
    if (text.len != 5 and text.len != 8) return null;
    if (text[2] != ':' or (text.len == 8 and text[5] != ':')) return null;
    const hour = parseFixedOrVariableUnsigned(u8, text[0..2], 2, 2) orelse return null;
    const minute = parseFixedOrVariableUnsigned(u8, text[3..5], 2, 2) orelse return null;
    const second = if (text.len == 8)
        parseFixedOrVariableUnsigned(u8, text[6..8], 2, 2) orelse return null
    else
        0;
    if (hour > 23 or minute > 59 or second > 60) return null;
    return .{ .hour = hour, .minute = minute, .second = second };
}

fn parseZone(text: []const u8) ?i16 {
    if (std.ascii.eqlIgnoreCase(text, "UTC") or
        std.ascii.eqlIgnoreCase(text, "GMT") or
        std.ascii.eqlIgnoreCase(text, "UT"))
    {
        return 0;
    }
    if (text.len != 5 or (text[0] != '+' and text[0] != '-')) return null;
    const hours = parseFixedOrVariableUnsigned(i16, text[1..3], 2, 2) orelse return null;
    const minutes = parseFixedOrVariableUnsigned(i16, text[3..5], 2, 2) orelse return null;
    if (hours > 23 or minutes > 59) return null;
    const total = hours * 60 + minutes;
    return if (text[0] == '-') -total else total;
}

fn parseFixedOrVariableUnsigned(
    comptime T: type,
    text: []const u8,
    minimum: usize,
    maximum: usize,
) ?T {
    if (text.len < minimum or text.len > maximum or !allDecimal(text)) return null;
    return std.fmt.parseUnsigned(T, text, 10) catch null;
}

fn validCalendarDate(year: u16, month: u8, day: u8) bool {
    if (year == 0 or month < 1 or month > 12 or day == 0) return false;
    const lengths = [_]u8{ 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    var maximum = lengths[month - 1];
    if (month == 2 and isLeapYear(year)) maximum = 29;
    return day <= maximum;
}

fn isLeapYear(year: u16) bool {
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0);
}

fn calendarWeekday(year: u16, month: u8, day: u8) Weekday {
    var y: i32 = year;
    const month_offsets = [_]i32{ 0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4 };
    if (month < 3) y -= 1;
    const sunday_zero = @mod(
        y + @divTrunc(y, 4) - @divTrunc(y, 100) + @divTrunc(y, 400) +
            month_offsets[month - 1] + day,
        7,
    );
    return switch (sunday_zero) {
        0 => .sunday,
        1 => .monday,
        2 => .tuesday,
        3 => .wednesday,
        4 => .thursday,
        5 => .friday,
        else => .saturday,
    };
}

fn tokenSpan(line: deb822.ValueLine, token: Token) Span {
    return .{
        .start = line.span.start.offset + token.start,
        .end = line.span.start.offset + token.end,
    };
}

fn fromDeb822Span(span: deb822.Span) Span {
    return .{ .start = span.start.offset, .end = span.end.offset };
}

fn pointSpan(offset: usize, source_len: usize) Span {
    return .{ .start = @min(offset, source_len), .end = @min(offset + 1, source_len) };
}

fn isHorizontalWhitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

fn isWhitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t';
}

fn expectDiagnostic(input: []const u8, limits: Limits, code: DiagnosticCode) !Diagnostic {
    const result = try parse(std.testing.allocator, input, limits);
    return switch (result) {
        .metadata => |metadata_value| {
            var metadata = metadata_value;
            metadata.deinit();
            return error.ExpectedDiagnostic;
        },
        .diagnostic => |diagnostic| blk: {
            try std.testing.expectEqual(code, diagnostic.code);
            break :blk diagnostic;
        },
    };
}

test "parses typed Release metadata and SHA256 indexes" {
    const input =
        "Origin: Debian\n" ++
        "Label: Debian\n" ++
        "Suite: stable\n" ++
        "Codename: trixie\n" ++
        "Version: 13.0\n" ++
        "Date: Thu, 14 Aug 2025 18:55:17 UTC\n" ++
        "Valid-Until: Fri, 15 Aug 2025 20:00 +0130\n" ++
        "Architectures: amd64 arm64\n" ++
        "Components: main non-free-firmware\n" ++
        "Acquire-By-Hash: yes\n" ++
        "MD5Sum:\n" ++
        " bad compatibility data is ignored\n" ++
        "SHA256:\n" ++
        " 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 42 main/binary-amd64/Packages.xz\n" ++
        " FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF 0 InRelease\n";
    const result = try parse(std.testing.allocator, input, .{});
    var metadata = switch (result) {
        .metadata => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer metadata.deinit();

    try std.testing.expectEqualStrings("Debian", metadata.origin.?.value);
    try std.testing.expectEqualStrings("stable", metadata.suite.?.value);
    try std.testing.expectEqualStrings("trixie", metadata.codename.?.value);
    try std.testing.expectEqual(@as(usize, 2), metadata.architectures.len);
    try std.testing.expectEqualStrings("arm64", metadata.architectures[1].value);
    try std.testing.expect(metadata.acquire_by_hash.?.value);
    try std.testing.expectEqual(@as(u16, 2025), metadata.date.?.value.year);
    try std.testing.expectEqual(@as(i16, 90), metadata.valid_until.?.value.utc_offset_minutes);
    try std.testing.expectEqual(@as(usize, 2), metadata.sha256_entries.len);
    try std.testing.expectEqual(@as(u64, 42), metadata.sha256_entries[0].size);
    try std.testing.expectEqualStrings(
        "main/binary-amd64/Packages.xz",
        metadata.sha256_entries[0].path.value,
    );
    try std.testing.expectEqual(@as(u8, 0x01), metadata.sha256_entries[0].digest.bytes[0]);
    try std.testing.expectEqual(@as(u8, 0xff), metadata.sha256_entries[1].digest.bytes[31]);
}

test "timestamp parser is typed but performs no clock policy" {
    const result = try parse(
        std.testing.allocator,
        "Date: 29 Feb 2024 23:59:60 -0500\nValid-Until: 1 Mar 2024 00:00:00 UTC\n",
        .{},
    );
    var metadata = switch (result) {
        .metadata => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer metadata.deinit();
    try std.testing.expect(metadata.date.?.value.weekday == null);
    try std.testing.expectEqual(@as(u8, 60), metadata.date.?.value.second);
    try std.testing.expectEqual(@as(i16, -300), metadata.date.?.value.utc_offset_minutes);
}

test "rejects invalid timestamps and mismatched weekdays" {
    _ = try expectDiagnostic("Date: Thu, 29 Feb 2023 00:00:00 UTC\n", .{}, .invalid_timestamp);
    _ = try expectDiagnostic(
        "Date: Mon, 14 Aug 2025 18:55:17 UTC\n",
        .{},
        .invalid_timestamp_weekday,
    );
    _ = try expectDiagnostic("Date: Thu, 14 Aug 2025 25:00:00 UTC\n", .{}, .invalid_timestamp);
    _ = try expectDiagnostic("Date: Thu, 14 Aug 2025 18:00:00 PST\n", .{}, .invalid_timestamp);
}

test "validates checksum digest size and row shape" {
    _ = try expectDiagnostic(
        "SHA256:\n abc 1 path\n",
        .{},
        .invalid_sha256_digest,
    );
    _ = try expectDiagnostic(
        "SHA256:\n 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 18446744073709551616 path\n",
        .{},
        .invalid_checksum_size,
    );
    _ = try expectDiagnostic(
        "SHA256:\n 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 1 path extra\n",
        .{},
        .malformed_checksum_row,
    );
}

test "rejects ambiguous and non-normalized checksum paths" {
    const digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    inline for (.{
        "/absolute",
        "../traversal",
        "a/../b",
        "a/./b",
        "a//b",
        "a/",
        "a\\b",
    }) |path| {
        const input = try std.fmt.allocPrint(std.testing.allocator, "SHA256:\n {s} 1 {s}\n", .{
            digest, path,
        });
        defer std.testing.allocator.free(input);
        _ = try expectDiagnostic(input, .{}, .invalid_checksum_path);
    }
}

test "distinguishes duplicate and conflicting SHA256 records" {
    const first = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const second = "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const duplicate = try std.fmt.allocPrint(
        std.testing.allocator,
        "SHA256:\n {s} 1 path\n {s} 1 path\n",
        .{ first, first },
    );
    defer std.testing.allocator.free(duplicate);
    _ = try expectDiagnostic(duplicate, .{}, .duplicate_checksum_path);

    const conflict = try std.fmt.allocPrint(
        std.testing.allocator,
        "SHA256:\n {s} 1 path\n {s} 2 path\n",
        .{ first, second },
    );
    defer std.testing.allocator.free(conflict);
    _ = try expectDiagnostic(conflict, .{}, .conflicting_checksum_path);
}

test "preserves actionable spans" {
    const input = "Acquire-By-Hash: maybe\n";
    const diagnostic = try expectDiagnostic(input, .{}, .invalid_boolean);
    try std.testing.expectEqualStrings("maybe", diagnostic.span.slice(input));

    const checksum =
        "SHA256:\n" ++
        " 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 1 ../bad\n";
    const path_diagnostic = try expectDiagnostic(checksum, .{}, .invalid_checksum_path);
    try std.testing.expectEqualStrings("../bad", path_diagnostic.span.slice(checksum));
}

test "enforces byte field list and checksum row limits" {
    _ = try expectDiagnostic("Origin: Debian\n", .{ .max_input_bytes = 5 }, .input_too_long);
    _ = try expectDiagnostic(
        "Origin: Debian\nLabel: Debian\n",
        .{ .max_fields = 1 },
        .too_many_fields,
    );
    _ = try expectDiagnostic(
        "Origin: Debian\n",
        .{ .max_field_bytes = 5 },
        .field_too_long,
    );
    _ = try expectDiagnostic(
        "Architectures: amd64 arm64\n",
        .{ .max_list_items = 1 },
        .too_many_list_items,
    );
    _ = try expectDiagnostic(
        "SHA256:\n 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef 1 path\n",
        .{ .max_checksum_rows = 0 },
        .too_many_checksum_rows,
    );
}

test "requires one paragraph and rejects duplicate fields" {
    _ = try expectDiagnostic("", .{}, .too_many_paragraphs);
    _ = try expectDiagnostic("Origin: one\n\nOrigin: two\n", .{}, .too_many_paragraphs);
    _ = try expectDiagnostic("Origin: one\norigin: two\n", .{}, .duplicate_field);
}

test "validates typed lists and scalar shapes" {
    _ = try expectDiagnostic("Architectures: amd64 x86_64\n", .{}, .invalid_list_item);
    _ = try expectDiagnostic("Components: main/path\n", .{}, .invalid_list_item);
    _ = try expectDiagnostic("Suite:\n", .{}, .empty_scalar);
    _ = try expectDiagnostic("Suite: stable\n continued\n", .{}, .multiline_scalar);
    _ = try expectDiagnostic("Acquire-By-Hash: true\n", .{}, .invalid_boolean);
}
