const std = @import("std");

pub const Position = struct {
    offset: usize,
    line: usize,
    column: usize,
};

pub const Span = struct {
    start: Position,
    end: Position,
};

pub const Limits = struct {
    max_total_bytes: usize = 16 * 1024 * 1024,
    max_paragraphs: usize = 100_000,
    max_fields_per_paragraph: usize = 1_000,
    /// Field-name bytes plus logical value bytes, including continuation newlines.
    max_field_bytes: usize = 1024 * 1024,
};

pub const DuplicatePolicy = enum {
    reject,
    allow,
};

pub const Options = struct {
    limits: Limits = .{},
    duplicate_policy: DuplicatePolicy = .reject,
    /// Ignore whole lines whose first byte is '#'. DEB822 consumers that
    /// define comment lines, such as Debian `.sources` files, opt in.
    allow_comments: bool = false,
};

pub const ErrorKind = enum {
    total_bytes_limit,
    paragraph_limit,
    fields_limit,
    field_size_limit,
    missing_colon,
    invalid_field_name,
    continuation_without_field,
    duplicate_field,
    bare_carriage_return,
};

pub const ParseFailure = struct {
    kind: ErrorKind,
    position: Position,
};

pub const ValueLine = struct {
    text: []const u8,
    span: Span,
};

pub const Field = struct {
    name: []const u8,
    name_span: Span,
    value_lines: []const ValueLine,
    span: Span,

    pub fn valueByteCount(self: Field) usize {
        var size: usize = 0;
        for (self.value_lines, 0..) |line, index| {
            size += line.text.len;
            if (index != 0) size += 1;
        }
        return size;
    }
};

pub const Paragraph = struct {
    fields: []const Field,
    span: Span,

    pub fn get(self: Paragraph, name: []const u8) ?*const Field {
        for (self.fields) |*field| {
            if (std.ascii.eqlIgnoreCase(field.name, name)) return field;
        }
        return null;
    }
};

/// The document owns its metadata, while all field text borrows `input`.
/// `input` must outlive this value.
pub const BorrowedDocument = struct {
    paragraphs: []const Paragraph,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *BorrowedDocument) void {
        for (self.paragraphs) |paragraph| {
            for (paragraph.fields) |field| self.allocator.free(field.value_lines);
            self.allocator.free(paragraph.fields);
        }
        self.allocator.free(self.paragraphs);
        self.* = undefined;
    }
};

/// Owns both the source bytes and parsed metadata.
pub const OwnedDocument = struct {
    source: []u8,
    document: BorrowedDocument,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedDocument) void {
        self.document.deinit();
        self.allocator.free(self.source);
        self.* = undefined;
    }
};

pub const BorrowedOutcome = union(enum) {
    document: BorrowedDocument,
    failure: ParseFailure,
};

pub const OwnedOutcome = union(enum) {
    document: OwnedDocument,
    failure: ParseFailure,
};

const Line = struct {
    text: []const u8,
    start: Position,
    end: Position,
    next_offset: usize,
    next_line: usize,
};

pub fn parseBorrowed(
    allocator: std.mem.Allocator,
    input: []const u8,
    options: Options,
) std.mem.Allocator.Error!BorrowedOutcome {
    if (input.len > options.limits.max_total_bytes) {
        return .{ .failure = .{
            .kind = .total_bytes_limit,
            .position = positionAt(input, options.limits.max_total_bytes),
        } };
    }

    var paragraphs: std.ArrayList(Paragraph) = .empty;
    var fields: std.ArrayList(Field) = .empty;
    var current_values: std.ArrayList(ValueLine) = .empty;
    var complete = false;
    defer {
        if (!complete) {
            for (fields.items) |field| allocator.free(field.value_lines);
            for (paragraphs.items) |paragraph| freeParagraph(allocator, paragraph);
        }
        fields.deinit(allocator);
        paragraphs.deinit(allocator);
        current_values.deinit(allocator);
    }

    var offset: usize = 0;
    var line_number: usize = 1;
    var paragraph_start: ?Position = null;
    var last_end = Position{ .offset = 0, .line = 1, .column = 1 };

    while (offset < input.len) {
        const line_result = nextLine(input, offset, line_number);
        const line = switch (line_result) {
            .line => |value| value,
            .bare_cr => |position| return failureWithCleanup(
                allocator,
                &fields,
                &current_values,
                .bare_carriage_return,
                position,
            ),
        };
        offset = line.next_offset;
        line_number = line.next_line;
        last_end = line.end;

        if (line.text.len == 0) {
            if (fields.items.len != 0) {
                try finishParagraph(
                    allocator,
                    &paragraphs,
                    &fields,
                    paragraph_start.?,
                    line.start,
                    options.limits.max_paragraphs,
                ) orelse return failureWithCleanup(
                    allocator,
                    &fields,
                    &current_values,
                    .paragraph_limit,
                    paragraph_start.?,
                );
                paragraph_start = null;
            }
            continue;
        }

        if (options.allow_comments and line.text[0] == '#') continue;

        if (line.text[0] == ' ' or line.text[0] == '\t') {
            if (fields.items.len == 0) {
                return failureWithCleanup(
                    allocator,
                    &fields,
                    &current_values,
                    .continuation_without_field,
                    line.start,
                );
            }
            const value_start = Position{
                .offset = line.start.offset + 1,
                .line = line.start.line,
                .column = 2,
            };
            const text = line.text[1..];
            const field = fields.items[fields.items.len - 1];
            const new_size = field.name.len + field.valueByteCount() + 1 + text.len;
            if (new_size > options.limits.max_field_bytes) {
                return failureWithCleanup(
                    allocator,
                    &fields,
                    &current_values,
                    .field_size_limit,
                    value_start,
                );
            }
            const old_lines = fields.items[fields.items.len - 1].value_lines;
            current_values.clearRetainingCapacity();
            try current_values.appendSlice(allocator, old_lines);
            try current_values.append(allocator, .{
                .text = text,
                .span = .{ .start = value_start, .end = line.end },
            });
            const replacement = try current_values.toOwnedSlice(allocator);
            allocator.free(old_lines);
            fields.items[fields.items.len - 1].value_lines = replacement;
            fields.items[fields.items.len - 1].span.end = line.end;
            continue;
        }

        if (fields.items.len >= options.limits.max_fields_per_paragraph) {
            return failureWithCleanup(
                allocator,
                &fields,
                &current_values,
                .fields_limit,
                line.start,
            );
        }
        const colon = std.mem.indexOfScalar(u8, line.text, ':') orelse
            return failureWithCleanup(
                allocator,
                &fields,
                &current_values,
                .missing_colon,
                line.start,
            );
        if (!validFieldName(line.text[0..colon])) {
            return failureWithCleanup(
                allocator,
                &fields,
                &current_values,
                .invalid_field_name,
                line.start,
            );
        }
        const name = line.text[0..colon];
        if (options.duplicate_policy == .reject) {
            for (fields.items) |field| {
                if (std.ascii.eqlIgnoreCase(field.name, name)) {
                    return failureWithCleanup(
                        allocator,
                        &fields,
                        &current_values,
                        .duplicate_field,
                        line.start,
                    );
                }
            }
        }

        var value_index = colon + 1;
        while (value_index < line.text.len and
            (line.text[value_index] == ' ' or line.text[value_index] == '\t'))
        {
            value_index += 1;
        }
        const value = line.text[value_index..];
        if (name.len + value.len > options.limits.max_field_bytes) {
            return failureWithCleanup(
                allocator,
                &fields,
                &current_values,
                .field_size_limit,
                line.start,
            );
        }
        const name_end = Position{
            .offset = line.start.offset + colon,
            .line = line.start.line,
            .column = colon + 1,
        };
        const value_start = Position{
            .offset = line.start.offset + value_index,
            .line = line.start.line,
            .column = value_index + 1,
        };
        const values = try allocator.alloc(ValueLine, 1);
        values[0] = .{
            .text = value,
            .span = .{ .start = value_start, .end = line.end },
        };
        fields.append(allocator, .{
            .name = name,
            .name_span = .{ .start = line.start, .end = name_end },
            .value_lines = values,
            .span = .{ .start = line.start, .end = line.end },
        }) catch |err| {
            allocator.free(values);
            return err;
        };
        if (paragraph_start == null) paragraph_start = line.start;
    }

    if (fields.items.len != 0) {
        try finishParagraph(
            allocator,
            &paragraphs,
            &fields,
            paragraph_start.?,
            last_end,
            options.limits.max_paragraphs,
        ) orelse return failureWithCleanup(
            allocator,
            &fields,
            &current_values,
            .paragraph_limit,
            paragraph_start.?,
        );
    }

    const owned_paragraphs = try paragraphs.toOwnedSlice(allocator);
    complete = true;
    return .{ .document = .{
        .paragraphs = owned_paragraphs,
        .allocator = allocator,
    } };
}

pub fn parseOwned(
    allocator: std.mem.Allocator,
    input: []const u8,
    options: Options,
) std.mem.Allocator.Error!OwnedOutcome {
    const source = try allocator.dupe(u8, input);
    errdefer allocator.free(source);
    const outcome = try parseBorrowed(allocator, source, options);
    return switch (outcome) {
        .failure => |failure| blk: {
            allocator.free(source);
            break :blk .{ .failure = failure };
        },
        .document => |document| .{ .document = .{
            .source = source,
            .document = document,
            .allocator = allocator,
        } },
    };
}

const NextLine = union(enum) {
    line: Line,
    bare_cr: Position,
};

fn nextLine(input: []const u8, offset: usize, line_number: usize) NextLine {
    var index = offset;
    while (index < input.len and input[index] != '\n' and input[index] != '\r') : (index += 1) {}
    const start = Position{ .offset = offset, .line = line_number, .column = 1 };
    const end = Position{
        .offset = index,
        .line = line_number,
        .column = index - offset + 1,
    };
    if (index == input.len) {
        return .{ .line = .{
            .text = input[offset..index],
            .start = start,
            .end = end,
            .next_offset = index,
            .next_line = line_number,
        } };
    }
    if (input[index] == '\r') {
        if (index + 1 >= input.len or input[index + 1] != '\n') {
            return .{ .bare_cr = end };
        }
        return .{ .line = .{
            .text = input[offset..index],
            .start = start,
            .end = end,
            .next_offset = index + 2,
            .next_line = line_number + 1,
        } };
    }
    return .{ .line = .{
        .text = input[offset..index],
        .start = start,
        .end = end,
        .next_offset = index + 1,
        .next_line = line_number + 1,
    } };
}

fn finishParagraph(
    allocator: std.mem.Allocator,
    paragraphs: *std.ArrayList(Paragraph),
    fields: *std.ArrayList(Field),
    start: Position,
    end: Position,
    limit: usize,
) std.mem.Allocator.Error!?void {
    if (paragraphs.items.len >= limit) return null;
    const owned_fields = try fields.toOwnedSlice(allocator);
    errdefer {
        for (owned_fields) |field| allocator.free(field.value_lines);
        allocator.free(owned_fields);
    }
    try paragraphs.append(allocator, .{
        .fields = owned_fields,
        .span = .{ .start = start, .end = end },
    });
    return {};
}

fn failureWithCleanup(
    allocator: std.mem.Allocator,
    fields: *std.ArrayList(Field),
    current_values: *std.ArrayList(ValueLine),
    kind: ErrorKind,
    position: Position,
) BorrowedOutcome {
    _ = current_values;
    for (fields.items) |field| allocator.free(field.value_lines);
    fields.clearRetainingCapacity();
    return .{ .failure = .{ .kind = kind, .position = position } };
}

fn freeParagraph(allocator: std.mem.Allocator, paragraph: Paragraph) void {
    for (paragraph.fields) |field| allocator.free(field.value_lines);
    allocator.free(paragraph.fields);
}

fn validFieldName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |character| {
        if (character < 33 or character > 126 or character == ':') return false;
    }
    return true;
}

fn positionAt(input: []const u8, target: usize) Position {
    var position = Position{ .offset = 0, .line = 1, .column = 1 };
    var index: usize = 0;
    while (index < target and index < input.len) : (index += 1) {
        if (input[index] == '\n') {
            position.line += 1;
            position.column = 1;
        } else {
            position.column += 1;
        }
        position.offset += 1;
    }
    return position;
}

fn expectFailure(
    input: []const u8,
    options: Options,
    kind: ErrorKind,
    offset: usize,
    line: usize,
    column: usize,
) !void {
    const result = try parseBorrowed(std.testing.allocator, input, options);
    switch (result) {
        .document => |document_value| {
            var document = document_value;
            defer document.deinit();
            return error.ExpectedFailure;
        },
        .failure => |failure| {
            try std.testing.expectEqual(kind, failure.kind);
            try std.testing.expectEqual(offset, failure.position.offset);
            try std.testing.expectEqual(line, failure.position.line);
            try std.testing.expectEqual(column, failure.position.column);
        },
    }
}

test "parses paragraphs, ordered fields, continuations, and CRLF" {
    const input =
        "Package: debz\r\n" ++
        "Description: first line\r\n" ++
        " second line\r\n" ++
        "\tthird line\r\n" ++
        "\r\n" ++
        "Package: other\r\n" ++
        "Empty:\r\n";
    const result = try parseBorrowed(std.testing.allocator, input, .{});
    var document = switch (result) {
        .document => |value| value,
        .failure => return error.UnexpectedParseFailure,
    };
    defer document.deinit();

    try std.testing.expectEqual(2, document.paragraphs.len);
    try std.testing.expectEqualStrings("Package", document.paragraphs[0].fields[0].name);
    try std.testing.expectEqualStrings("debz", document.paragraphs[0].fields[0].value_lines[0].text);
    const description = document.paragraphs[0].get("description").?;
    try std.testing.expectEqual(3, description.value_lines.len);
    try std.testing.expectEqualStrings("first line", description.value_lines[0].text);
    try std.testing.expectEqualStrings("second line", description.value_lines[1].text);
    try std.testing.expectEqualStrings("third line", description.value_lines[2].text);
    try std.testing.expectEqual(33, description.valueByteCount());
    try std.testing.expectEqualStrings("", document.paragraphs[1].fields[1].value_lines[0].text);
}

test "owned parse remains valid after caller input changes" {
    var input = [_]u8{ 'N', 'a', 'm', 'e', ':', ' ', 'o', 'l', 'd' };
    const result = try parseOwned(std.testing.allocator, &input, .{});
    var owned = switch (result) {
        .document => |value| value,
        .failure => return error.UnexpectedParseFailure,
    };
    defer owned.deinit();
    input[6] = 'X';
    try std.testing.expectEqualStrings("old", owned.document.paragraphs[0].fields[0].value_lines[0].text);
}

test "duplicate policy is case insensitive and explicit" {
    try expectFailure("Name: one\nname: two\n", .{}, .duplicate_field, 10, 2, 1);

    const result = try parseBorrowed(std.testing.allocator, "Name: one\nname: two\n", .{
        .duplicate_policy = .allow,
    });
    var document = switch (result) {
        .document => |value| value,
        .failure => return error.UnexpectedParseFailure,
    };
    defer document.deinit();
    try std.testing.expectEqual(2, document.paragraphs[0].fields.len);
}

test "reports malformed input positions" {
    try expectFailure("Name value\n", .{}, .missing_colon, 0, 1, 1);
    try expectFailure(": value\n", .{}, .invalid_field_name, 0, 1, 1);
    try expectFailure("Bad Name: value\n", .{}, .invalid_field_name, 0, 1, 1);
    try expectFailure(" continuation\n", .{}, .continuation_without_field, 0, 1, 1);
    try expectFailure("Name: value\rbad\n", .{}, .bare_carriage_return, 11, 1, 12);
}

test "enforces every configured bound" {
    try expectFailure("Name: value\n", .{
        .limits = .{ .max_total_bytes = 5 },
    }, .total_bytes_limit, 5, 1, 6);
    try expectFailure("A: 1\n\nB: 2\n", .{
        .limits = .{ .max_paragraphs = 1 },
    }, .paragraph_limit, 6, 3, 1);
    try expectFailure("A: 1\nB: 2\n", .{
        .limits = .{ .max_fields_per_paragraph = 1 },
    }, .fields_limit, 5, 2, 1);
    try expectFailure("Name: value\n", .{
        .limits = .{ .max_field_bytes = 8 },
    }, .field_size_limit, 0, 1, 1);
    try expectFailure("A: 1\n 234\n", .{
        .limits = .{ .max_field_bytes = 5 },
    }, .field_size_limit, 6, 2, 2);
}

test "accepts empty input and repeated blank lines" {
    inline for (.{ "", "\n\n", "\r\n\r\n" }) |input| {
        const result = try parseBorrowed(std.testing.allocator, input, .{});
        var document = switch (result) {
            .document => |value| value,
            .failure => return error.UnexpectedParseFailure,
        };
        defer document.deinit();
        try std.testing.expectEqual(0, document.paragraphs.len);
    }
}

test "comment lines are opt-in and do not split paragraphs" {
    const input = "# heading\nName: one\n# between fields\nValue: two\n";
    const result = try parseBorrowed(std.testing.allocator, input, .{
        .allow_comments = true,
    });
    var document = switch (result) {
        .document => |value| value,
        .failure => return error.UnexpectedParseFailure,
    };
    defer document.deinit();
    try std.testing.expectEqual(1, document.paragraphs.len);
    try std.testing.expectEqual(2, document.paragraphs[0].fields.len);
}
