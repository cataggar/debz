const std = @import("std");
const deb822 = @import("deb822.zig");
const version_module = @import("debian_version.zig");
const relation_module = @import("relation.zig");

pub const DebianVersion = version_module.DebianVersion;

pub const Token = struct {
    text: []const u8,
    span: deb822.Span,
};

pub const VersionValue = struct {
    value: DebianVersion,
    span: deb822.Span,
};

pub const Source = struct {
    package: Token,
    version: ?VersionValue = null,
    span: deb822.Span,
};

pub const Priority = enum {
    required,
    important,
    standard,
    optional,
    extra,
};

pub const MultiArch = enum {
    no,
    same,
    foreign,
    allowed,
};

pub const RelationValue = struct {
    source: []u8,
    value: relation_module.Relation,
    field_span: deb822.Span,

    pub fn deinit(self: *RelationValue, allocator: std.mem.Allocator) void {
        self.value.deinit(allocator);
        allocator.free(self.source);
        self.* = undefined;
    }
};

pub const UnknownField = struct {
    name: []const u8,
    value_lines: []const deb822.ValueLine,
    span: deb822.Span,
};

pub const Record = struct {
    package: Token,
    version: VersionValue,
    architecture: Token,
    source: ?Source = null,
    essential: ?bool = null,
    protected: ?bool = null,
    important: ?bool = null,
    priority: ?Priority = null,
    multi_arch: ?MultiArch = null,
    installed_size: ?u64 = null,
    built_using: ?RelationValue = null,
    depends: ?RelationValue = null,
    pre_depends: ?RelationValue = null,
    recommends: ?RelationValue = null,
    suggests: ?RelationValue = null,
    enhances: ?RelationValue = null,
    provides: ?RelationValue = null,
    conflicts: ?RelationValue = null,
    breaks: ?RelationValue = null,
    replaces: ?RelationValue = null,
    unknown_fields: []const UnknownField = &.{},
    span: deb822.Span,

    fn deinit(self: *Record, allocator: std.mem.Allocator) void {
        inline for (.{
            "built_using",
            "depends",
            "pre_depends",
            "recommends",
            "suggests",
            "enhances",
            "provides",
            "conflicts",
            "breaks",
            "replaces",
        }) |name| {
            if (@field(self, name)) |*value| value.deinit(allocator);
        }
        allocator.free(self.unknown_fields);
        self.* = undefined;
    }
};

/// Owns parser metadata and relation value buffers while borrowing field text
/// from the caller's `input`. The input must outlive this document.
pub const BorrowedDocument = struct {
    records: []Record,
    deb822_document: deb822.BorrowedDocument,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *BorrowedDocument) void {
        for (self.records) |*record| record.deinit(self.allocator);
        self.allocator.free(self.records);
        self.deb822_document.deinit();
        self.* = undefined;
    }
};

pub const Limits = struct {
    deb822: deb822.Limits = .{},
    max_records: usize = 100_000,
    max_unknown_fields_per_record: usize = 512,
    relation: relation_module.Limits = .{},
};

pub const Options = struct {
    limits: Limits = .{},
};

pub const DiagnosticKind = enum {
    deb822_syntax,
    too_many_records,
    too_many_unknown_fields,
    missing_package,
    missing_version,
    missing_architecture,
    scalar_must_be_single_line,
    invalid_package,
    invalid_version,
    invalid_architecture,
    invalid_source,
    invalid_boolean,
    invalid_priority,
    invalid_multi_arch,
    invalid_installed_size,
    invalid_relation,
    invalid_relation_version,
};

pub const Diagnostic = struct {
    kind: DiagnosticKind,
    span: deb822.Span,
    field_name: ?[]const u8 = null,
    deb822_kind: ?deb822.ErrorKind = null,
    relation_kind: ?relation_module.DiagnosticCode = null,
};

pub const ParseOutcome = union(enum) {
    document: BorrowedDocument,
    diagnostic: Diagnostic,
};

pub fn parseBorrowed(
    allocator: std.mem.Allocator,
    input: []const u8,
    options: Options,
) std.mem.Allocator.Error!ParseOutcome {
    const raw_outcome = try deb822.parseBorrowed(allocator, input, .{
        .limits = options.limits.deb822,
        .duplicate_policy = .reject,
    });
    var raw = switch (raw_outcome) {
        .document => |document| document,
        .failure => |failure| return .{ .diagnostic = .{
            .kind = .deb822_syntax,
            .span = .{ .start = failure.position, .end = failure.position },
            .deb822_kind = failure.kind,
        } },
    };
    errdefer raw.deinit();

    if (raw.paragraphs.len > options.limits.max_records) {
        const paragraph = raw.paragraphs[options.limits.max_records];
        const diagnostic: Diagnostic = .{
            .kind = .too_many_records,
            .span = paragraph.span,
        };
        raw.deinit();
        return .{ .diagnostic = diagnostic };
    }

    var parser: Parser = .{
        .allocator = allocator,
        .limits = options.limits,
    };
    var records: std.ArrayList(Record) = .empty;
    errdefer {
        for (records.items) |*record| record.deinit(allocator);
        records.deinit(allocator);
    }

    for (raw.paragraphs) |paragraph| {
        var record = parser.parseRecord(paragraph) catch |err| switch (err) {
            error.InvalidRecord => {
                for (records.items) |*item| item.deinit(allocator);
                records.deinit(allocator);
                raw.deinit();
                return .{ .diagnostic = parser.diagnostic.? };
            },
            error.OutOfMemory => return error.OutOfMemory,
        };
        records.append(allocator, record) catch |err| {
            record.deinit(allocator);
            return err;
        };
    }

    return .{ .document = .{
        .records = try records.toOwnedSlice(allocator),
        .deb822_document = raw,
        .allocator = allocator,
    } };
}

const Parser = struct {
    allocator: std.mem.Allocator,
    limits: Limits,
    diagnostic: ?Diagnostic = null,

    const Error = std.mem.Allocator.Error || error{InvalidRecord};

    fn parseRecord(self: *Parser, paragraph: deb822.Paragraph) Error!Record {
        const package_field = paragraph.get("Package") orelse
            return self.fail(.missing_package, paragraph.span, "Package");
        const version_field = paragraph.get("Version") orelse
            return self.fail(.missing_version, paragraph.span, "Version");
        const architecture_field = paragraph.get("Architecture") orelse
            return self.fail(.missing_architecture, paragraph.span, "Architecture");

        const package = try self.parsePackage(package_field, .invalid_package);
        const parsed_version = try self.parseVersion(version_field, .invalid_version);
        const architecture = try self.parseArchitecture(architecture_field);

        var record: Record = .{
            .package = package,
            .version = parsed_version,
            .architecture = architecture,
            .span = paragraph.span,
        };
        errdefer record.deinit(self.allocator);

        var unknown: std.ArrayList(UnknownField) = .empty;
        defer unknown.deinit(self.allocator);

        for (paragraph.fields) |*field| {
            if (isIdentityField(field.name)) continue;
            if (std.ascii.eqlIgnoreCase(field.name, "Source")) {
                record.source = try self.parseSource(field);
            } else if (std.ascii.eqlIgnoreCase(field.name, "Essential")) {
                record.essential = try self.parseBoolean(field);
            } else if (std.ascii.eqlIgnoreCase(field.name, "Protected")) {
                record.protected = try self.parseBoolean(field);
            } else if (std.ascii.eqlIgnoreCase(field.name, "Important")) {
                record.important = try self.parseBoolean(field);
            } else if (std.ascii.eqlIgnoreCase(field.name, "Priority")) {
                record.priority = try self.parsePriority(field);
            } else if (std.ascii.eqlIgnoreCase(field.name, "Multi-Arch")) {
                record.multi_arch = try self.parseMultiArch(field);
            } else if (std.ascii.eqlIgnoreCase(field.name, "Installed-Size")) {
                record.installed_size = try self.parseInstalledSize(field);
            } else if (relationFieldMember(field.name)) |member| {
                const value = try self.parseRelation(field);
                switch (member) {
                    .built_using => record.built_using = value,
                    .depends => record.depends = value,
                    .pre_depends => record.pre_depends = value,
                    .recommends => record.recommends = value,
                    .suggests => record.suggests = value,
                    .enhances => record.enhances = value,
                    .provides => record.provides = value,
                    .conflicts => record.conflicts = value,
                    .breaks => record.breaks = value,
                    .replaces => record.replaces = value,
                }
            } else {
                if (unknown.items.len >= self.limits.max_unknown_fields_per_record) {
                    return self.fail(.too_many_unknown_fields, field.span, field.name);
                }
                try unknown.append(self.allocator, .{
                    .name = field.name,
                    .value_lines = field.value_lines,
                    .span = field.span,
                });
            }
        }
        record.unknown_fields = try unknown.toOwnedSlice(self.allocator);
        return record;
    }

    fn parsePackage(
        self: *Parser,
        field: *const deb822.Field,
        kind: DiagnosticKind,
    ) Error!Token {
        const token = try self.scalar(field);
        if (!validPackageName(token.text)) return self.fail(kind, token.span, field.name);
        return token;
    }

    fn parseVersion(
        self: *Parser,
        field: *const deb822.Field,
        kind: DiagnosticKind,
    ) Error!VersionValue {
        const token = try self.scalar(field);
        const parsed = DebianVersion.parse(token.text) catch
            return self.fail(kind, token.span, field.name);
        return .{ .value = parsed, .span = token.span };
    }

    fn parseArchitecture(self: *Parser, field: *const deb822.Field) Error!Token {
        const token = try self.scalar(field);
        if (!validArchitecture(token.text)) {
            return self.fail(.invalid_architecture, token.span, field.name);
        }
        return token;
    }

    fn parseSource(self: *Parser, field: *const deb822.Field) Error!Source {
        const token = try self.scalar(field);
        const open = std.mem.indexOfScalar(u8, token.text, '(');
        if (open == null) {
            if (!validPackageName(token.text)) {
                return self.fail(.invalid_source, token.span, field.name);
            }
            return .{ .package = token, .span = token.span };
        }

        const open_index = open.?;
        if (token.text[token.text.len - 1] != ')') {
            return self.fail(.invalid_source, token.span, field.name);
        }
        const package_text = std.mem.trim(u8, token.text[0..open_index], " \t");
        const version_text = std.mem.trim(u8, token.text[open_index + 1 .. token.text.len - 1], " \t");
        if (!validPackageName(package_text) or version_text.len == 0 or
            std.mem.indexOfScalar(u8, version_text, '(') != null)
        {
            return self.fail(.invalid_source, token.span, field.name);
        }

        const package_start = token.span.start.offset +
            (@intFromPtr(package_text.ptr) - @intFromPtr(token.text.ptr));
        const version_start = token.span.start.offset +
            (@intFromPtr(version_text.ptr) - @intFromPtr(token.text.ptr));
        const package_span = singleLineSpan(token.span.start, package_start, package_text.len);
        const version_span = singleLineSpan(token.span.start, version_start, version_text.len);
        const parsed_version = DebianVersion.parse(version_text) catch
            return self.fail(.invalid_source, version_span, field.name);
        return .{
            .package = .{ .text = package_text, .span = package_span },
            .version = .{
                .value = parsed_version,
                .span = version_span,
            },
            .span = token.span,
        };
    }

    fn parseBoolean(self: *Parser, field: *const deb822.Field) Error!bool {
        const token = try self.scalar(field);
        if (std.mem.eql(u8, token.text, "yes")) return true;
        if (std.mem.eql(u8, token.text, "no")) return false;
        return self.fail(.invalid_boolean, token.span, field.name);
    }

    fn parsePriority(self: *Parser, field: *const deb822.Field) Error!Priority {
        const token = try self.scalar(field);
        return std.meta.stringToEnum(Priority, token.text) orelse
            self.fail(.invalid_priority, token.span, field.name);
    }

    fn parseMultiArch(self: *Parser, field: *const deb822.Field) Error!MultiArch {
        const token = try self.scalar(field);
        return std.meta.stringToEnum(MultiArch, token.text) orelse
            self.fail(.invalid_multi_arch, token.span, field.name);
    }

    fn parseInstalledSize(self: *Parser, field: *const deb822.Field) Error!u64 {
        const token = try self.scalar(field);
        if (token.text.len == 0) {
            return self.fail(.invalid_installed_size, token.span, field.name);
        }
        for (token.text) |byte| {
            if (!std.ascii.isDigit(byte)) {
                return self.fail(.invalid_installed_size, token.span, field.name);
            }
        }
        return std.fmt.parseUnsigned(u64, token.text, 10) catch
            return self.fail(.invalid_installed_size, token.span, field.name);
    }

    fn parseRelation(self: *Parser, field: *const deb822.Field) Error!RelationValue {
        const source = try joinValue(self.allocator, field);
        errdefer self.allocator.free(source);
        const outcome = try relation_module.parse(self.allocator, source, self.limits.relation);
        var parsed = switch (outcome) {
            .relation => |value| value,
            .diagnostic => |diagnostic| {
                self.diagnostic = .{
                    .kind = .invalid_relation,
                    .span = mapRelationSpan(field, diagnostic.span),
                    .field_name = field.name,
                    .relation_kind = diagnostic.code,
                };
                return error.InvalidRecord;
            },
        };
        errdefer parsed.deinit(self.allocator);

        for (parsed.groups) |group| {
            for (group.alternatives) |alternative| {
                if (alternative.version) |constraint| {
                    _ = DebianVersion.parse(constraint.version.text) catch {
                        self.diagnostic = .{
                            .kind = .invalid_relation_version,
                            .span = mapRelationSpan(field, constraint.version.span),
                            .field_name = field.name,
                        };
                        return error.InvalidRecord;
                    };
                }
            }
        }

        return .{
            .source = source,
            .value = parsed,
            .field_span = field.span,
        };
    }

    fn scalar(self: *Parser, field: *const deb822.Field) Error!Token {
        if (field.value_lines.len != 1) {
            return self.fail(.scalar_must_be_single_line, field.span, field.name);
        }
        const line = field.value_lines[0];
        const text = std.mem.trim(u8, line.text, " \t");
        const leading = @intFromPtr(text.ptr) - @intFromPtr(line.text.ptr);
        return .{
            .text = text,
            .span = singleLineSpan(line.span.start, line.span.start.offset + leading, text.len),
        };
    }

    fn fail(
        self: *Parser,
        kind: DiagnosticKind,
        span: deb822.Span,
        field_name: ?[]const u8,
    ) error{InvalidRecord} {
        self.diagnostic = .{
            .kind = kind,
            .span = span,
            .field_name = field_name,
        };
        return error.InvalidRecord;
    }
};

fn isIdentityField(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "Package") or
        std.ascii.eqlIgnoreCase(name, "Version") or
        std.ascii.eqlIgnoreCase(name, "Architecture");
}

const RelationMember = enum {
    built_using,
    depends,
    pre_depends,
    recommends,
    suggests,
    enhances,
    provides,
    conflicts,
    breaks,
    replaces,
};

fn relationFieldMember(name: []const u8) ?RelationMember {
    const fields = .{
        .{ "Built-Using", RelationMember.built_using },
        .{ "Depends", RelationMember.depends },
        .{ "Pre-Depends", RelationMember.pre_depends },
        .{ "Recommends", RelationMember.recommends },
        .{ "Suggests", RelationMember.suggests },
        .{ "Enhances", RelationMember.enhances },
        .{ "Provides", RelationMember.provides },
        .{ "Conflicts", RelationMember.conflicts },
        .{ "Breaks", RelationMember.breaks },
        .{ "Replaces", RelationMember.replaces },
    };
    inline for (fields) |entry| {
        if (std.ascii.eqlIgnoreCase(name, entry[0])) return entry[1];
    }
    return null;
}

fn validPackageName(text: []const u8) bool {
    if (text.len < 2 or !lowerAlphaNumeric(text[0])) return false;
    for (text[1..]) |byte| {
        if (!lowerAlphaNumeric(byte) and byte != '+' and byte != '-' and byte != '.') return false;
    }
    return true;
}

fn validArchitecture(text: []const u8) bool {
    if (text.len == 0 or !lowerAlphaNumeric(text[0])) return false;
    for (text[1..]) |byte| {
        if (!lowerAlphaNumeric(byte) and byte != '-') return false;
    }
    return true;
}

fn lowerAlphaNumeric(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or std.ascii.isDigit(byte);
}

fn joinValue(allocator: std.mem.Allocator, field: *const deb822.Field) ![]u8 {
    const source = try allocator.alloc(u8, field.valueByteCount());
    var index: usize = 0;
    for (field.value_lines, 0..) |line, line_index| {
        if (line_index != 0) {
            source[index] = '\n';
            index += 1;
        }
        @memcpy(source[index .. index + line.text.len], line.text);
        index += line.text.len;
    }
    return source;
}

fn mapRelationSpan(field: *const deb822.Field, span: relation_module.Span) deb822.Span {
    return .{
        .start = mapRelationPosition(field, span.start),
        .end = mapRelationPosition(field, span.end),
    };
}

fn mapRelationPosition(field: *const deb822.Field, target: usize) deb822.Position {
    var logical_offset: usize = 0;
    for (field.value_lines, 0..) |line, index| {
        const line_end = logical_offset + line.text.len;
        if (target <= line_end) {
            const delta = target - logical_offset;
            return .{
                .offset = line.span.start.offset + delta,
                .line = line.span.start.line,
                .column = line.span.start.column + delta,
            };
        }
        logical_offset = line_end;
        if (index + 1 < field.value_lines.len) {
            if (target == logical_offset + 1) return field.value_lines[index + 1].span.start;
            logical_offset += 1;
        }
    }
    return field.span.end;
}

fn singleLineSpan(start: deb822.Position, absolute_start: usize, length: usize) deb822.Span {
    const delta = absolute_start - start.offset;
    const adjusted = deb822.Position{
        .offset = absolute_start,
        .line = start.line,
        .column = start.column + delta,
    };
    return .{
        .start = adjusted,
        .end = .{
            .offset = absolute_start + length,
            .line = start.line,
            .column = adjusted.column + length,
        },
    };
}

fn expectDocument(input: []const u8) !BorrowedDocument {
    const outcome = try parseBorrowed(std.testing.allocator, input, .{});
    return switch (outcome) {
        .document => |document| document,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
}

fn expectDiagnostic(input: []const u8, kind: DiagnosticKind) !Diagnostic {
    const outcome = try parseBorrowed(std.testing.allocator, input, .{});
    return switch (outcome) {
        .diagnostic => |diagnostic| blk: {
            try std.testing.expectEqual(kind, diagnostic.kind);
            break :blk diagnostic;
        },
        .document => |document_value| {
            var document = document_value;
            document.deinit();
            return error.ExpectedDiagnostic;
        },
    };
}

test "parses typed binary control fields and preserves unknown fields" {
    const input =
        "Package: libfoo1\n" ++
        "Version: 0002:1.0~rc1-03\n" ++
        "Architecture: amd64\n" ++
        "Source: foo (0002:1.0~rc1-03)\n" ++
        "Essential: yes\n" ++
        "Protected: no\n" ++
        "Important: yes\n" ++
        "Priority: optional\n" ++
        "Multi-Arch: same\n" ++
        "Installed-Size: 001024\n" ++
        "Built-Using: source-a (= 1.0-1)\n" ++
        "Depends: libc6 (>= 2.39), zlib1g\n" ++
        "Pre-Depends: init-system-helpers (>= 1.0)\n" ++
        "Recommends: helper\n" ++
        "Suggests: docs\n" ++
        "Enhances: shell\n" ++
        "Provides: foo-abi (= 1.0)\n" ++
        "Conflicts: old-foo\n" ++
        "Breaks: consumer (<< 2.0)\n" ++
        "Replaces: old-foo\n" ++
        "X-Future: retained\n";
    var document = try expectDocument(input);
    defer document.deinit();

    const record = document.records[0];
    try std.testing.expectEqualStrings("libfoo1", record.package.text);
    try std.testing.expectEqualStrings("0002:1.0~rc1-03", record.version.value.original);
    try std.testing.expectEqualStrings("0002", record.version.value.epoch.?);
    try std.testing.expectEqualStrings("amd64", record.architecture.text);
    try std.testing.expectEqualStrings("foo", record.source.?.package.text);
    try std.testing.expectEqualStrings("0002:1.0~rc1-03", record.source.?.version.?.value.original);
    try std.testing.expectEqual(true, record.essential.?);
    try std.testing.expectEqual(false, record.protected.?);
    try std.testing.expectEqual(true, record.important.?);
    try std.testing.expectEqual(Priority.optional, record.priority.?);
    try std.testing.expectEqual(MultiArch.same, record.multi_arch.?);
    try std.testing.expectEqual(@as(u64, 1024), record.installed_size.?);
    try std.testing.expectEqualStrings("libc6", record.depends.?.value.groups[0].alternatives[0].package.name.text);
    try std.testing.expectEqualStrings("2.39", record.depends.?.value.groups[0].alternatives[0].version.?.version.text);
    try std.testing.expect(record.built_using != null);
    try std.testing.expect(record.pre_depends != null);
    try std.testing.expect(record.recommends != null);
    try std.testing.expect(record.suggests != null);
    try std.testing.expect(record.enhances != null);
    try std.testing.expect(record.provides != null);
    try std.testing.expect(record.conflicts != null);
    try std.testing.expect(record.breaks != null);
    try std.testing.expect(record.replaces != null);
    try std.testing.expectEqual(@as(usize, 1), record.unknown_fields.len);
    try std.testing.expectEqualStrings("X-Future", record.unknown_fields[0].name);
    try std.testing.expectEqualStrings("retained", record.unknown_fields[0].value_lines[0].text);
    try std.testing.expectEqual(@as(usize, 1), record.package.span.start.line);
}

test "validates all required identity fields" {
    _ = try expectDiagnostic("Version: 1\nArchitecture: all\n", .missing_package);
    _ = try expectDiagnostic("Package: aa\nArchitecture: all\n", .missing_version);
    _ = try expectDiagnostic("Package: aa\nVersion: 1\n", .missing_architecture);
    _ = try expectDiagnostic("Package: A\nVersion: 1\nArchitecture: all\n", .invalid_package);
    _ = try expectDiagnostic("Package: aa\nVersion: bad\nArchitecture: all\n", .invalid_version);
    _ = try expectDiagnostic("Package: aa\nVersion: 1\nArchitecture: AMD64\n", .invalid_architecture);
}

test "rejects malformed booleans enums numbers and source values" {
    const prefix = "Package: aa\nVersion: 1\nArchitecture: all\n";
    _ = try expectDiagnostic(prefix ++ "Essential: true\n", .invalid_boolean);
    _ = try expectDiagnostic(prefix ++ "Protected: Yes\n", .invalid_boolean);
    _ = try expectDiagnostic(prefix ++ "Important: 1\n", .invalid_boolean);
    _ = try expectDiagnostic(prefix ++ "Priority: high\n", .invalid_priority);
    _ = try expectDiagnostic(prefix ++ "Multi-Arch: maybe\n", .invalid_multi_arch);
    _ = try expectDiagnostic(prefix ++ "Installed-Size: -1\n", .invalid_installed_size);
    _ = try expectDiagnostic(prefix ++ "Installed-Size: 18446744073709551616\n", .invalid_installed_size);
    _ = try expectDiagnostic(prefix ++ "Source: Bad\n", .invalid_source);
    _ = try expectDiagnostic(prefix ++ "Source: source (bad)\n", .invalid_source);
    _ = try expectDiagnostic(prefix ++ "Priority: optional\n continued\n", .scalar_must_be_single_line);
}

test "reports relation syntax and version diagnostics at source spans" {
    const prefix = "Package: aa\nVersion: 1\nArchitecture: all\n";
    const syntax = try expectDiagnostic(prefix ++ "Depends: foo |\n", .invalid_relation);
    try std.testing.expectEqual(relation_module.DiagnosticCode.trailing_separator, syntax.relation_kind.?);
    try std.testing.expectEqual(@as(usize, 4), syntax.span.start.line);

    const bad_version = try expectDiagnostic(prefix ++ "Depends: foo (>= bad)\n", .invalid_relation_version);
    try std.testing.expectEqual(@as(usize, 4), bad_version.span.start.line);
    try std.testing.expectEqualStrings("Depends", bad_version.field_name.?);
}

test "parses folded relations and multiple records" {
    const input =
        "Package: aa\nVersion: 01.0-00\nArchitecture: all\n" ++
        "Depends: foo (>= 1),\n bar | baz\n\n" ++
        "Package: bb\nVersion: 2\nArchitecture: arm64\n";
    var document = try expectDocument(input);
    defer document.deinit();
    try std.testing.expectEqual(@as(usize, 2), document.records.len);
    try std.testing.expectEqualStrings("01.0-00", document.records[0].version.value.original);
    try std.testing.expectEqual(@as(usize, 2), document.records[0].depends.?.value.groups.len);
}

test "enforces record unknown-field and underlying value bounds" {
    const input =
        "Package: aa\nVersion: 1\nArchitecture: all\nX-One: 1\nX-Two: 2\n";
    var outcome = try parseBorrowed(std.testing.allocator, input, .{
        .limits = .{ .max_unknown_fields_per_record = 1 },
    });
    try std.testing.expectEqual(DiagnosticKind.too_many_unknown_fields, outcome.diagnostic.kind);

    outcome = try parseBorrowed(std.testing.allocator, "Package: aa\nVersion: 1\nArchitecture: all\n\n" ++
        "Package: bb\nVersion: 1\nArchitecture: all\n", .{
        .limits = .{ .max_records = 1 },
    });
    try std.testing.expectEqual(DiagnosticKind.too_many_records, outcome.diagnostic.kind);

    outcome = try parseBorrowed(std.testing.allocator, input, .{
        .limits = .{ .deb822 = .{ .max_field_bytes = 8 } },
    });
    try std.testing.expectEqual(DiagnosticKind.deb822_syntax, outcome.diagnostic.kind);
}
