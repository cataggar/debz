const std = @import("std");

pub const Span = struct {
    start: usize,
    end: usize,

    pub fn slice(self: Span, source: []const u8) []const u8 {
        return source[self.start..self.end];
    }
};

pub const Token = struct {
    text: []const u8,
    span: Span,
};

pub const VersionOperator = enum {
    less_than,
    less_than_or_equal,
    equal,
    greater_than_or_equal,
    greater_than,
};

pub const VersionConstraint = struct {
    operator: VersionOperator,
    version: Token,
    span: Span,
};

/// Reserved extension point for architecture and build-profile restrictions.
/// The first parser intentionally accepts neither syntax yet.
pub const RestrictionSet = struct {};

pub const PackageReference = struct {
    name: Token,
    architecture_qualifier: ?Token = null,
};

pub const Alternative = struct {
    package: PackageReference,
    version: ?VersionConstraint = null,
    restrictions: RestrictionSet = .{},
    span: Span,
};

pub const DependencyGroup = struct {
    alternatives: []Alternative,
    span: Span,
};

/// Owns the AST arrays, but borrows all token text from `source`.
pub const Relation = struct {
    source: []const u8,
    groups: []DependencyGroup,
    span: Span,

    pub fn deinit(self: *Relation, allocator: std.mem.Allocator) void {
        for (self.groups) |group| allocator.free(group.alternatives);
        allocator.free(self.groups);
        self.* = undefined;
    }
};

pub const Limits = struct {
    max_input_bytes: usize = 64 * 1024,
    max_groups: usize = 1024,
    max_alternatives_per_group: usize = 128,
    max_total_alternatives: usize = 4096,
    max_package_name_bytes: usize = 255,
    max_architecture_qualifier_bytes: usize = 64,
    max_version_bytes: usize = 4096,
};

pub const DiagnosticCode = enum {
    empty_input,
    input_too_long,
    expected_package,
    invalid_package_character,
    package_name_too_long,
    expected_architecture_qualifier,
    invalid_architecture_qualifier,
    architecture_qualifier_too_long,
    expected_version_operator,
    invalid_version_operator,
    expected_version,
    version_too_long,
    expected_closing_parenthesis,
    expected_separator,
    trailing_separator,
    unsupported_restriction,
    too_many_groups,
    too_many_alternatives,
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    span: Span,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .empty_input => "expected at least one package dependency",
            .input_too_long => "relation exceeds the configured input size limit",
            .expected_package => "expected a package name",
            .invalid_package_character => "package names must start with a lowercase letter or digit and contain only lowercase letters, digits, '+', '-', or '.'",
            .package_name_too_long => "package name exceeds the configured length limit",
            .expected_architecture_qualifier => "expected an architecture qualifier after ':'",
            .invalid_architecture_qualifier => "architecture qualifiers must contain only lowercase letters, digits, or '-'",
            .architecture_qualifier_too_long => "architecture qualifier exceeds the configured length limit",
            .expected_version_operator => "expected a version predicate after '('",
            .invalid_version_operator => "version predicate must be one of '<<', '<=', '=', '>=', or '>>'",
            .expected_version => "expected version text after the version predicate",
            .version_too_long => "version text exceeds the configured length limit",
            .expected_closing_parenthesis => "expected ')' to close the version predicate",
            .expected_separator => "expected ',', '|', or the end of the relation",
            .trailing_separator => "expected another package after the separator",
            .unsupported_restriction => "architecture and build-profile restrictions are not supported yet",
            .too_many_groups => "relation exceeds the configured dependency-group limit",
            .too_many_alternatives => "relation exceeds a configured alternative-count limit",
        };
    }
};

pub const ParseResult = union(enum) {
    relation: Relation,
    diagnostic: Diagnostic,
};

pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
    limits: Limits,
) std.mem.Allocator.Error!ParseResult {
    var parser: Parser = .{
        .allocator = allocator,
        .source = source,
        .limits = limits,
    };
    const relation = parser.parseRelation() catch |err| switch (err) {
        error.InvalidRelation => return .{ .diagnostic = parser.diagnostic.? },
        error.OutOfMemory => return error.OutOfMemory,
    };
    return .{ .relation = relation };
}

const Parser = struct {
    allocator: std.mem.Allocator,
    source: []const u8,
    limits: Limits,
    index: usize = 0,
    total_alternatives: usize = 0,
    diagnostic: ?Diagnostic = null,

    const Error = std.mem.Allocator.Error || error{InvalidRelation};

    fn parseRelation(self: *Parser) Error!Relation {
        if (self.source.len > self.limits.max_input_bytes) {
            return self.fail(.input_too_long, .{ .start = 0, .end = self.source.len });
        }

        self.skipWhitespace();
        if (self.atEnd()) return self.fail(.empty_input, self.pointSpan());
        const relation_start = self.index;

        var groups: std.ArrayList(DependencyGroup) = .empty;
        errdefer {
            for (groups.items) |group| self.allocator.free(group.alternatives);
            groups.deinit(self.allocator);
        }

        while (true) {
            if (groups.items.len >= self.limits.max_groups) {
                return self.fail(.too_many_groups, self.pointSpan());
            }

            const group_start = self.index;
            var alternatives: std.ArrayList(Alternative) = .empty;
            errdefer alternatives.deinit(self.allocator);

            while (true) {
                if (alternatives.items.len >= self.limits.max_alternatives_per_group or
                    self.total_alternatives >= self.limits.max_total_alternatives)
                {
                    return self.fail(.too_many_alternatives, self.pointSpan());
                }

                const alternative = try self.parseAlternative();
                try alternatives.append(self.allocator, alternative);
                self.total_alternatives += 1;
                self.skipWhitespace();

                if (!self.consume('|')) break;
                const separator = self.index - 1;
                self.skipWhitespace();
                if (self.atEnd() or self.peek() == ',' or self.peek() == '|') {
                    return self.fail(.trailing_separator, .{ .start = separator, .end = separator + 1 });
                }
            }

            const group_end = alternatives.items[alternatives.items.len - 1].span.end;
            try groups.ensureUnusedCapacity(self.allocator, 1);
            const owned_alternatives = try alternatives.toOwnedSlice(self.allocator);
            groups.appendAssumeCapacity(.{
                .alternatives = owned_alternatives,
                .span = .{ .start = group_start, .end = group_end },
            });

            self.skipWhitespace();
            if (self.atEnd()) {
                return .{
                    .source = self.source,
                    .groups = try groups.toOwnedSlice(self.allocator),
                    .span = .{ .start = relation_start, .end = group_end },
                };
            }

            if (self.consume(',')) {
                const separator = self.index - 1;
                self.skipWhitespace();
                if (self.atEnd() or self.peek() == ',' or self.peek() == '|') {
                    return self.fail(.trailing_separator, .{ .start = separator, .end = separator + 1 });
                }
                continue;
            }

            if (self.peek() == '[' or self.peek() == '<') {
                return self.fail(.unsupported_restriction, self.pointSpan());
            }
            return self.fail(.expected_separator, self.pointSpan());
        }
    }

    fn parseAlternative(self: *Parser) Error!Alternative {
        const start = self.index;
        const name = try self.parsePackageName();
        var package: PackageReference = .{ .name = name };

        if (self.consume(':')) {
            package.architecture_qualifier = try self.parseArchitectureQualifier();
        }

        self.skipWhitespace();
        var version: ?VersionConstraint = null;
        if (self.consume('(')) version = try self.parseVersionConstraint(self.index - 1);

        const end = if (version) |constraint|
            constraint.span.end
        else if (package.architecture_qualifier) |qualifier|
            qualifier.span.end
        else
            name.span.end;

        return .{
            .package = package,
            .version = version,
            .span = .{ .start = start, .end = end },
        };
    }

    fn parsePackageName(self: *Parser) Error!Token {
        if (self.atEnd() or !isLowerAlphaNumeric(self.peek())) {
            if (!self.atEnd() and (isPackageCharacter(self.peek()) or isAsciiUpper(self.peek()))) {
                return self.fail(.invalid_package_character, self.pointSpan());
            }
            return self.fail(.expected_package, self.pointSpan());
        }

        const start = self.index;
        self.index += 1;
        while (!self.atEnd() and isPackageCharacter(self.peek())) self.index += 1;
        if (self.index - start > self.limits.max_package_name_bytes) {
            return self.fail(.package_name_too_long, .{ .start = start, .end = self.index });
        }
        if (!self.atEnd() and !isPackageDelimiter(self.peek())) {
            return self.fail(.invalid_package_character, self.pointSpan());
        }
        return self.token(start, self.index);
    }

    fn parseArchitectureQualifier(self: *Parser) Error!Token {
        const start = self.index;
        if (self.atEnd() or !isArchitectureCharacter(self.peek())) {
            if (!self.atEnd() and isAsciiUpper(self.peek())) {
                return self.fail(.invalid_architecture_qualifier, self.pointSpan());
            }
            return self.fail(.expected_architecture_qualifier, self.pointSpan());
        }
        while (!self.atEnd() and isArchitectureCharacter(self.peek())) self.index += 1;
        if (self.index - start > self.limits.max_architecture_qualifier_bytes) {
            return self.fail(.architecture_qualifier_too_long, .{ .start = start, .end = self.index });
        }
        if (!self.atEnd() and !isQualifierDelimiter(self.peek())) {
            return self.fail(.invalid_architecture_qualifier, self.pointSpan());
        }
        return self.token(start, self.index);
    }

    fn parseVersionConstraint(self: *Parser, start: usize) Error!VersionConstraint {
        self.skipWhitespace();
        if (self.atEnd()) return self.fail(.expected_version_operator, self.pointSpan());

        const operator = try self.parseVersionOperator();
        self.skipWhitespace();
        const version_start = self.index;

        while (!self.atEnd() and self.peek() != ')') self.index += 1;
        if (self.atEnd()) {
            return self.fail(.expected_closing_parenthesis, .{ .start = start, .end = self.index });
        }

        var version_end = self.index;
        while (version_end > version_start and isWhitespace(self.source[version_end - 1])) {
            version_end -= 1;
        }
        if (version_end == version_start) {
            return self.fail(.expected_version, .{ .start = version_start, .end = self.index });
        }
        if (version_end - version_start > self.limits.max_version_bytes) {
            return self.fail(.version_too_long, .{ .start = version_start, .end = version_end });
        }

        self.index += 1;
        return .{
            .operator = operator,
            .version = self.token(version_start, version_end),
            .span = .{ .start = start, .end = self.index },
        };
    }

    fn parseVersionOperator(self: *Parser) Error!VersionOperator {
        if (self.remainingStartsWith("<<")) {
            self.index += 2;
            return .less_than;
        }
        if (self.remainingStartsWith("<=")) {
            self.index += 2;
            return .less_than_or_equal;
        }
        if (self.consume('=')) return .equal;
        if (self.remainingStartsWith(">=")) {
            self.index += 2;
            return .greater_than_or_equal;
        }
        if (self.remainingStartsWith(">>")) {
            self.index += 2;
            return .greater_than;
        }

        if (self.peek() == '<' or self.peek() == '>') {
            const start = self.index;
            self.index += 1;
            if (!self.atEnd() and (self.peek() == '<' or self.peek() == '>' or self.peek() == '=')) {
                self.index += 1;
            }
            return self.fail(.invalid_version_operator, .{ .start = start, .end = self.index });
        }
        return self.fail(.expected_version_operator, self.pointSpan());
    }

    fn fail(self: *Parser, code: DiagnosticCode, span: Span) error{InvalidRelation} {
        self.diagnostic = .{ .code = code, .span = span };
        return error.InvalidRelation;
    }

    fn token(self: *Parser, start: usize, end: usize) Token {
        return .{
            .text = self.source[start..end],
            .span = .{ .start = start, .end = end },
        };
    }

    fn skipWhitespace(self: *Parser) void {
        while (!self.atEnd() and isWhitespace(self.peek())) self.index += 1;
    }

    fn atEnd(self: *const Parser) bool {
        return self.index == self.source.len;
    }

    fn peek(self: *const Parser) u8 {
        return self.source[self.index];
    }

    fn consume(self: *Parser, byte: u8) bool {
        if (self.atEnd() or self.peek() != byte) return false;
        self.index += 1;
        return true;
    }

    fn remainingStartsWith(self: *const Parser, text: []const u8) bool {
        return std.mem.startsWith(u8, self.source[self.index..], text);
    }

    fn pointSpan(self: *const Parser) Span {
        return .{
            .start = self.index,
            .end = @min(self.index + 1, self.source.len),
        };
    }
};

fn isWhitespace(byte: u8) bool {
    return byte == ' ' or byte == '\t' or byte == '\r' or byte == '\n';
}

fn isLowerAlphaNumeric(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or (byte >= '0' and byte <= '9');
}

fn isAsciiUpper(byte: u8) bool {
    return byte >= 'A' and byte <= 'Z';
}

fn isPackageCharacter(byte: u8) bool {
    return isLowerAlphaNumeric(byte) or byte == '+' or byte == '-' or byte == '.';
}

fn isArchitectureCharacter(byte: u8) bool {
    return isLowerAlphaNumeric(byte) or byte == '-';
}

fn isPackageDelimiter(byte: u8) bool {
    return isWhitespace(byte) or byte == ':' or byte == '(' or byte == '|' or byte == ',' or
        byte == '[' or byte == '<';
}

fn isQualifierDelimiter(byte: u8) bool {
    return isWhitespace(byte) or byte == '(' or byte == '|' or byte == ',' or byte == '[' or
        byte == '<';
}

fn expectRelation(source: []const u8) !Relation {
    const result = try parse(std.testing.allocator, source, .{});
    return switch (result) {
        .relation => |relation| relation,
        .diagnostic => |diagnostic| {
            std.debug.print("unexpected diagnostic {s} at {d}..{d}\n", .{
                diagnostic.message(),
                diagnostic.span.start,
                diagnostic.span.end,
            });
            return error.UnexpectedDiagnostic;
        },
    };
}

fn expectDiagnostic(source: []const u8, code: DiagnosticCode) !Diagnostic {
    const result = try parse(std.testing.allocator, source, .{});
    return switch (result) {
        .diagnostic => |diagnostic| {
            try std.testing.expectEqual(code, diagnostic.code);
            return diagnostic;
        },
        .relation => |relation_value| {
            var relation = relation_value;
            relation.deinit(std.testing.allocator);
            return error.ExpectedDiagnostic;
        },
    };
}

test "parses groups alternatives qualifiers versions whitespace and spans" {
    const source = " \tfoo:any (>= 1:2.3~rc1-4) | bar, baz-qux:native (<< 2.0) \n";
    var relation = try expectRelation(source);
    defer relation.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), relation.groups.len);
    try std.testing.expectEqualStrings("foo:any (>= 1:2.3~rc1-4) | bar, baz-qux:native (<< 2.0)", relation.span.slice(source));

    const first_group = relation.groups[0];
    try std.testing.expectEqual(@as(usize, 2), first_group.alternatives.len);
    try std.testing.expectEqualStrings("foo", first_group.alternatives[0].package.name.text);
    try std.testing.expectEqualStrings("any", first_group.alternatives[0].package.architecture_qualifier.?.text);
    try std.testing.expectEqual(VersionOperator.greater_than_or_equal, first_group.alternatives[0].version.?.operator);
    try std.testing.expectEqualStrings("1:2.3~rc1-4", first_group.alternatives[0].version.?.version.text);
    try std.testing.expectEqualStrings("foo:any (>= 1:2.3~rc1-4)", first_group.alternatives[0].span.slice(source));
    try std.testing.expectEqualStrings("bar", first_group.alternatives[1].package.name.text);

    const second = relation.groups[1].alternatives[0];
    try std.testing.expectEqualStrings("baz-qux", second.package.name.text);
    try std.testing.expectEqualStrings("native", second.package.architecture_qualifier.?.text);
    try std.testing.expectEqual(VersionOperator.less_than, second.version.?.operator);
    try std.testing.expectEqualStrings("2.0", second.version.?.version.text);
}

test "parses every version predicate and preserves opaque version text" {
    const source = "a (<< 1), b (<= 2+git), c (= 1 2), d (>= 4), e (>> 5)";
    var relation = try expectRelation(source);
    defer relation.deinit(std.testing.allocator);

    const expected = [_]VersionOperator{
        .less_than,
        .less_than_or_equal,
        .equal,
        .greater_than_or_equal,
        .greater_than,
    };
    for (expected, 0..) |operator, index| {
        try std.testing.expectEqual(operator, relation.groups[index].alternatives[0].version.?.operator);
    }
    try std.testing.expectEqualStrings("1 2", relation.groups[2].alternatives[0].version.?.version.text);
}

test "accepts ASCII whitespace around relation punctuation" {
    var relation = try expectRelation("a\t|\n b \r,\t c ( =\t7 \n)");
    defer relation.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), relation.groups.len);
    try std.testing.expectEqual(@as(usize, 2), relation.groups[0].alternatives.len);
    try std.testing.expectEqualStrings("7", relation.groups[1].alternatives[0].version.?.version.text);
}

test "reports actionable malformed input diagnostics with source spans" {
    const cases = [_]struct {
        source: []const u8,
        code: DiagnosticCode,
        selected: []const u8,
    }{
        .{ .source = "", .code = .empty_input, .selected = "" },
        .{ .source = "Foo", .code = .invalid_package_character, .selected = "F" },
        .{ .source = "foo_bar", .code = .invalid_package_character, .selected = "_" },
        .{ .source = "foo:", .code = .expected_architecture_qualifier, .selected = "" },
        .{ .source = "foo:AMD64", .code = .invalid_architecture_qualifier, .selected = "A" },
        .{ .source = "foo:amd64_x", .code = .invalid_architecture_qualifier, .selected = "_" },
        .{ .source = "foo (", .code = .expected_version_operator, .selected = "" },
        .{ .source = "foo (< 1)", .code = .invalid_version_operator, .selected = "<" },
        .{ .source = "foo (>= )", .code = .expected_version, .selected = "" },
        .{ .source = "foo (>= 1", .code = .expected_closing_parenthesis, .selected = "(>= 1" },
        .{ .source = "foo |", .code = .trailing_separator, .selected = "|" },
        .{ .source = "foo bar", .code = .expected_separator, .selected = "b" },
        .{ .source = "foo [amd64]", .code = .unsupported_restriction, .selected = "[" },
    };

    for (cases) |case| {
        const diagnostic = try expectDiagnostic(case.source, case.code);
        try std.testing.expectEqualStrings(case.selected, diagnostic.span.slice(case.source));
        try std.testing.expect(diagnostic.message().len != 0);
    }
}

test "enforces configurable input and count limits" {
    var result = try parse(std.testing.allocator, "abcd", .{ .max_input_bytes = 3 });
    try std.testing.expectEqual(DiagnosticCode.input_too_long, result.diagnostic.code);

    result = try parse(std.testing.allocator, "abcd", .{ .max_package_name_bytes = 3 });
    try std.testing.expectEqual(DiagnosticCode.package_name_too_long, result.diagnostic.code);

    result = try parse(std.testing.allocator, "a:amd64", .{ .max_architecture_qualifier_bytes = 4 });
    try std.testing.expectEqual(DiagnosticCode.architecture_qualifier_too_long, result.diagnostic.code);

    result = try parse(std.testing.allocator, "a (= 1234)", .{ .max_version_bytes = 3 });
    try std.testing.expectEqual(DiagnosticCode.version_too_long, result.diagnostic.code);

    result = try parse(std.testing.allocator, "a,b", .{ .max_groups = 1 });
    try std.testing.expectEqual(DiagnosticCode.too_many_groups, result.diagnostic.code);

    result = try parse(std.testing.allocator, "a|b", .{ .max_alternatives_per_group = 1 });
    try std.testing.expectEqual(DiagnosticCode.too_many_alternatives, result.diagnostic.code);

    result = try parse(std.testing.allocator, "a,b", .{ .max_total_alternatives = 1 });
    try std.testing.expectEqual(DiagnosticCode.too_many_alternatives, result.diagnostic.code);
}

test "AST borrows exact token text from caller input" {
    const source = "pkg:arm64 (= 01.002-0)";
    var relation = try expectRelation(source);
    defer relation.deinit(std.testing.allocator);

    const alternative = relation.groups[0].alternatives[0];
    try std.testing.expectEqualStrings(alternative.package.name.span.slice(source), alternative.package.name.text);
    try std.testing.expectEqualStrings("01.002-0", alternative.version.?.version.text);
    try std.testing.expectEqualStrings("01.002-0", alternative.version.?.version.span.slice(source));
}
