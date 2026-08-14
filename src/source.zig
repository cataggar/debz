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

pub const SourceType = enum {
    binary,
    source,

    pub fn spelling(self: SourceType) []const u8 {
        return switch (self) {
            .binary => "deb",
            .source => "deb-src",
        };
    }
};

pub const RepositoryId = struct {
    bytes: [64]u8,

    pub fn slice(self: *const RepositoryId) []const u8 {
        return &self.bytes;
    }
};

pub const Repository = struct {
    id: RepositoryId,
    types: []SourceType,
    enabled: bool,
    uris: []LocatedString,
    suites: []LocatedString,
    components: []LocatedString,
    architectures: []LocatedString,
    signed_by: []LocatedString,
    trusted: ?bool,
    span: Span,
};

/// Owns repository arrays, while all strings borrow `source`.
pub const SourceList = struct {
    source: []const u8,
    repositories: []Repository,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *SourceList) void {
        for (self.repositories) |repository| freeRepository(self.allocator, repository);
        self.allocator.free(self.repositories);
        self.* = undefined;
    }
};

pub const Format = enum {
    deb822,
    legacy,
};

pub const Limits = struct {
    max_input_bytes: usize = 1024 * 1024,
    max_sources: usize = 1024,
    max_fields_per_stanza: usize = 32,
    max_field_bytes: usize = 64 * 1024,
    max_values_per_field: usize = 256,
    max_value_bytes: usize = 4096,
    max_legacy_options: usize = 32,
};

pub const DiagnosticCode = enum {
    input_too_long,
    too_many_sources,
    too_many_fields,
    field_too_long,
    malformed_deb822,
    duplicate_field,
    unknown_field,
    missing_field,
    empty_field,
    too_many_values,
    value_too_long,
    invalid_type,
    invalid_boolean,
    invalid_uri,
    invalid_suite,
    invalid_component,
    invalid_architecture,
    invalid_signed_by,
    components_for_exact_suite,
    missing_components,
    malformed_legacy_entry,
    malformed_option_block,
    too_many_options,
    malformed_option,
    duplicate_option,
    unsupported_option,
    ambiguous_enabled_state,
    trailing_content,
    duplicate_repository,
    repository_id_collision,
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    span: Span,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .input_too_long => "repository source input exceeds the configured byte limit",
            .too_many_sources => "repository source input exceeds the configured source limit",
            .too_many_fields => "DEB822 stanza exceeds the configured field limit",
            .field_too_long => "DEB822 field exceeds the configured byte limit",
            .malformed_deb822 => "malformed DEB822 repository source stanza",
            .duplicate_field => "repository source fields must not be repeated",
            .unknown_field => "unsupported repository source field",
            .missing_field => "repository source stanza is missing a required field",
            .empty_field => "repository source field must contain at least one value",
            .too_many_values => "repository source field exceeds the configured value limit",
            .value_too_long => "repository source value exceeds the configured byte limit",
            .invalid_type => "Types must contain only 'deb' or 'deb-src'",
            .invalid_boolean => "boolean values must be exactly 'yes' or 'no'",
            .invalid_uri => "URI must be a non-empty token without control characters",
            .invalid_suite => "suite must be a non-empty token without control characters",
            .invalid_component => "component must use Debian component token characters",
            .invalid_architecture => "architecture must contain only letters, digits, or '-'",
            .invalid_signed_by => "Signed-By values must be absolute keyring paths",
            .components_for_exact_suite => "an exact-path suite ending in '/' cannot have components",
            .missing_components => "a non-exact suite requires at least one component",
            .malformed_legacy_entry => "expected a legacy 'deb' or 'deb-src' entry",
            .malformed_option_block => "legacy option block must be closed with ']'",
            .too_many_options => "legacy entry exceeds the configured option limit",
            .malformed_option => "legacy options must have the form name=value",
            .duplicate_option => "legacy options must not be repeated",
            .unsupported_option => "unsupported legacy repository option",
            .ambiguous_enabled_state => "comment-disabled entry conflicts with enabled=yes",
            .trailing_content => "unexpected content after repository entry",
            .duplicate_repository => "two repository declarations normalize to the same ID",
            .repository_id_collision => "different repository declarations produced the same ID",
        };
    }
};

pub const ParseResult = union(enum) {
    sources: SourceList,
    diagnostic: Diagnostic,
};

pub fn parse(
    allocator: std.mem.Allocator,
    source: []const u8,
    format: Format,
    limits: Limits,
) std.mem.Allocator.Error!ParseResult {
    if (source.len > limits.max_input_bytes) {
        return .{ .diagnostic = .{
            .code = .input_too_long,
            .span = .{ .start = limits.max_input_bytes, .end = source.len },
        } };
    }
    return switch (format) {
        .deb822 => parseDeb822(allocator, source, limits),
        .legacy => parseLegacy(allocator, source, limits),
    };
}

pub fn parseDeb822(
    allocator: std.mem.Allocator,
    source: []const u8,
    limits: Limits,
) std.mem.Allocator.Error!ParseResult {
    const outcome = try deb822.parseBorrowed(allocator, source, .{
        .limits = .{
            .max_total_bytes = limits.max_input_bytes,
            .max_paragraphs = limits.max_sources,
            .max_fields_per_paragraph = limits.max_fields_per_stanza,
            .max_field_bytes = limits.max_field_bytes,
        },
        .allow_comments = true,
    });
    var document = switch (outcome) {
        .document => |value| value,
        .failure => |failure| return .{ .diagnostic = .{
            .code = switch (failure.kind) {
                .total_bytes_limit => .input_too_long,
                .paragraph_limit => .too_many_sources,
                .fields_limit => .too_many_fields,
                .field_size_limit => .field_too_long,
                .duplicate_field => .duplicate_field,
                else => .malformed_deb822,
            },
            .span = pointSpan(failure.position.offset, source.len),
        } },
    };
    defer document.deinit();

    var repositories: std.ArrayList(Repository) = .empty;
    var complete = false;
    defer repositories.deinit(allocator);
    defer if (!complete) freeRepositories(allocator, repositories.items);

    for (document.paragraphs) |paragraph| {
        const parsed = try repositoryFromParagraph(allocator, source, paragraph, limits);
        switch (parsed) {
            .repository => |repository| {
                if (collisionDiagnostic(repositories.items, repository)) |diagnostic| {
                    freeRepository(allocator, repository);
                    return .{ .diagnostic = diagnostic };
                }
                try repositories.append(allocator, repository);
            },
            .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
        }
    }

    const result = try finish(allocator, source, &repositories);
    complete = true;
    return result;
}

pub fn parseLegacy(
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
    var repositories: std.ArrayList(Repository) = .empty;
    var complete = false;
    defer repositories.deinit(allocator);
    defer if (!complete) freeRepositories(allocator, repositories.items);

    var line_start: usize = 0;
    while (line_start < source.len) {
        const newline = std.mem.indexOfScalarPos(u8, source, line_start, '\n') orelse source.len;
        var line_end = newline;
        if (line_end > line_start and source[line_end - 1] == '\r') line_end -= 1;
        const line = source[line_start..line_end];
        const parsed = try parseLegacyLine(allocator, source, line, line_start, limits);
        switch (parsed) {
            .skip => {},
            .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            .repository => |repository| {
                if (repositories.items.len >= limits.max_sources) {
                    freeRepository(allocator, repository);
                    return .{ .diagnostic = .{
                        .code = .too_many_sources,
                        .span = .{ .start = line_start, .end = line_end },
                    } };
                }
                if (collisionDiagnostic(repositories.items, repository)) |diagnostic| {
                    freeRepository(allocator, repository);
                    return .{ .diagnostic = diagnostic };
                }
                try repositories.append(allocator, repository);
            },
        }
        if (newline == source.len) break;
        line_start = newline + 1;
    }
    const result = try finish(allocator, source, &repositories);
    complete = true;
    return result;
}

const RepositoryResult = union(enum) {
    repository: Repository,
    diagnostic: Diagnostic,
};

const LegacyLineResult = union(enum) {
    skip,
    repository: Repository,
    diagnostic: Diagnostic,
};

fn repositoryFromParagraph(
    allocator: std.mem.Allocator,
    source: []const u8,
    paragraph: deb822.Paragraph,
    limits: Limits,
) std.mem.Allocator.Error!RepositoryResult {
    var types: []SourceType = &.{};
    var uris: []LocatedString = &.{};
    var suites: []LocatedString = &.{};
    var components: []LocatedString = &.{};
    var architectures: []LocatedString = &.{};
    var signed_by: []LocatedString = &.{};
    var enabled = true;
    var trusted: ?bool = null;
    var complete = false;
    defer if (!complete) {
        allocator.free(types);
        allocator.free(uris);
        allocator.free(suites);
        allocator.free(components);
        allocator.free(architectures);
        allocator.free(signed_by);
    };

    for (paragraph.fields) |field| {
        if (std.ascii.eqlIgnoreCase(field.name, "Types")) {
            const values = try fieldWords(allocator, field, limits);
            switch (values) {
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
                .values => |words| {
                    defer allocator.free(words);
                    types = try allocator.alloc(SourceType, words.len);
                    for (words, 0..) |word, index| {
                        types[index] = parseType(word.value) orelse return .{ .diagnostic = .{
                            .code = .invalid_type,
                            .span = word.span,
                        } };
                    }
                },
            }
        } else if (std.ascii.eqlIgnoreCase(field.name, "Enabled")) {
            const value = try singleFieldWord(allocator, field, limits);
            switch (value) {
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
                .value => |word| enabled = parseBoolean(word.value) orelse
                    return .{ .diagnostic = .{ .code = .invalid_boolean, .span = word.span } },
            }
        } else if (std.ascii.eqlIgnoreCase(field.name, "URIs")) {
            const result = try fieldWords(allocator, field, limits);
            switch (result) {
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
                .values => |words| uris = words,
            }
        } else if (std.ascii.eqlIgnoreCase(field.name, "Suites")) {
            const result = try fieldWords(allocator, field, limits);
            switch (result) {
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
                .values => |words| suites = words,
            }
        } else if (std.ascii.eqlIgnoreCase(field.name, "Components")) {
            const result = try fieldWords(allocator, field, limits);
            switch (result) {
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
                .values => |words| components = words,
            }
        } else if (std.ascii.eqlIgnoreCase(field.name, "Architectures")) {
            const result = try fieldWords(allocator, field, limits);
            switch (result) {
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
                .values => |words| architectures = words,
            }
        } else if (std.ascii.eqlIgnoreCase(field.name, "Signed-By")) {
            const result = try fieldWords(allocator, field, limits);
            switch (result) {
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
                .values => |words| signed_by = words,
            }
        } else if (std.ascii.eqlIgnoreCase(field.name, "Trusted")) {
            const value = try singleFieldWord(allocator, field, limits);
            switch (value) {
                .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
                .value => |word| trusted = parseBoolean(word.value) orelse
                    return .{ .diagnostic = .{ .code = .invalid_boolean, .span = word.span } },
            }
        } else {
            return .{ .diagnostic = .{
                .code = .unknown_field,
                .span = fromDeb822Span(field.name_span),
            } };
        }
    }

    const paragraph_span = fromDeb822Span(paragraph.span);
    if (types.len == 0) return missing(paragraph_span);
    if (uris.len == 0) return missing(paragraph_span);
    if (suites.len == 0) return missing(paragraph_span);
    if (components.len == 0 and !allExactSuites(suites)) {
        return .{ .diagnostic = .{ .code = .missing_components, .span = paragraph_span } };
    }
    if (components.len != 0 and anyExactSuite(suites)) {
        return .{ .diagnostic = .{ .code = .components_for_exact_suite, .span = suites[0].span } };
    }
    if (validateValues(uris, .uri)) |diagnostic| return .{ .diagnostic = diagnostic };
    if (validateValues(suites, .suite)) |diagnostic| return .{ .diagnostic = diagnostic };
    if (validateValues(components, .component)) |diagnostic| return .{ .diagnostic = diagnostic };
    if (validateValues(architectures, .architecture)) |diagnostic| return .{ .diagnostic = diagnostic };
    if (validateValues(signed_by, .signed_by)) |diagnostic| return .{ .diagnostic = diagnostic };

    var repository: Repository = .{
        .id = undefined,
        .types = types,
        .enabled = enabled,
        .uris = uris,
        .suites = suites,
        .components = components,
        .architectures = architectures,
        .signed_by = signed_by,
        .trusted = trusted,
        .span = paragraph_span,
    };
    repository.id = repositoryId(repository);
    complete = true;
    _ = source;
    return .{ .repository = repository };
}

fn parseLegacyLine(
    allocator: std.mem.Allocator,
    source: []const u8,
    line: []const u8,
    absolute_start: usize,
    limits: Limits,
) std.mem.Allocator.Error!LegacyLineResult {
    var cursor = Cursor{ .source = line, .base = absolute_start };
    cursor.skipSpace();
    if (cursor.atEnd()) return .skip;

    var comment_disabled = false;
    if (cursor.peek() == '#') {
        cursor.index += 1;
        cursor.skipSpace();
        if (!cursor.startsSourceType()) return .skip;
        comment_disabled = true;
    }

    const type_word = cursor.nextWord() orelse return .{ .diagnostic = diagnosticAt(
        .malformed_legacy_entry,
        absolute_start + cursor.index,
        source.len,
    ) };
    const source_type = parseType(type_word.value) orelse {
        if (!comment_disabled and type_word.value.len > 0 and type_word.value[0] == '#') return .skip;
        return .{ .diagnostic = .{ .code = .malformed_legacy_entry, .span = type_word.span } };
    };

    var enabled = !comment_disabled;
    var trusted: ?bool = null;
    var architectures: []LocatedString = &.{};
    var signed_by: []LocatedString = &.{};
    var complete = false;
    defer if (!complete) {
        allocator.free(architectures);
        allocator.free(signed_by);
    };

    cursor.skipSpace();
    if (!cursor.atEnd() and cursor.peek() == '[') {
        const option_result = try parseLegacyOptions(allocator, &cursor, limits);
        switch (option_result) {
            .diagnostic => |diagnostic| return .{ .diagnostic = diagnostic },
            .options => |options| {
                architectures = options.architectures;
                signed_by = options.signed_by;
                if (options.enabled) |option_enabled| {
                    if (comment_disabled and option_enabled) {
                        return .{ .diagnostic = .{
                            .code = .ambiguous_enabled_state,
                            .span = options.enabled_span.?,
                        } };
                    }
                    enabled = option_enabled;
                }
                trusted = options.trusted;
            },
        }
    }

    const uri = cursor.nextWord() orelse return .{ .diagnostic = diagnosticAt(
        .malformed_legacy_entry,
        absolute_start + cursor.index,
        source.len,
    ) };
    const suite = cursor.nextWord() orelse return .{ .diagnostic = diagnosticAt(
        .malformed_legacy_entry,
        absolute_start + cursor.index,
        source.len,
    ) };

    var components_list: std.ArrayList(LocatedString) = .empty;
    defer components_list.deinit(allocator);
    while (cursor.nextWord()) |word| {
        if (word.value.len > 0 and word.value[0] == '#') break;
        try components_list.append(allocator, word);
    }
    const components = try components_list.toOwnedSlice(allocator);
    defer if (!complete) allocator.free(components);

    const types = try allocator.alloc(SourceType, 1);
    defer if (!complete) allocator.free(types);
    types[0] = source_type;
    const uris = try allocator.alloc(LocatedString, 1);
    defer if (!complete) allocator.free(uris);
    uris[0] = uri;
    const suites = try allocator.alloc(LocatedString, 1);
    defer if (!complete) allocator.free(suites);
    suites[0] = suite;

    if (components.len == 0 and !isExactSuite(suite.value)) {
        return .{ .diagnostic = .{ .code = .missing_components, .span = suite.span } };
    }
    if (components.len != 0 and isExactSuite(suite.value)) {
        return .{ .diagnostic = .{ .code = .components_for_exact_suite, .span = suite.span } };
    }
    if (validateValues(uris, .uri)) |diagnostic| return .{ .diagnostic = diagnostic };
    if (validateValues(suites, .suite)) |diagnostic| return .{ .diagnostic = diagnostic };
    if (validateValues(components, .component)) |diagnostic| return .{ .diagnostic = diagnostic };
    if (validateValues(architectures, .architecture)) |diagnostic| return .{ .diagnostic = diagnostic };
    if (validateValues(signed_by, .signed_by)) |diagnostic| return .{ .diagnostic = diagnostic };

    var repository: Repository = .{
        .id = undefined,
        .types = types,
        .enabled = enabled,
        .uris = uris,
        .suites = suites,
        .components = components,
        .architectures = architectures,
        .signed_by = signed_by,
        .trusted = trusted,
        .span = .{ .start = absolute_start, .end = absolute_start + line.len },
    };
    repository.id = repositoryId(repository);
    complete = true;
    return .{ .repository = repository };
}

const LegacyOptions = struct {
    architectures: []LocatedString,
    signed_by: []LocatedString,
    enabled: ?bool = null,
    enabled_span: ?Span = null,
    trusted: ?bool = null,
    trusted_span: ?Span = null,
};

const LegacyOptionsResult = union(enum) {
    options: LegacyOptions,
    diagnostic: Diagnostic,
};

fn parseLegacyOptions(
    allocator: std.mem.Allocator,
    cursor: *Cursor,
    limits: Limits,
) std.mem.Allocator.Error!LegacyOptionsResult {
    const block_start = cursor.base + cursor.index;
    cursor.index += 1;
    const close = std.mem.indexOfScalarPos(u8, cursor.source, cursor.index, ']') orelse
        return .{ .diagnostic = .{
            .code = .malformed_option_block,
            .span = .{ .start = block_start, .end = cursor.base + cursor.source.len },
        } };
    const block = cursor.source[cursor.index..close];
    const block_base = cursor.base + cursor.index;
    cursor.index = close + 1;
    if (!cursor.atEnd() and cursor.peek() != ' ' and cursor.peek() != '\t') {
        return .{ .diagnostic = .{
            .code = .trailing_content,
            .span = pointSpan(cursor.base + cursor.index, cursor.base + cursor.source.len),
        } };
    }

    var architectures: []LocatedString = &.{};
    var signed_by: []LocatedString = &.{};
    var enabled: ?bool = null;
    var enabled_span: ?Span = null;
    var trusted: ?bool = null;
    var trusted_span: ?Span = null;
    var complete = false;
    defer if (!complete) {
        allocator.free(architectures);
        allocator.free(signed_by);
    };

    var option_cursor = Cursor{ .source = block, .base = block_base };
    var option_count: usize = 0;
    while (option_cursor.nextWord()) |option| {
        option_count += 1;
        if (option_count > limits.max_legacy_options) {
            return .{ .diagnostic = .{ .code = .too_many_options, .span = option.span } };
        }
        const equals = std.mem.indexOfScalar(u8, option.value, '=') orelse
            return .{ .diagnostic = .{ .code = .malformed_option, .span = option.span } };
        if (equals == 0 or equals + 1 == option.value.len or
            std.mem.indexOfScalar(u8, option.value[equals + 1 ..], '=') != null)
        {
            return .{ .diagnostic = .{ .code = .malformed_option, .span = option.span } };
        }
        const name = option.value[0..equals];
        const value = option.value[equals + 1 ..];
        const value_span = Span{ .start = option.span.start + equals + 1, .end = option.span.end };
        if (std.mem.eql(u8, name, "arch")) {
            if (architectures.len != 0) return duplicateOption(option.span);
            if (validateCommaList(value, value_span, limits)) |diagnostic| {
                return .{ .diagnostic = diagnostic };
            }
            architectures = try commaValues(allocator, value, value_span);
        } else if (std.mem.eql(u8, name, "signed-by")) {
            if (signed_by.len != 0) return duplicateOption(option.span);
            if (validateCommaList(value, value_span, limits)) |diagnostic| {
                return .{ .diagnostic = diagnostic };
            }
            signed_by = try commaValues(allocator, value, value_span);
        } else if (std.mem.eql(u8, name, "enabled")) {
            if (enabled != null) return duplicateOption(option.span);
            enabled = parseBoolean(value) orelse
                return .{ .diagnostic = .{ .code = .invalid_boolean, .span = value_span } };
            enabled_span = value_span;
        } else if (std.mem.eql(u8, name, "trusted")) {
            if (trusted != null) return duplicateOption(option.span);
            trusted = parseBoolean(value) orelse
                return .{ .diagnostic = .{ .code = .invalid_boolean, .span = value_span } };
            trusted_span = value_span;
        } else {
            return .{ .diagnostic = .{ .code = .unsupported_option, .span = option.span } };
        }
    }
    if (option_count == 0) return .{ .diagnostic = .{
        .code = .malformed_option,
        .span = .{ .start = block_start, .end = cursor.base + close + 1 },
    } };
    const options: LegacyOptions = .{
        .architectures = architectures,
        .signed_by = signed_by,
        .enabled = enabled,
        .enabled_span = enabled_span,
        .trusted = trusted,
        .trusted_span = trusted_span,
    };
    complete = true;
    return .{ .options = options };
}

fn duplicateOption(span: Span) LegacyOptionsResult {
    return .{ .diagnostic = .{ .code = .duplicate_option, .span = span } };
}

const WordsResult = union(enum) {
    values: []LocatedString,
    diagnostic: Diagnostic,
};

fn fieldWords(
    allocator: std.mem.Allocator,
    field: deb822.Field,
    limits: Limits,
) std.mem.Allocator.Error!WordsResult {
    var words: std.ArrayList(LocatedString) = .empty;
    defer words.deinit(allocator);
    for (field.value_lines) |line| {
        var cursor = Cursor{ .source = line.text, .base = line.span.start.offset };
        while (cursor.nextWord()) |word| {
            if (word.value.len > limits.max_value_bytes) {
                return .{ .diagnostic = .{ .code = .value_too_long, .span = word.span } };
            }
            if (words.items.len >= limits.max_values_per_field) {
                return .{ .diagnostic = .{ .code = .too_many_values, .span = word.span } };
            }
            try words.append(allocator, word);
        }
    }
    if (words.items.len == 0) return .{ .diagnostic = .{
        .code = .empty_field,
        .span = fromDeb822Span(field.span),
    } };
    return .{ .values = try words.toOwnedSlice(allocator) };
}

const SingleWordResult = union(enum) {
    value: LocatedString,
    diagnostic: Diagnostic,
};

fn singleFieldWord(
    allocator: std.mem.Allocator,
    field: deb822.Field,
    limits: Limits,
) std.mem.Allocator.Error!SingleWordResult {
    const result = try fieldWords(allocator, field, limits);
    return switch (result) {
        .diagnostic => |diagnostic| .{ .diagnostic = diagnostic },
        .values => |words| blk: {
            defer allocator.free(words);
            if (words.len != 1) break :blk .{ .diagnostic = .{
                .code = .invalid_boolean,
                .span = fromDeb822Span(field.span),
            } };
            break :blk .{ .value = words[0] };
        },
    };
}

fn commaValues(
    allocator: std.mem.Allocator,
    value: []const u8,
    span: Span,
) std.mem.Allocator.Error![]LocatedString {
    var values: std.ArrayList(LocatedString) = .empty;
    defer values.deinit(allocator);
    var start: usize = 0;
    while (start <= value.len) {
        const end = std.mem.indexOfScalarPos(u8, value, start, ',') orelse value.len;
        try values.append(allocator, .{
            .value = value[start..end],
            .span = .{ .start = span.start + start, .end = span.start + end },
        });
        if (end == value.len) break;
        start = end + 1;
    }
    return values.toOwnedSlice(allocator);
}

fn validateCommaList(value: []const u8, span: Span, limits: Limits) ?Diagnostic {
    var count: usize = 0;
    var start: usize = 0;
    while (start <= value.len) {
        const end = std.mem.indexOfScalarPos(u8, value, start, ',') orelse value.len;
        if (end == start) return .{ .code = .malformed_option, .span = span };
        if (end - start > limits.max_value_bytes) {
            return .{
                .code = .value_too_long,
                .span = .{ .start = span.start + start, .end = span.start + end },
            };
        }
        count += 1;
        if (count > limits.max_values_per_field) {
            return .{
                .code = .too_many_values,
                .span = .{ .start = span.start + start, .end = span.start + end },
            };
        }
        if (end == value.len) break;
        start = end + 1;
    }
    return null;
}

const ValueKind = enum { uri, suite, component, architecture, signed_by };

fn validateValues(values: []const LocatedString, kind: ValueKind) ?Diagnostic {
    for (values) |value| {
        const valid = switch (kind) {
            .uri, .suite => validGeneralToken(value.value),
            .component => validComponent(value.value),
            .architecture => validArchitecture(value.value),
            .signed_by => validSignedBy(value.value),
        };
        if (!valid) return .{
            .code = switch (kind) {
                .uri => .invalid_uri,
                .suite => .invalid_suite,
                .component => .invalid_component,
                .architecture => .invalid_architecture,
                .signed_by => .invalid_signed_by,
            },
            .span = value.span,
        };
    }
    return null;
}

fn validGeneralToken(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |character| if (character <= ' ' or character == 0x7f) return false;
    return true;
}

fn validComponent(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |character| {
        if (!(std.ascii.isAlphanumeric(character) or character == '-' or
            character == '_' or character == '.' or character == '/')) return false;
    }
    return true;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |character| {
        if (!(std.ascii.isAlphanumeric(character) or character == '-')) return false;
    }
    return true;
}

fn validSignedBy(value: []const u8) bool {
    if (value.len < 2 or value[0] != '/') return false;
    for (value) |character| if (character <= ' ' or character == 0x7f) return false;
    return true;
}

fn parseType(value: []const u8) ?SourceType {
    if (std.mem.eql(u8, value, "deb")) return .binary;
    if (std.mem.eql(u8, value, "deb-src")) return .source;
    return null;
}

fn parseBoolean(value: []const u8) ?bool {
    if (std.mem.eql(u8, value, "yes")) return true;
    if (std.mem.eql(u8, value, "no")) return false;
    return null;
}

fn anyExactSuite(suites: []const LocatedString) bool {
    for (suites) |suite| if (isExactSuite(suite.value)) return true;
    return false;
}

fn allExactSuites(suites: []const LocatedString) bool {
    for (suites) |suite| if (!isExactSuite(suite.value)) return false;
    return true;
}

fn isExactSuite(suite: []const u8) bool {
    return suite.len != 0 and suite[suite.len - 1] == '/';
}

fn repositoryId(repository: Repository) RepositoryId {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hashPart(&hash, "enabled");
    hashPart(&hash, if (repository.enabled) "yes" else "no");
    hashPart(&hash, "trusted");
    hashPart(&hash, if (repository.trusted) |trusted|
        if (trusted) "yes" else "no"
    else
        "default");
    hashPart(&hash, "types");
    hashCount(&hash, repository.types.len);
    for (repository.types) |source_type| hashPart(&hash, source_type.spelling());
    hashPart(&hash, "uris");
    hashCount(&hash, repository.uris.len);
    for (repository.uris) |value| hashPart(&hash, value.value);
    hashPart(&hash, "suites");
    hashCount(&hash, repository.suites.len);
    for (repository.suites) |value| hashPart(&hash, value.value);
    hashPart(&hash, "components");
    hashCount(&hash, repository.components.len);
    for (repository.components) |value| hashPart(&hash, value.value);
    hashPart(&hash, "architectures");
    hashCount(&hash, repository.architectures.len);
    for (repository.architectures) |value| hashPart(&hash, value.value);
    hashPart(&hash, "signed-by");
    hashCount(&hash, repository.signed_by.len);
    for (repository.signed_by) |value| hashPart(&hash, value.value);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .bytes = std.fmt.bytesToHex(digest, .lower) };
}

fn hashPart(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, @intCast(value.len), .big);
    hash.update(&length);
    hash.update(value);
}

fn hashCount(hash: *std.crypto.hash.sha2.Sha256, count: usize) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(count), .big);
    hash.update(&bytes);
}

fn collisionDiagnostic(existing: []const Repository, candidate: Repository) ?Diagnostic {
    for (existing) |repository| {
        if (std.mem.eql(u8, repository.id.slice(), candidate.id.slice())) {
            return .{
                .code = if (repositoriesEqual(repository, candidate))
                    .duplicate_repository
                else
                    .repository_id_collision,
                .span = candidate.span,
            };
        }
    }
    return null;
}

fn repositoriesEqual(a: Repository, b: Repository) bool {
    return a.enabled == b.enabled and a.trusted == b.trusted and
        std.mem.eql(SourceType, a.types, b.types) and
        equalValues(a.uris, b.uris) and equalValues(a.suites, b.suites) and
        equalValues(a.components, b.components) and
        equalValues(a.architectures, b.architectures) and
        equalValues(a.signed_by, b.signed_by);
}

fn equalValues(a: []const LocatedString, b: []const LocatedString) bool {
    if (a.len != b.len) return false;
    for (a, b) |left, right| if (!std.mem.eql(u8, left.value, right.value)) return false;
    return true;
}

fn finish(
    allocator: std.mem.Allocator,
    source: []const u8,
    repositories: *std.ArrayList(Repository),
) std.mem.Allocator.Error!ParseResult {
    return .{ .sources = .{
        .source = source,
        .repositories = try repositories.toOwnedSlice(allocator),
        .allocator = allocator,
    } };
}

fn freeRepository(allocator: std.mem.Allocator, repository: Repository) void {
    allocator.free(repository.types);
    allocator.free(repository.uris);
    allocator.free(repository.suites);
    allocator.free(repository.components);
    allocator.free(repository.architectures);
    allocator.free(repository.signed_by);
}

fn freeRepositories(allocator: std.mem.Allocator, repositories: []const Repository) void {
    for (repositories) |repository| freeRepository(allocator, repository);
}

fn missing(span: Span) RepositoryResult {
    return .{ .diagnostic = .{ .code = .missing_field, .span = span } };
}

fn fromDeb822Span(span: deb822.Span) Span {
    return .{ .start = span.start.offset, .end = span.end.offset };
}

fn pointSpan(offset: usize, source_len: usize) Span {
    return .{ .start = @min(offset, source_len), .end = @min(offset + 1, source_len) };
}

fn diagnosticAt(code: DiagnosticCode, offset: usize, source_len: usize) Diagnostic {
    return .{ .code = code, .span = pointSpan(offset, source_len) };
}

const Cursor = struct {
    source: []const u8,
    base: usize,
    index: usize = 0,

    fn atEnd(self: Cursor) bool {
        return self.index >= self.source.len;
    }

    fn peek(self: Cursor) u8 {
        return self.source[self.index];
    }

    fn skipSpace(self: *Cursor) void {
        while (!self.atEnd() and (self.peek() == ' ' or self.peek() == '\t')) self.index += 1;
    }

    fn nextWord(self: *Cursor) ?LocatedString {
        self.skipSpace();
        if (self.atEnd()) return null;
        const start = self.index;
        while (!self.atEnd() and self.peek() != ' ' and self.peek() != '\t') self.index += 1;
        return .{
            .value = self.source[start..self.index],
            .span = .{ .start = self.base + start, .end = self.base + self.index },
        };
    }

    fn startsSourceType(self: Cursor) bool {
        return (std.mem.startsWith(u8, self.source[self.index..], "deb ") or
            std.mem.startsWith(u8, self.source[self.index..], "deb\t") or
            std.mem.startsWith(u8, self.source[self.index..], "deb-src ") or
            std.mem.startsWith(u8, self.source[self.index..], "deb-src\t"));
    }
};

fn expectDiagnostic(input: []const u8, format: Format, code: DiagnosticCode) !Diagnostic {
    const result = try parse(std.testing.allocator, input, format, .{});
    return switch (result) {
        .diagnostic => |diagnostic| blk: {
            try std.testing.expectEqual(code, diagnostic.code);
            break :blk diagnostic;
        },
        .sources => |sources_value| {
            var sources = sources_value;
            defer sources.deinit();
            return error.ExpectedDiagnostic;
        },
    };
}

test "parses canonical DEB822 sources with comments and multiple values" {
    const input =
        "# Debian repositories\n" ++
        "Types: deb deb-src\n" ++
        "URIs: https://deb.example/debian https://mirror.example/debian\n" ++
        "Suites: stable stable-updates\n" ++
        "Components: main contrib\n" ++
        "Architectures: amd64 arm64\n" ++
        "Signed-By: /usr/share/keyrings/example.gpg\n" ++
        "Enabled: no\n";
    const result = try parseDeb822(std.testing.allocator, input, .{});
    var sources = switch (result) {
        .sources => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer sources.deinit();
    const repository = sources.repositories[0];
    try std.testing.expectEqual(2, repository.types.len);
    try std.testing.expectEqual(2, repository.uris.len);
    try std.testing.expectEqual(2, repository.suites.len);
    try std.testing.expect(!repository.enabled);
    try std.testing.expectEqualStrings("amd64", repository.architectures[0].value);
    try std.testing.expectEqual(64, repository.id.slice().len);
}

test "DEB822 whitespace normalizes to deterministic IDs" {
    const compact =
        "Types: deb\nURIs: https://deb.example/debian\nSuites: stable\nComponents: main\n";
    const spaced =
        "Types:\tdeb\nURIs:   https://deb.example/debian\nSuites: stable\nComponents: main\n";
    const first_result = try parseDeb822(std.testing.allocator, compact, .{});
    var first = switch (first_result) {
        .sources => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer first.deinit();
    const second_result = try parseDeb822(std.testing.allocator, spaced, .{});
    var second = switch (second_result) {
        .sources => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer second.deinit();
    try std.testing.expectEqualStrings(
        first.repositories[0].id.slice(),
        second.repositories[0].id.slice(),
    );
    try std.testing.expectEqualStrings(
        "65b22c90c0440ad603851b8219cdf44f35ca85d1ee99ecd37eb9e9e6cc6a9fa8",
        first.repositories[0].id.slice(),
    );
}

test "parses legacy entries, options, comments, and disabled entries" {
    const input =
        "  # ordinary comment\n" ++
        "deb [arch=amd64,arm64 signed-by=/keys/a.gpg,/keys/b.gpg trusted=no] https://deb.example stable main contrib # trailing\n" ++
        "# deb-src https://deb.example stable main\n" ++
        "deb [enabled=no] https://other.example testing main\n";
    const result = try parseLegacy(std.testing.allocator, input, .{});
    var sources = switch (result) {
        .sources => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer sources.deinit();
    try std.testing.expectEqual(3, sources.repositories.len);
    try std.testing.expectEqual(2, sources.repositories[0].architectures.len);
    try std.testing.expectEqual(2, sources.repositories[0].signed_by.len);
    try std.testing.expectEqual(false, sources.repositories[0].trusted.?);
    try std.testing.expect(!sources.repositories[1].enabled);
    try std.testing.expect(!sources.repositories[2].enabled);
}

test "rejects duplicate and unsupported DEB822 fields" {
    _ = try expectDiagnostic(
        "Types: deb\nTypes: deb-src\nURIs: https://x\nSuites: stable\nComponents: main\n",
        .deb822,
        .duplicate_field,
    );
    _ = try expectDiagnostic(
        "Types: deb\nURIs: https://x\nSuites: stable\nComponents: main\nTargets: Packages\n",
        .deb822,
        .unknown_field,
    );
}

test "rejects malformed legacy options and ambiguous disabled entries" {
    _ = try expectDiagnostic("deb [arch] https://x stable main\n", .legacy, .malformed_option);
    _ = try expectDiagnostic("deb [arch=amd64,] https://x stable main\n", .legacy, .malformed_option);
    _ = try expectDiagnostic("deb [foo=yes] https://x stable main\n", .legacy, .unsupported_option);
    _ = try expectDiagnostic("deb [arch=amd64 arch=arm64] https://x stable main\n", .legacy, .duplicate_option);
    _ = try expectDiagnostic("# deb [enabled=yes] https://x stable main\n", .legacy, .ambiguous_enabled_state);
    _ = try expectDiagnostic("deb [arch=amd64]https://x stable main\n", .legacy, .trailing_content);
}

test "rejects invalid paths, exact-suite components, and duplicate IDs" {
    _ = try expectDiagnostic(
        "Types: deb\nURIs: https://x\nSuites: stable\nComponents: main\nSigned-By: ABCDEF\n",
        .deb822,
        .invalid_signed_by,
    );
    _ = try expectDiagnostic("deb https://x path/ main\n", .legacy, .components_for_exact_suite);
    _ = try expectDiagnostic(
        "deb https://x stable main\ndeb   https://x stable main\n",
        .legacy,
        .duplicate_repository,
    );
}

test "enforces source-specific configured bounds" {
    const result = try parse(std.testing.allocator, "deb https://x stable main\n", .legacy, .{
        .max_input_bytes = 5,
    });
    switch (result) {
        .diagnostic => |diagnostic| try std.testing.expectEqual(.input_too_long, diagnostic.code),
        .sources => |sources_value| {
            var sources = sources_value;
            defer sources.deinit();
            return error.ExpectedDiagnostic;
        },
    }

    const too_many_sources = try parse(
        std.testing.allocator,
        "deb https://x stable main\ndeb https://y stable main\n",
        .legacy,
        .{ .max_sources = 1 },
    );
    switch (too_many_sources) {
        .diagnostic => |diagnostic| try std.testing.expectEqual(.too_many_sources, diagnostic.code),
        .sources => |sources_value| {
            var sources = sources_value;
            defer sources.deinit();
            return error.ExpectedDiagnostic;
        },
    }

    const too_many_values = try parse(
        std.testing.allocator,
        "Types: deb\nURIs: https://x https://y\nSuites: stable\nComponents: main\n",
        .deb822,
        .{ .max_values_per_field = 1 },
    );
    switch (too_many_values) {
        .diagnostic => |diagnostic| try std.testing.expectEqual(.too_many_values, diagnostic.code),
        .sources => |sources_value| {
            var sources = sources_value;
            defer sources.deinit();
            return error.ExpectedDiagnostic;
        },
    }
}

test "diagnostics retain the offending source span" {
    const input = "deb [arch=amd64,@] https://x stable main\n";
    const diagnostic = try expectDiagnostic(input, .legacy, .invalid_architecture);
    try std.testing.expectEqualStrings("@", diagnostic.span.slice(input));
}
