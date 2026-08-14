const std = @import("std");
const control_record = @import("control_record.zig");
const deb822 = @import("deb822.zig");
const source_module = @import("source.zig");

pub const RepositoryId = source_module.RepositoryId;

/// Caller-selected identity for the uncompressed Packages index. All strings
/// are borrowed and must outlive the parsed index.
pub const Context = struct {
    repository_id: RepositoryId,
    component: []const u8,
    architecture: []const u8,
    /// Opaque caller-provided path or URL used in record diagnostics.
    source_location: []const u8,
};

/// Duplicate identity uses exact Package, Version spelling, and Architecture
/// bytes; it does not collapse Debian versions that merely compare equal.
pub const DuplicatePolicy = enum {
    reject,
    keep_first,
    /// Replace a duplicate in its first-seen output position.
    keep_last,
};

pub const Limits = struct {
    max_total_bytes: usize = 64 * 1024 * 1024,
    max_records: usize = 250_000,
    max_fields_per_record: usize = 1_000,
    max_field_bytes: usize = 1024 * 1024,
    max_unknown_fields_per_record: usize = 512,
    max_filename_bytes: usize = 4096,
    relation: @import("relation.zig").Limits = .{},
};

pub const Options = struct {
    limits: Limits = .{},
    duplicate_policy: DuplicatePolicy = .reject,
};

pub const Text = struct {
    value: []const u8,
    span: deb822.Span,
};

pub const DecimalSize = struct {
    value: u64,
    spelling: Text,
};

pub const Sha256 = struct {
    bytes: [32]u8,
    spelling: Text,
};

pub const Transport = struct {
    filename: Text,
    size: DecimalSize,
    sha256: Sha256,
};

pub const Location = struct {
    source: []const u8,
    span: deb822.Span,
};

pub const Identity = struct {
    package: control_record.Token,
    version: control_record.VersionValue,
    architecture: control_record.Token,
};

pub const PackageRecord = struct {
    /// The typed control record is the sole source of package identity, so the
    /// transport wrapper cannot disagree with it.
    control: *const control_record.Record,
    transport: Transport,
    location: Location,

    pub fn identity(self: PackageRecord) Identity {
        return .{
            .package = self.control.package,
            .version = self.control.version,
            .architecture = self.control.architecture,
        };
    }
};

pub const DiagnosticCode = enum {
    invalid_context_component,
    invalid_context_architecture,
    missing_context_source,
    control_record,
    missing_filename,
    invalid_filename,
    filename_too_long,
    missing_size,
    invalid_size,
    missing_sha256,
    invalid_sha256,
    architecture_mismatch,
    duplicate_identity,
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    span: deb822.Span,
    field_name: ?[]const u8 = null,
    control_diagnostic: ?control_record.Diagnostic = null,
};

/// Borrows the input bytes and context strings. The DEB822 parser currently
/// materializes bounded metadata for the complete input; it does not copy the
/// input. Iterator consumption therefore avoids another full input copy but is
/// not incremental I/O parsing.
pub const Index = struct {
    context: Context,
    records: []PackageRecord,
    control_document: control_record.BorrowedDocument,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Index) void {
        self.allocator.free(self.records);
        self.control_document.deinit();
        self.* = undefined;
    }

    pub fn iterator(self: *const Index) Iterator {
        return .{ .records = self.records };
    }
};

pub const Iterator = struct {
    records: []const PackageRecord,
    next_index: usize = 0,

    pub fn next(self: *Iterator) ?*const PackageRecord {
        if (self.next_index == self.records.len) return null;
        defer self.next_index += 1;
        return &self.records[self.next_index];
    }
};

pub const ParseResult = union(enum) {
    index: Index,
    diagnostic: Diagnostic,
};

pub fn parseBorrowed(
    allocator: std.mem.Allocator,
    input: []const u8,
    context: Context,
    options: Options,
) std.mem.Allocator.Error!ParseResult {
    const origin = pointSpan(0);
    if (!validComponent(context.component)) {
        return .{ .diagnostic = .{ .code = .invalid_context_component, .span = origin } };
    }
    if (!validArchitecture(context.architecture)) {
        return .{ .diagnostic = .{ .code = .invalid_context_architecture, .span = origin } };
    }
    if (context.source_location.len == 0) {
        return .{ .diagnostic = .{ .code = .missing_context_source, .span = origin } };
    }

    const parsed = try control_record.parseBorrowed(allocator, input, .{
        .limits = .{
            .deb822 = .{
                .max_total_bytes = options.limits.max_total_bytes,
                .max_paragraphs = options.limits.max_records,
                .max_fields_per_paragraph = options.limits.max_fields_per_record,
                .max_field_bytes = options.limits.max_field_bytes,
            },
            .max_records = options.limits.max_records,
            .max_unknown_fields_per_record = options.limits.max_unknown_fields_per_record,
            .relation = options.limits.relation,
        },
    });
    var document = switch (parsed) {
        .document => |value| value,
        .diagnostic => |diagnostic| return .{ .diagnostic = .{
            .code = .control_record,
            .span = diagnostic.span,
            .field_name = diagnostic.field_name,
            .control_diagnostic = diagnostic,
        } },
    };
    errdefer document.deinit();

    var records: std.ArrayList(PackageRecord) = .empty;
    defer records.deinit(allocator);
    var identities = std.StringHashMap(usize).init(allocator);
    defer identities.deinit();
    var identity_keys: std.ArrayList([]u8) = .empty;
    defer {
        for (identity_keys.items) |key| allocator.free(key);
        identity_keys.deinit(allocator);
    }

    for (document.records, document.deb822_document.paragraphs) |*control, paragraph| {
        if (!std.mem.eql(u8, control.architecture.text, context.architecture) and
            !std.mem.eql(u8, control.architecture.text, "all"))
        {
            const diagnostic: Diagnostic = .{
                .code = .architecture_mismatch,
                .span = control.architecture.span,
                .field_name = "Architecture",
            };
            document.deinit();
            return .{ .diagnostic = diagnostic };
        }

        var transport_parser: TransportParser = .{ .limits = options.limits };
        const transport = transport_parser.parse(paragraph) catch {
            const failure = transport_parser.failure.?;
            const diagnostic: Diagnostic = .{
                .code = failure.code,
                .span = failure.span,
                .field_name = failure.field_name,
            };
            document.deinit();
            return .{ .diagnostic = diagnostic };
        };
        const record: PackageRecord = .{
            .control = control,
            .transport = transport,
            .location = .{ .source = context.source_location, .span = control.span },
        };

        const key = try identityKey(allocator, control);
        var free_key = true;
        defer if (free_key) allocator.free(key);
        if (identities.get(key)) |existing| {
            switch (options.duplicate_policy) {
                .reject => {
                    const diagnostic: Diagnostic = .{
                        .code = .duplicate_identity,
                        .span = control.span,
                    };
                    document.deinit();
                    return .{ .diagnostic = diagnostic };
                },
                .keep_first => continue,
                .keep_last => records.items[existing] = record,
            }
        } else {
            const output_index = records.items.len;
            try identities.put(key, output_index);
            identity_keys.append(allocator, key) catch |err| {
                _ = identities.remove(key);
                return err;
            };
            free_key = false;
            try records.append(allocator, record);
        }
    }

    return .{ .index = .{
        .context = context,
        .records = try records.toOwnedSlice(allocator),
        .control_document = document,
        .allocator = allocator,
    } };
}

const TransportFailure = struct {
    code: DiagnosticCode,
    span: deb822.Span,
    field_name: []const u8,
};

const TransportParser = struct {
    limits: Limits,
    failure: ?TransportFailure = null,

    fn parse(self: *TransportParser, paragraph: deb822.Paragraph) error{InvalidTransport}!Transport {
        const filename_field = paragraph.get("Filename") orelse
            return self.fail(.missing_filename, paragraph.span, "Filename");
        const filename = try self.exactScalar(filename_field, .invalid_filename);
        if (filename.value.len > self.limits.max_filename_bytes) {
            return self.fail(.filename_too_long, filename.span, filename_field.name);
        }
        if (!validRelativeFilename(filename.value)) {
            return self.fail(.invalid_filename, filename.span, filename_field.name);
        }

        const size_field = paragraph.get("Size") orelse
            return self.fail(.missing_size, paragraph.span, "Size");
        const size_text = try self.exactScalar(size_field, .invalid_size);
        if (size_text.value.len == 0) {
            return self.fail(.invalid_size, size_text.span, size_field.name);
        }
        for (size_text.value) |byte| {
            if (!std.ascii.isDigit(byte)) {
                return self.fail(.invalid_size, size_text.span, size_field.name);
            }
        }
        const size = std.fmt.parseUnsigned(u64, size_text.value, 10) catch
            return self.fail(.invalid_size, size_text.span, size_field.name);

        const sha_field = paragraph.get("SHA256") orelse
            return self.fail(.missing_sha256, paragraph.span, "SHA256");
        const sha_text = try self.exactScalar(sha_field, .invalid_sha256);
        if (sha_text.value.len != 64) {
            return self.fail(.invalid_sha256, sha_text.span, sha_field.name);
        }
        var digest: [32]u8 = undefined;
        for (0..32) |index| {
            const high = lowerHex(sha_text.value[index * 2]) orelse
                return self.fail(.invalid_sha256, sha_text.span, sha_field.name);
            const low = lowerHex(sha_text.value[index * 2 + 1]) orelse
                return self.fail(.invalid_sha256, sha_text.span, sha_field.name);
            digest[index] = high * 16 + low;
        }

        return .{
            .filename = filename,
            .size = .{ .value = size, .spelling = size_text },
            .sha256 = .{ .bytes = digest, .spelling = sha_text },
        };
    }

    fn exactScalar(
        self: *TransportParser,
        field: *const deb822.Field,
        code: DiagnosticCode,
    ) error{InvalidTransport}!Text {
        if (field.value_lines.len != 1) return self.fail(code, field.span, field.name);
        const line = field.value_lines[0];
        return .{ .value = line.text, .span = line.span };
    }

    fn fail(
        self: *TransportParser,
        code: DiagnosticCode,
        span: deb822.Span,
        field_name: []const u8,
    ) error{InvalidTransport} {
        self.failure = .{ .code = code, .span = span, .field_name = field_name };
        return error.InvalidTransport;
    }
};

fn identityKey(
    allocator: std.mem.Allocator,
    record: *const control_record.Record,
) std.mem.Allocator.Error![]u8 {
    const length = record.package.text.len + record.version.value.original.len +
        record.architecture.text.len + 2;
    const key = try allocator.alloc(u8, length);
    var offset: usize = 0;
    inline for (.{
        record.package.text,
        record.version.value.original,
        record.architecture.text,
    }, 0..) |part, index| {
        @memcpy(key[offset .. offset + part.len], part);
        offset += part.len;
        if (index != 2) {
            key[offset] = 0;
            offset += 1;
        }
    }
    return key;
}

fn validRelativeFilename(value: []const u8) bool {
    if (value.len == 0 or value[0] == '/' or value[value.len - 1] == '/') return false;
    var segment_start: usize = 0;
    for (value, 0..) |byte, index| {
        if (byte == '/') {
            const segment = value[segment_start..index];
            if (segment.len == 0 or std.mem.eql(u8, segment, ".") or
                std.mem.eql(u8, segment, ".."))
            {
                return false;
            }
            segment_start = index + 1;
        } else if (!validFilenameByte(byte)) {
            return false;
        }
    }

    const final = value[segment_start..];
    return !std.mem.eql(u8, final, ".") and !std.mem.eql(u8, final, "..");
}

fn validFilenameByte(byte: u8) bool {
    return std.ascii.isAlphanumeric(byte) or
        byte == '+' or byte == '-' or byte == '.' or byte == '_' or
        byte == '~' or byte == ':' or byte == '@';
}

fn validComponent(value: []const u8) bool {
    if (value.len == 0 or !lowerAlphaNumeric(value[0])) return false;
    for (value[1..]) |byte| {
        if (!lowerAlphaNumeric(byte) and byte != '+' and byte != '-' and byte != '.') return false;
    }
    return true;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or !lowerAlphaNumeric(value[0])) return false;
    for (value[1..]) |byte| {
        if (!lowerAlphaNumeric(byte) and byte != '-') return false;
    }
    return true;
}

fn lowerAlphaNumeric(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or std.ascii.isDigit(byte);
}

fn lowerHex(byte: u8) ?u8 {
    return if (byte >= '0' and byte <= '9')
        byte - '0'
    else if (byte >= 'a' and byte <= 'f')
        byte - 'a' + 10
    else
        null;
}

fn pointSpan(offset: usize) deb822.Span {
    const position: deb822.Position = .{ .offset = offset, .line = 1, .column = offset + 1 };
    return .{ .start = position, .end = position };
}

fn testContext(architecture: []const u8) Context {
    return .{
        .repository_id = .{ .bytes = [_]u8{'a'} ** 64 },
        .component = "main",
        .architecture = architecture,
        .source_location = "dists/stable/main/binary-amd64/Packages",
    };
}

fn packageParagraph(name: []const u8, version: []const u8, architecture: []const u8) ![]u8 {
    return std.fmt.allocPrint(std.testing.allocator, "Package: {s}\nVersion: {s}\nArchitecture: {s}\n" ++
        "Filename: pool/main/{s}/{s}_{s}_{s}.deb\n" ++
        "Size: 00123\n" ++
        "SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n" ++
        "X-Keep: yes\n", .{ name, version, architecture, name, name, version, architecture });
}

test "parses transport data, preserves control fields, and iterates without copying input" {
    const input = try packageParagraph("libfoo1", "1.2-3", "amd64");
    defer std.testing.allocator.free(input);
    const result = try parseBorrowed(std.testing.allocator, input, testContext("amd64"), .{});
    var index = switch (result) {
        .index => |value| value,
        .diagnostic => return error.UnexpectedDiagnostic,
    };
    defer index.deinit();

    try std.testing.expectEqual(@as(usize, 1), index.records.len);
    const record = index.records[0];
    try std.testing.expectEqualStrings("libfoo1", record.identity().package.text);
    try std.testing.expectEqualStrings("pool/main/libfoo1/libfoo1_1.2-3_amd64.deb", record.transport.filename.value);
    try std.testing.expectEqual(@as(u64, 123), record.transport.size.value);
    try std.testing.expectEqual(@as(u8, 0x01), record.transport.sha256.bytes[0]);
    try std.testing.expectEqualStrings(testContext("amd64").source_location, record.location.source);
    try std.testing.expectEqual(@as(usize, 1), record.location.span.start.line);
    try std.testing.expectEqual(@as(usize, 4), record.control.unknown_fields.len);
    try std.testing.expectEqualStrings("Filename", record.control.unknown_fields[0].name);

    var iterator = index.iterator();
    try std.testing.expect(iterator.next() != null);
    try std.testing.expect(iterator.next() == null);
    try std.testing.expectEqual(@intFromPtr(input.ptr), @intFromPtr(record.control.package.text.ptr) - "Package: ".len);
}

test "accepts architecture all but rejects another selected architecture" {
    const all_input = try packageParagraph("data-pkg", "1", "all");
    defer std.testing.allocator.free(all_input);
    var all_result = try parseBorrowed(std.testing.allocator, all_input, testContext("amd64"), .{});
    switch (all_result) {
        .index => |*index| index.deinit(),
        .diagnostic => return error.UnexpectedDiagnostic,
    }

    const wrong_input = try packageParagraph("arm-pkg", "1", "arm64");
    defer std.testing.allocator.free(wrong_input);
    const wrong = try parseBorrowed(std.testing.allocator, wrong_input, testContext("amd64"), .{});
    try std.testing.expectEqual(DiagnosticCode.architecture_mismatch, wrong.diagnostic.code);
}

test "requires normalized relative filenames, checked sizes, and lowercase SHA256" {
    const prefix = "Package: aa\nVersion: 1\nArchitecture: amd64\n";
    const suffix = "Size: 1\nSHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    inline for (.{
        "/pool/a.deb",
        "pool//a.deb",
        "pool/./a.deb",
        "pool/../a.deb",
        "pool\\a.deb",
        "pool/a.deb/",
        "pool/a.deb ",
        "pool/a.deb?mirror=1",
        "pool/%2e%2e/a.deb",
    }) |filename| {
        const input = try std.fmt.allocPrint(std.testing.allocator, "{s}Filename: {s}\n{s}", .{ prefix, filename, suffix });
        defer std.testing.allocator.free(input);
        const result = try parseBorrowed(std.testing.allocator, input, testContext("amd64"), .{});
        try std.testing.expectEqual(DiagnosticCode.invalid_filename, result.diagnostic.code);
    }

    const overflow = prefix ++ "Filename: pool/a.deb\nSize: 18446744073709551616\n" ++
        "SHA256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n";
    const overflow_result = try parseBorrowed(std.testing.allocator, overflow, testContext("amd64"), .{});
    try std.testing.expectEqual(DiagnosticCode.invalid_size, overflow_result.diagnostic.code);

    const uppercase = prefix ++ "Filename: pool/a.deb\nSize: 1\n" ++
        "SHA256: 0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef\n";
    const uppercase_result = try parseBorrowed(std.testing.allocator, uppercase, testContext("amd64"), .{});
    try std.testing.expectEqual(DiagnosticCode.invalid_sha256, uppercase_result.diagnostic.code);
}

test "requires every single-line transport field" {
    const prefix = "Package: aa\nVersion: 1\nArchitecture: amd64\n";
    const hash = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const cases = .{
        .{ prefix ++ "Size: 1\nSHA256: " ++ hash ++ "\n", DiagnosticCode.missing_filename },
        .{ prefix ++ "Filename: pool/a.deb\nSHA256: " ++ hash ++ "\n", DiagnosticCode.missing_size },
        .{ prefix ++ "Filename: pool/a.deb\nSize: 1\n", DiagnosticCode.missing_sha256 },
        .{ prefix ++ "Filename: pool/a.deb\nSize: 1\nSHA256: " ++ hash ++ "\n continued\n", DiagnosticCode.invalid_sha256 },
    };
    inline for (cases) |case| {
        const result = try parseBorrowed(std.testing.allocator, case[0], testContext("amd64"), .{});
        try std.testing.expectEqual(case[1], result.diagnostic.code);
    }
}

test "duplicate identity policy is deterministic" {
    const first = try packageParagraph("same-pkg", "1", "amd64");
    defer std.testing.allocator.free(first);
    const second = try std.mem.concat(std.testing.allocator, u8, &.{ first[0 .. first.len - "X-Keep: yes\n".len], "X-Keep: no\n" });
    defer std.testing.allocator.free(second);
    const input = try std.mem.concat(std.testing.allocator, u8, &.{ first, "\n", second });
    defer std.testing.allocator.free(input);

    const rejected = try parseBorrowed(std.testing.allocator, input, testContext("amd64"), .{});
    try std.testing.expectEqual(DiagnosticCode.duplicate_identity, rejected.diagnostic.code);

    inline for (.{ DuplicatePolicy.keep_first, DuplicatePolicy.keep_last }) |policy| {
        const result = try parseBorrowed(std.testing.allocator, input, testContext("amd64"), .{
            .duplicate_policy = policy,
        });
        var index = switch (result) {
            .index => |value| value,
            .diagnostic => return error.UnexpectedDiagnostic,
        };
        defer index.deinit();
        try std.testing.expectEqual(@as(usize, 1), index.records.len);
        const expected = if (policy == .keep_first) "yes" else "no";
        try std.testing.expectEqualStrings(expected, index.records[0].control.unknown_fields[3].value_lines[0].text);
    }
}

test "enforces total record field value and filename bounds" {
    const input = try packageParagraph("bounded", "1", "amd64");
    defer std.testing.allocator.free(input);
    const cases = .{
        Options{ .limits = .{ .max_total_bytes = 10 } },
        Options{ .limits = .{ .max_records = 0 } },
        Options{ .limits = .{ .max_fields_per_record = 2 } },
        Options{ .limits = .{ .max_field_bytes = 8 } },
    };
    inline for (cases) |options| {
        const result = try parseBorrowed(std.testing.allocator, input, testContext("amd64"), options);
        try std.testing.expectEqual(DiagnosticCode.control_record, result.diagnostic.code);
    }
    const filename_result = try parseBorrowed(std.testing.allocator, input, testContext("amd64"), .{
        .limits = .{ .max_filename_bytes = 5 },
    });
    try std.testing.expectEqual(DiagnosticCode.filename_too_long, filename_result.diagnostic.code);
}

test "validates explicit repository context" {
    var context = testContext("AMD64");
    const result = try parseBorrowed(std.testing.allocator, "", context, .{});
    try std.testing.expectEqual(DiagnosticCode.invalid_context_architecture, result.diagnostic.code);
    context = testContext("amd64");
    context.component = "../main";
    const component = try parseBorrowed(std.testing.allocator, "", context, .{});
    try std.testing.expectEqual(DiagnosticCode.invalid_context_component, component.diagnostic.code);
}
