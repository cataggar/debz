const std = @import("std");
const deb822 = @import("deb822.zig");
const version_module = @import("debian_version.zig");
const relation_module = @import("relation.zig");

pub const DebianVersion = version_module.DebianVersion;

pub const Want = enum {
    unknown,
    install,
    hold,
    deinstall,
    purge,
};

pub const ErrorState = enum {
    ok,
    reinst_required,
};

pub const CurrentState = enum {
    not_installed,
    config_files,
    half_installed,
    unpacked,
    half_configured,
    triggers_awaited,
    triggers_pending,
    installed,
};

pub const Status = struct {
    want: Want,
    error_state: ErrorState,
    current: CurrentState,

    pub fn isFullyInstalled(self: Status) bool {
        return self.error_state == .ok and self.current == .installed;
    }

    pub fn requiresRepair(self: Status) bool {
        return self.error_state == .reinst_required or switch (self.current) {
            .half_installed, .unpacked, .half_configured, .triggers_awaited, .triggers_pending => true,
            else => false,
        };
    }
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

pub const RelationKind = enum {
    pre_depends,
    depends,
    recommends,
    suggests,
    breaks,
    conflicts,
    replaces,
    enhances,
    provides,
};

pub const Text = struct {
    value: []const u8,
    span: deb822.Span,
};

pub const ExactVersion = struct {
    spelling: Text,
    parsed: DebianVersion,
};

pub const DependencyRelation = struct {
    kind: RelationKind,
    field_span: deb822.Span,
    source: []u8,
    relation: relation_module.Relation,

    fn deinit(self: *DependencyRelation, allocator: std.mem.Allocator) void {
        self.relation.deinit(allocator);
        allocator.free(self.source);
        self.* = undefined;
    }
};

pub const Package = struct {
    name: Text,
    version: ExactVersion,
    architecture: Text,
    status: Status,
    essential: ?bool,
    protected: ?bool,
    priority: ?Priority,
    multi_arch: ?MultiArch,
    installed_size_kib: ?u64,
    relations: []DependencyRelation,
    paragraph_span: deb822.Span,

    pub fn relation(self: Package, kind: RelationKind) ?*const DependencyRelation {
        for (self.relations) |*dependency| {
            if (dependency.kind == kind) return dependency;
        }
        return null;
    }

    fn deinit(self: *Package, allocator: std.mem.Allocator) void {
        for (self.relations) |*dependency| dependency.deinit(allocator);
        allocator.free(self.relations);
        self.* = undefined;
    }
};

pub const IdentityPolicy = enum {
    reject,
    keep_first,
    keep_last,
};

pub const Limits = struct {
    deb822: deb822.Limits = .{},
    max_packages: usize = 100_000,
    max_package_name_bytes: usize = 255,
    max_architecture_bytes: usize = 64,
    relation: relation_module.Limits = .{},
};

pub const Options = struct {
    limits: Limits = .{},
    repeated_identity: IdentityPolicy = .reject,
};

pub const DiagnosticCode = enum {
    deb822_syntax,
    too_many_packages,
    missing_package,
    invalid_package,
    package_name_too_long,
    missing_version,
    invalid_version,
    missing_architecture,
    invalid_architecture,
    architecture_too_long,
    missing_status,
    malformed_status,
    invalid_want,
    invalid_error_state,
    invalid_current_state,
    multiline_scalar,
    invalid_boolean,
    invalid_priority,
    invalid_multi_arch,
    invalid_installed_size,
    invalid_relation,
    repeated_identity,
};

pub const Diagnostic = struct {
    code: DiagnosticCode,
    span: deb822.Span,
    field_name: ?[]const u8 = null,
    deb822_code: ?deb822.ErrorKind = null,
    relation_code: ?relation_module.DiagnosticCode = null,

    pub fn message(self: Diagnostic) []const u8 {
        return switch (self.code) {
            .deb822_syntax => "invalid DEB822 status syntax",
            .too_many_packages => "status contains more packages than the configured limit",
            .missing_package => "package paragraph is missing Package",
            .invalid_package => "Package is not a valid binary package name",
            .package_name_too_long => "Package exceeds the configured length limit",
            .missing_version => "package paragraph is missing Version",
            .invalid_version => "Version is not a valid Debian version",
            .missing_architecture => "package paragraph is missing Architecture",
            .invalid_architecture => "Architecture is malformed",
            .architecture_too_long => "Architecture exceeds the configured length limit",
            .missing_status => "package paragraph is missing Status",
            .malformed_status => "Status must contain want, error, and current-state tokens",
            .invalid_want => "Status contains an unknown want token",
            .invalid_error_state => "Status contains an unknown error token",
            .invalid_current_state => "Status contains an unknown current-state token",
            .multiline_scalar => "scalar status field must not use continuation lines",
            .invalid_boolean => "boolean status field must be 'yes' or 'no'",
            .invalid_priority => "Priority contains an unknown value",
            .invalid_multi_arch => "Multi-Arch contains an unknown value",
            .invalid_installed_size => "Installed-Size must be an unsigned decimal integer",
            .invalid_relation => "dependency relation is malformed",
            .repeated_identity => "Package and Architecture identity is repeated",
        };
    }
};

pub const Database = struct {
    packages: []Package,
    document: deb822.BorrowedDocument,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Database) void {
        for (self.packages) |*package| package.deinit(self.allocator);
        self.allocator.free(self.packages);
        self.document.deinit();
        self.* = undefined;
    }

    pub fn find(self: Database, name: []const u8, architecture: []const u8) ?*const Package {
        for (self.packages) |*package| {
            if (std.mem.eql(u8, package.name.value, name) and
                std.mem.eql(u8, package.architecture.value, architecture))
            {
                return package;
            }
        }
        return null;
    }
};

pub const OwnedDatabase = struct {
    source: []u8,
    database: Database,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedDatabase) void {
        self.database.deinit();
        self.allocator.free(self.source);
        self.* = undefined;
    }
};

pub const BorrowedResult = union(enum) {
    database: Database,
    diagnostic: Diagnostic,
};

pub const OwnedResult = union(enum) {
    database: OwnedDatabase,
    diagnostic: Diagnostic,
};

const ParseError = std.mem.Allocator.Error || error{InvalidStatus};

const Parser = struct {
    allocator: std.mem.Allocator,
    options: Options,
    diagnostic: ?Diagnostic = null,

    fn fail(
        self: *Parser,
        code: DiagnosticCode,
        span: deb822.Span,
        field_name: ?[]const u8,
    ) error{InvalidStatus} {
        self.diagnostic = .{ .code = code, .span = span, .field_name = field_name };
        return error.InvalidStatus;
    }

    fn parsePackage(self: *Parser, paragraph: deb822.Paragraph) ParseError!Package {
        const name = try self.requiredScalar(paragraph, "Package", .missing_package);
        if (name.value.len > self.options.limits.max_package_name_bytes) {
            return self.fail(.package_name_too_long, name.span, "Package");
        }
        if (!validPackageName(name.value)) return self.fail(.invalid_package, name.span, "Package");

        const version_text = try self.requiredScalar(paragraph, "Version", .missing_version);
        const parsed_version = DebianVersion.parse(version_text.value) catch
            return self.fail(.invalid_version, version_text.span, "Version");

        const architecture = try self.requiredScalar(paragraph, "Architecture", .missing_architecture);
        if (architecture.value.len > self.options.limits.max_architecture_bytes) {
            return self.fail(.architecture_too_long, architecture.span, "Architecture");
        }
        if (!validArchitecture(architecture.value)) {
            return self.fail(.invalid_architecture, architecture.span, "Architecture");
        }

        const status_text = try self.requiredScalar(paragraph, "Status", .missing_status);
        const status = try self.parseStatus(status_text);

        var relations: std.ArrayList(DependencyRelation) = .empty;
        errdefer {
            for (relations.items) |*dependency| dependency.deinit(self.allocator);
            relations.deinit(self.allocator);
        }
        inline for (relation_fields) |entry| {
            if (paragraph.get(entry.name)) |field| {
                var dependency = try self.parseRelation(field.*, entry.kind);
                relations.append(self.allocator, dependency) catch |err| {
                    dependency.deinit(self.allocator);
                    return err;
                };
            }
        }

        return .{
            .name = name,
            .version = .{ .spelling = version_text, .parsed = parsed_version },
            .architecture = architecture,
            .status = status,
            .essential = try self.optionalBoolean(paragraph, "Essential"),
            .protected = try self.optionalBoolean(paragraph, "Protected"),
            .priority = try self.optionalPriority(paragraph),
            .multi_arch = try self.optionalMultiArch(paragraph),
            .installed_size_kib = try self.optionalInstalledSize(paragraph),
            .relations = try relations.toOwnedSlice(self.allocator),
            .paragraph_span = paragraph.span,
        };
    }

    fn requiredScalar(
        self: *Parser,
        paragraph: deb822.Paragraph,
        name: []const u8,
        missing: DiagnosticCode,
    ) ParseError!Text {
        const field = paragraph.get(name) orelse return self.fail(
            missing,
            pointSpan(paragraph.span.start),
            name,
        );
        return self.scalar(field.*);
    }

    fn scalar(self: *Parser, field: deb822.Field) ParseError!Text {
        if (field.value_lines.len != 1) return self.fail(.multiline_scalar, field.span, field.name);
        return .{ .value = field.value_lines[0].text, .span = field.value_lines[0].span };
    }

    fn parseStatus(self: *Parser, text: Text) ParseError!Status {
        var tokens = std.mem.tokenizeAny(u8, text.value, " \t");
        const want_text = tokens.next() orelse return self.fail(.malformed_status, text.span, "Status");
        const error_text = tokens.next() orelse return self.fail(.malformed_status, text.span, "Status");
        const current_text = tokens.next() orelse return self.fail(.malformed_status, text.span, "Status");
        if (tokens.next() != null) return self.fail(.malformed_status, text.span, "Status");

        const want = std.meta.stringToEnum(Want, want_text) orelse
            return self.fail(.invalid_want, subSpan(text, want_text), "Status");
        const error_state: ErrorState = if (std.mem.eql(u8, error_text, "ok"))
            .ok
        else if (std.mem.eql(u8, error_text, "reinstreq"))
            .reinst_required
        else
            return self.fail(.invalid_error_state, subSpan(text, error_text), "Status");
        const current: CurrentState = if (std.mem.eql(u8, current_text, "not-installed"))
            .not_installed
        else if (std.mem.eql(u8, current_text, "config-files"))
            .config_files
        else if (std.mem.eql(u8, current_text, "half-installed"))
            .half_installed
        else if (std.mem.eql(u8, current_text, "unpacked"))
            .unpacked
        else if (std.mem.eql(u8, current_text, "half-configured"))
            .half_configured
        else if (std.mem.eql(u8, current_text, "triggers-awaited"))
            .triggers_awaited
        else if (std.mem.eql(u8, current_text, "triggers-pending"))
            .triggers_pending
        else if (std.mem.eql(u8, current_text, "installed"))
            .installed
        else
            return self.fail(.invalid_current_state, subSpan(text, current_text), "Status");
        return .{ .want = want, .error_state = error_state, .current = current };
    }

    fn optionalBoolean(self: *Parser, paragraph: deb822.Paragraph, name: []const u8) ParseError!?bool {
        const field = paragraph.get(name) orelse return null;
        const text = try self.scalar(field.*);
        if (std.mem.eql(u8, text.value, "yes")) return true;
        if (std.mem.eql(u8, text.value, "no")) return false;
        return self.fail(.invalid_boolean, text.span, name);
    }

    fn optionalPriority(self: *Parser, paragraph: deb822.Paragraph) ParseError!?Priority {
        const field = paragraph.get("Priority") orelse return null;
        const text = try self.scalar(field.*);
        return std.meta.stringToEnum(Priority, text.value) orelse
            return self.fail(.invalid_priority, text.span, "Priority");
    }

    fn optionalMultiArch(self: *Parser, paragraph: deb822.Paragraph) ParseError!?MultiArch {
        const field = paragraph.get("Multi-Arch") orelse return null;
        const text = try self.scalar(field.*);
        return std.meta.stringToEnum(MultiArch, text.value) orelse
            return self.fail(.invalid_multi_arch, text.span, "Multi-Arch");
    }

    fn optionalInstalledSize(self: *Parser, paragraph: deb822.Paragraph) ParseError!?u64 {
        const field = paragraph.get("Installed-Size") orelse return null;
        const text = try self.scalar(field.*);
        if (text.value.len == 0) return self.fail(.invalid_installed_size, text.span, "Installed-Size");
        for (text.value) |byte| {
            if (!std.ascii.isDigit(byte)) {
                return self.fail(.invalid_installed_size, text.span, "Installed-Size");
            }
        }
        return std.fmt.parseUnsigned(u64, text.value, 10) catch
            return self.fail(.invalid_installed_size, text.span, "Installed-Size");
    }

    fn parseRelation(
        self: *Parser,
        field: deb822.Field,
        kind: RelationKind,
    ) ParseError!DependencyRelation {
        var logical = try LogicalValue.init(self.allocator, field);
        defer logical.deinit(self.allocator);
        const result = try relation_module.parse(self.allocator, logical.text, self.options.limits.relation);
        switch (result) {
            .diagnostic => |diagnostic| {
                self.diagnostic = .{
                    .code = .invalid_relation,
                    .span = logical.sourceSpan(diagnostic.span),
                    .field_name = field.name,
                    .relation_code = diagnostic.code,
                };
                return error.InvalidStatus;
            },
            .relation => |relation| {
                var parsed_relation = relation;
                for (parsed_relation.groups) |group| {
                    for (group.alternatives) |alternative| {
                        if (alternative.version) |constraint| {
                            _ = DebianVersion.parse(constraint.version.text) catch {
                                const invalid_span = logical.sourceSpan(constraint.version.span);
                                parsed_relation.deinit(self.allocator);
                                self.diagnostic = .{
                                    .code = .invalid_relation,
                                    .span = invalid_span,
                                    .field_name = field.name,
                                };
                                return error.InvalidStatus;
                            };
                        }
                    }
                }
                const source = logical.text;
                logical.text = &.{};
                return .{
                    .kind = kind,
                    .field_span = field.span,
                    .source = source,
                    .relation = parsed_relation,
                };
            },
        }
    }
};

const relation_fields = .{
    .{ .name = "Pre-Depends", .kind = RelationKind.pre_depends },
    .{ .name = "Depends", .kind = RelationKind.depends },
    .{ .name = "Recommends", .kind = RelationKind.recommends },
    .{ .name = "Suggests", .kind = RelationKind.suggests },
    .{ .name = "Breaks", .kind = RelationKind.breaks },
    .{ .name = "Conflicts", .kind = RelationKind.conflicts },
    .{ .name = "Replaces", .kind = RelationKind.replaces },
    .{ .name = "Enhances", .kind = RelationKind.enhances },
    .{ .name = "Provides", .kind = RelationKind.provides },
};

const LogicalValue = struct {
    text: []u8,
    positions: []deb822.Position,

    fn init(allocator: std.mem.Allocator, field: deb822.Field) std.mem.Allocator.Error!LogicalValue {
        var size: usize = 0;
        for (field.value_lines, 0..) |line, index| {
            size += line.text.len;
            if (index != 0) size += 1;
        }
        const text = try allocator.alloc(u8, size);
        errdefer allocator.free(text);
        const positions = try allocator.alloc(deb822.Position, size + 1);
        errdefer allocator.free(positions);

        var index: usize = 0;
        for (field.value_lines, 0..) |line, line_index| {
            if (line_index != 0) {
                text[index] = '\n';
                positions[index] = field.value_lines[line_index - 1].span.end;
                index += 1;
            }
            for (line.text, 0..) |byte, column| {
                text[index] = byte;
                positions[index] = .{
                    .offset = line.span.start.offset + column,
                    .line = line.span.start.line,
                    .column = line.span.start.column + column,
                };
                index += 1;
            }
        }
        positions[size] = if (field.value_lines.len == 0)
            field.span.end
        else
            field.value_lines[field.value_lines.len - 1].span.end;
        return .{ .text = text, .positions = positions };
    }

    fn deinit(self: *LogicalValue, allocator: std.mem.Allocator) void {
        if (self.text.len != 0) allocator.free(self.text);
        allocator.free(self.positions);
        self.* = undefined;
    }

    fn sourceSpan(self: LogicalValue, span: relation_module.Span) deb822.Span {
        return .{
            .start = self.positions[@min(span.start, self.text.len)],
            .end = self.positions[@min(span.end, self.text.len)],
        };
    }
};

pub fn parseBorrowed(
    allocator: std.mem.Allocator,
    source: []const u8,
    options: Options,
) std.mem.Allocator.Error!BorrowedResult {
    const syntax_result = try deb822.parseBorrowed(allocator, source, .{
        .limits = options.limits.deb822,
        .duplicate_policy = .reject,
    });
    var document = switch (syntax_result) {
        .failure => |failure| return .{ .diagnostic = .{
            .code = .deb822_syntax,
            .span = pointSpan(failure.position),
            .deb822_code = failure.kind,
        } },
        .document => |value| value,
    };
    errdefer document.deinit();

    var parser: Parser = .{ .allocator = allocator, .options = options };
    var packages: std.ArrayList(Package) = .empty;
    errdefer {
        for (packages.items) |*package| package.deinit(allocator);
        packages.deinit(allocator);
    }

    for (document.paragraphs) |paragraph| {
        if (packages.items.len >= options.limits.max_packages) {
            for (packages.items) |*package| package.deinit(allocator);
            packages.deinit(allocator);
            document.deinit();
            return .{ .diagnostic = .{
                .code = .too_many_packages,
                .span = pointSpan(paragraph.span.start),
            } };
        }

        var package = parser.parsePackage(paragraph) catch |err| switch (err) {
            error.InvalidStatus => {
                for (packages.items) |*item| item.deinit(allocator);
                packages.deinit(allocator);
                document.deinit();
                return .{ .diagnostic = parser.diagnostic.? };
            },
            error.OutOfMemory => return error.OutOfMemory,
        };

        var repeated_index: ?usize = null;
        for (packages.items, 0..) |existing, index| {
            if (std.mem.eql(u8, existing.name.value, package.name.value) and
                std.mem.eql(u8, existing.architecture.value, package.architecture.value))
            {
                repeated_index = index;
                break;
            }
        }
        if (repeated_index) |index| switch (options.repeated_identity) {
            .reject => {
                const repeated_span = package.name.span;
                package.deinit(allocator);
                for (packages.items) |*item| item.deinit(allocator);
                packages.deinit(allocator);
                document.deinit();
                return .{ .diagnostic = .{
                    .code = .repeated_identity,
                    .span = repeated_span,
                    .field_name = "Package",
                } };
            },
            .keep_first => package.deinit(allocator),
            .keep_last => {
                packages.items[index].deinit(allocator);
                packages.items[index] = package;
            },
        } else {
            packages.append(allocator, package) catch |err| {
                package.deinit(allocator);
                return err;
            };
        }
    }

    return .{ .database = .{
        .packages = try packages.toOwnedSlice(allocator),
        .document = document,
        .allocator = allocator,
    } };
}

pub fn parseOwned(
    allocator: std.mem.Allocator,
    source: []const u8,
    options: Options,
) std.mem.Allocator.Error!OwnedResult {
    const owned_source = try allocator.dupe(u8, source);
    errdefer allocator.free(owned_source);
    const result = try parseBorrowed(allocator, owned_source, options);
    return switch (result) {
        .diagnostic => |diagnostic| blk: {
            allocator.free(owned_source);
            break :blk .{ .diagnostic = diagnostic };
        },
        .database => |database| .{ .database = .{
            .source = owned_source,
            .database = database,
            .allocator = allocator,
        } },
    };
}

/// Reads only the caller-supplied path. No default or system dpkg path is consulted.
pub fn parseFile(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    options: Options,
) !OwnedResult {
    const source = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(options.limits.deb822.max_total_bytes),
    );
    defer allocator.free(source);
    return parseOwned(allocator, source, options);
}

fn validPackageName(value: []const u8) bool {
    if (value.len == 0 or !lowerAlphaNumeric(value[0])) return false;
    for (value) |byte| {
        if (!(lowerAlphaNumeric(byte) or byte == '+' or byte == '-' or byte == '.')) return false;
    }
    return true;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or !lowerAlphaNumeric(value[0])) return false;
    for (value) |byte| {
        if (!(lowerAlphaNumeric(byte) or byte == '-')) return false;
    }
    return true;
}

fn lowerAlphaNumeric(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or std.ascii.isDigit(byte);
}

fn pointSpan(position: deb822.Position) deb822.Span {
    return .{ .start = position, .end = position };
}

fn subSpan(parent: Text, child: []const u8) deb822.Span {
    const offset = @intFromPtr(child.ptr) - @intFromPtr(parent.value.ptr);
    return .{
        .start = .{
            .offset = parent.span.start.offset + offset,
            .line = parent.span.start.line,
            .column = parent.span.start.column + offset,
        },
        .end = .{
            .offset = parent.span.start.offset + offset + child.len,
            .line = parent.span.start.line,
            .column = parent.span.start.column + offset + child.len,
        },
    };
}

fn expectDatabase(source: []const u8, options: Options) !Database {
    const result = try parseBorrowed(std.testing.allocator, source, options);
    return switch (result) {
        .database => |database| database,
        .diagnostic => |diagnostic| {
            std.debug.print("unexpected status diagnostic {s} at {d}:{d}\n", .{
                diagnostic.message(),
                diagnostic.span.start.line,
                diagnostic.span.start.column,
            });
            return error.UnexpectedDiagnostic;
        },
    };
}

fn expectDiagnostic(source: []const u8, code: DiagnosticCode) !Diagnostic {
    const result = try parseBorrowed(std.testing.allocator, source, .{});
    return switch (result) {
        .diagnostic => |diagnostic| blk: {
            try std.testing.expectEqual(code, diagnostic.code);
            break :blk diagnostic;
        },
        .database => |database_value| {
            var database = database_value;
            database.deinit();
            return error.ExpectedDiagnostic;
        },
    };
}

test "installed fixture exposes typed package metadata and relations" {
    var database = try expectDatabase(@embedFile("fixtures/dpkg-status/installed.status"), .{});
    defer database.deinit();

    try std.testing.expectEqual(@as(usize, 2), database.packages.len);
    const package = database.find("debz", "amd64").?;
    try std.testing.expectEqualStrings("2:1.0~rc1-03", package.version.spelling.value);
    try std.testing.expectEqualStrings("03", package.version.parsed.revision.?);
    try std.testing.expect(package.status.isFullyInstalled());
    try std.testing.expect(!package.status.requiresRepair());
    try std.testing.expectEqual(true, package.essential.?);
    try std.testing.expectEqual(false, package.protected.?);
    try std.testing.expectEqual(Priority.required, package.priority.?);
    try std.testing.expectEqual(MultiArch.foreign, package.multi_arch.?);
    try std.testing.expectEqual(@as(u64, 4096), package.installed_size_kib.?);
    const depends = package.relation(.depends).?;
    try std.testing.expectEqual(@as(usize, 2), depends.relation.groups.len);
    try std.testing.expectEqualStrings("libc6", depends.relation.groups[0].alternatives[0].package.name.text);
}

test "state fixture distinguishes every transaction-relevant state" {
    var database = try expectDatabase(@embedFile("fixtures/dpkg-status/states.status"), .{});
    defer database.deinit();
    const expected = [_]CurrentState{
        .installed,
        .config_files,
        .unpacked,
        .half_configured,
        .triggers_awaited,
        .triggers_pending,
        .half_installed,
        .not_installed,
    };
    try std.testing.expectEqual(expected.len, database.packages.len);
    for (expected, database.packages) |state, package| {
        try std.testing.expectEqual(state, package.status.current);
    }
    try std.testing.expect(database.packages[3].status.requiresRepair());
    try std.testing.expectEqual(ErrorState.reinst_required, database.packages[6].status.error_state);
}

test "malformed fixture diagnostics retain source positions and primitive details" {
    const missing = try expectDiagnostic(
        "Package: x\nArchitecture: amd64\nStatus: install ok installed\n",
        .missing_version,
    );
    try std.testing.expectEqual(@as(usize, 1), missing.span.start.line);

    const status = try expectDiagnostic(
        "Package: x\nVersion: 1\nArchitecture: amd64\nStatus: install ok broken\n",
        .invalid_current_state,
    );
    try std.testing.expectEqual(@as(usize, 4), status.span.start.line);
    try std.testing.expectEqual(@as(usize, 20), status.span.start.column);

    const relation = try expectDiagnostic(
        "Package: x\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nDepends: good,\n bad |\n",
        .invalid_relation,
    );
    try std.testing.expectEqual(relation_module.DiagnosticCode.trailing_separator, relation.relation_code.?);
    try std.testing.expectEqual(@as(usize, 6), relation.span.start.line);
}

test "rejects malformed identity scalar and numeric fields" {
    const prefix = "Package: Bad\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n";
    _ = try expectDiagnostic(prefix, .invalid_package);
    _ = try expectDiagnostic(
        "Package: x\nVersion: bad\nArchitecture: amd64\nStatus: install ok installed\n",
        .invalid_version,
    );
    _ = try expectDiagnostic(
        "Package: x\nVersion: 1\nArchitecture: AMD64\nStatus: install ok installed\n",
        .invalid_architecture,
    );
    _ = try expectDiagnostic(
        "Package: x\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nInstalled-Size: -1\n",
        .invalid_installed_size,
    );
}

test "repeated identities follow the configured deterministic policy" {
    const source = @embedFile("fixtures/dpkg-status/repeated.status");
    _ = try expectDiagnostic(source, .repeated_identity);

    var first = try expectDatabase(source, .{ .repeated_identity = .keep_first });
    defer first.deinit();
    try std.testing.expectEqualStrings("1", first.packages[0].version.spelling.value);

    var last = try expectDatabase(source, .{ .repeated_identity = .keep_last });
    defer last.deinit();
    try std.testing.expectEqualStrings("2", last.packages[0].version.spelling.value);
}

test "configured limits are enforced by status and nested parsers" {
    const name_limit = try parseBorrowed(
        std.testing.allocator,
        "Package: toolong\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n",
        .{ .limits = .{ .max_package_name_bytes = 3 } },
    );
    try std.testing.expectEqual(DiagnosticCode.package_name_too_long, name_limit.diagnostic.code);
    const result = try parseBorrowed(
        std.testing.allocator,
        "Package: a\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n\n" ++
            "Package: b\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n",
        .{ .limits = .{ .max_packages = 1 } },
    );
    try std.testing.expectEqual(DiagnosticCode.too_many_packages, result.diagnostic.code);

    const relation_result = try parseBorrowed(
        std.testing.allocator,
        "Package: a\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\nDepends: abcdef\n",
        .{ .limits = .{ .relation = .{ .max_package_name_bytes = 3 } } },
    );
    try std.testing.expectEqual(DiagnosticCode.invalid_relation, relation_result.diagnostic.code);
    try std.testing.expectEqual(
        relation_module.DiagnosticCode.package_name_too_long,
        relation_result.diagnostic.relation_code.?,
    );
}

test "owned bytes API does not borrow caller storage" {
    var source = [_]u8{
        'P', 'a', 'c',  'k', 'a', 'g', 'e',  ':', ' ', 'x', '\n',
        'V', 'e', 'r',  's', 'i', 'o', 'n',  ':', ' ', '1', '\n',
        'A', 'r', 'c',  'h', 'i', 't', 'e',  'c', 't', 'u', 'r',
        'e', ':', ' ',  'a', 'l', 'l', '\n', 'S', 't', 'a', 't',
        'u', 's', ':',  ' ', 'i', 'n', 's',  't', 'a', 'l', 'l',
        ' ', 'o', 'k',  ' ', 'i', 'n', 's',  't', 'a', 'l', 'l',
        'e', 'd', '\n',
    };
    const result = try parseOwned(std.testing.allocator, &source, .{});
    var owned = result.database;
    defer owned.deinit();
    source[9] = 'y';
    try std.testing.expectEqualStrings("x", owned.database.packages[0].name.value);
}

test "file API reads only the explicit caller path" {
    const result = try parseFile(
        std.testing.allocator,
        std.testing.io,
        "src/fixtures/dpkg-status/installed.status",
        .{},
    );
    var owned = result.database;
    defer owned.deinit();
    try std.testing.expectEqual(@as(usize, 2), owned.database.packages.len);
}
