const std = @import("std");

pub const api_version: u32 = 1;
pub const json_schema = "io.github.cataggar.debz.command.v1";

pub const Operation = enum {
    refresh,
    install,
    remove,
    upgrade,
    upgrade_all,
    reinstall,
    download,
    plan,
    list_installed,
    list_available,
    info,
    provides,
    why,
    clean,
    recover,

    pub fn spelling(self: Operation) []const u8 {
        return switch (self) {
            .upgrade_all => "upgrade-all",
            .list_installed => "list-installed",
            .list_available => "list-available",
            else => @tagName(self),
        };
    }

    pub fn mutates(self: Operation) bool {
        return switch (self) {
            .refresh, .install, .remove, .upgrade, .upgrade_all, .reinstall, .clean, .recover => true,
            .download, .plan, .list_installed, .list_available, .info, .provides, .why => false,
        };
    }
};

pub const OutputFormat = enum { human, json };
pub const RepositoryPolicy = enum { strict_priority, best_version };
pub const ConffilePolicy = enum { unspecified, keep_existing, use_package_version };
pub const ForcePolicy = enum {
    depends,
    depends_version,
    break_replaces,
    overwrite,
    overwrite_dir,
    remove_reinstreq,
};

/// All paths and external policy inputs are explicit. An empty optional path
/// means the corresponding input is unavailable; it never selects a host
/// default.
pub const CommonOptions = struct {
    install_root: []const u8,
    source_paths: []const []const u8 = &.{},
    config_paths: []const []const u8 = &.{},
    keyring_paths: []const []const u8 = &.{},
    cache_path: []const u8,
    state_path: []const u8,
    status_path: ?[]const u8 = null,
    architecture: []const u8,
    foreign_architectures: []const []const u8 = &.{},
    default_release: ?[]const u8 = null,
    repository_policy: RepositoryPolicy = .strict_priority,
    proxy: ?[]const u8 = null,
    credential_reference: ?[]const u8 = null,
    lock_input_path: ?[]const u8 = null,
    lock_output_path: ?[]const u8 = null,
    output: OutputFormat = .human,
    offline: bool = false,
    cache_only: bool = false,
    recommends: bool = false,
    allow_downgrade: bool = false,
    deadline_ms: ?u64 = null,
    lock_wait_ms: u64 = 30_000,
    assume_yes: bool = false,
    noninteractive: bool = false,
    conffile: ConffilePolicy = .unspecified,
    force: []const ForcePolicy = &.{},
};

pub const Request = struct {
    api_version: u32 = api_version,
    operation: Operation,
    packages: []const []const u8 = &.{},
    options: CommonOptions,
};

pub const ExitStatus = enum(u8) {
    success = 0,
    usage = 2,
    unavailable = 3,
    authentication = 4,
    planning = 5,
    download = 6,
    transaction = 7,
    recovery = 8,
    internal = 70,
};

pub const ErrorId = enum {
    unsupported_api_version,
    invalid_request,
    confirmation_required,
    conffile_policy_required,
    configuration_required,
    repository_authentication_failed,
    offline_cache_miss,
    planning_failed,
    download_failed,
    transaction_backend_unavailable,
    transaction_failed,
    recovery_failed,
    root_operation_conflict,
    root_operation_recovery_required,
    lock_verification_failed,
    internal_error,
};

pub const Diagnostic = struct {
    id: ErrorId,
    message: []const u8,
};

pub const Item = struct {
    package: []const u8,
    version: ?[]const u8 = null,
    architecture: ?[]const u8 = null,
    detail: ?[]const u8 = null,
};

pub const Result = struct {
    api_version: u32 = api_version,
    operation: Operation,
    exit_status: ExitStatus,
    changed: bool = false,
    summary: []const u8,
    items: []const Item = &.{},
    diagnostics: [1]Diagnostic = undefined,
    diagnostic_count: usize = 0,

    pub fn canonicalJson(self: Result, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        const writer = &output.writer;
        try writer.writeAll("{\"schema\":\"");
        try writer.writeAll(json_schema);
        try writer.writeAll("\",\"api_version\":");
        try writer.print("{d}", .{self.api_version});
        try writer.writeAll(",\"operation\":");
        try writeJsonString(writer, self.operation.spelling());
        try writer.writeAll(",\"exit_status\":");
        try writer.print("{d}", .{@intFromEnum(self.exit_status)});
        try writer.writeAll(",\"changed\":");
        try writer.writeAll(if (self.changed) "true" else "false");
        try writer.writeAll(",\"summary\":");
        try writeJsonString(writer, self.summary);
        try writer.writeAll(",\"items\":[");
        for (self.items, 0..) |item, index| {
            if (index != 0) try writer.writeByte(',');
            try writer.writeAll("{\"package\":");
            try writeJsonString(writer, item.package);
            try writer.writeAll(",\"version\":");
            if (item.version) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
            try writer.writeAll(",\"architecture\":");
            if (item.architecture) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
            try writer.writeAll(",\"detail\":");
            if (item.detail) |value| try writeJsonString(writer, value) else try writer.writeAll("null");
            try writer.writeByte('}');
        }
        try writer.writeAll("],\"diagnostics\":[");
        for (self.diagnostics[0..self.diagnostic_count], 0..) |diagnostic, index| {
            if (index != 0) try writer.writeByte(',');
            try writer.writeAll("{\"id\":");
            try writeJsonString(writer, @tagName(diagnostic.id));
            try writer.writeAll(",\"message\":");
            try writeJsonString(writer, diagnostic.message);
            try writer.writeByte('}');
        }
        try writer.writeAll("]}\n");
        return output.toOwnedSlice();
    }
};

pub const Backend = struct {
    context: *anyopaque,
    executeFn: *const fn (*anyopaque, std.mem.Allocator, Request) anyerror!Result,

    pub fn execute(self: Backend, allocator: std.mem.Allocator, request: Request) !Result {
        return self.executeFn(self.context, allocator, request);
    }
};

pub fn execute(allocator: std.mem.Allocator, request: Request, backend: Backend) !Result {
    if (request.api_version != api_version)
        return failure(request.operation, .usage, .unsupported_api_version, "unsupported library API version");
    if (!validAbsolutePath(request.options.install_root) or
        !validAbsolutePath(request.options.cache_path) or
        !validAbsolutePath(request.options.state_path) or
        (request.options.status_path != null and !validAbsolutePath(request.options.status_path.?)) or
        (request.options.credential_reference != null and !validAbsolutePath(request.options.credential_reference.?)) or
        !validPaths(request.options.source_paths) or
        !validPaths(request.options.config_paths) or
        !validPaths(request.options.keyring_paths) or
        (request.options.lock_input_path != null and !validAbsolutePath(request.options.lock_input_path.?)) or
        (request.options.lock_output_path != null and !validAbsolutePath(request.options.lock_output_path.?)) or
        !validArchitecture(request.options.architecture) or
        !validForeignArchitectures(request.options.architecture, request.options.foreign_architectures) or
        (request.options.deadline_ms != null and request.options.deadline_ms.? == 0))
        return failure(request.operation, .usage, .invalid_request, "invalid explicit path, architecture, or deadline");
    if (!validPackages(request))
        return failure(request.operation, .usage, .invalid_request, "invalid package argument count or spelling");
    if (request.options.cache_only and !request.options.offline)
        return failure(request.operation, .usage, .invalid_request, "cache-only requires offline mode");
    if (request.operation.mutates() and request.options.status_path != null)
        return failure(request.operation, .usage, .invalid_request, "--status-path is read-only and cannot verify a mutation");
    if (request.operation.mutates() and !request.options.assume_yes)
        return failure(request.operation, .usage, .confirmation_required, "mutating command requires --assume-yes");
    if (request.operation.mutates() and request.operation != .refresh and request.operation != .clean and
        request.options.noninteractive and request.options.conffile == .unspecified)
        return failure(request.operation, .usage, .conffile_policy_required, "noninteractive mutation requires an explicit conffile policy");
    return backend.execute(allocator, request);
}

pub fn failure(operation: Operation, status: ExitStatus, id: ErrorId, message: []const u8) Result {
    return .{
        .operation = operation,
        .exit_status = status,
        .summary = message,
        .diagnostics = .{.{ .id = id, .message = message }},
        .diagnostic_count = 1,
    };
}

pub fn redact(allocator: std.mem.Allocator, input: []const u8) ![]u8 {
    if (std.Uri.parse(input)) |uri| {
        if (uri.user != null or uri.password != null) {
            if (uri.host == null) return allocator.dupe(u8, "<redacted-uri>");
            return std.fmt.allocPrint(allocator, "{s}://<redacted>@<redacted-host>", .{uri.scheme});
        }
    } else |_| {}
    return allocator.dupe(u8, input);
}

fn validPackages(request: Request) bool {
    const count_ok = switch (request.operation) {
        .install, .remove, .reinstall, .download => request.packages.len == 1,
        .info, .provides, .why => request.packages.len != 0,
        .plan => request.packages.len <= 1,
        .upgrade => true,
        .refresh, .upgrade_all, .list_installed, .list_available, .clean, .recover => request.packages.len == 0,
    };
    if (!count_ok) return false;
    for (request.packages) |package| {
        if (package.len == 0 or package.len > 255 or package[0] == '-') return false;
        for (package) |character| if (!(std.ascii.isAlphanumeric(character) or
            character == '+' or character == '-' or character == '.' or character == ':' or character == '='))
            return false;
    }
    return true;
}

fn validAbsolutePath(path: []const u8) bool {
    if (path.len <= 1 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component|
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return false;
    return true;
}

fn validForeignArchitectures(native: []const u8, foreign: []const []const u8) bool {
    for (foreign, 0..) |architecture, index| {
        if (!validArchitecture(architecture) or std.mem.eql(u8, native, architecture)) return false;
        for (foreign[0..index]) |prior|
            if (std.mem.eql(u8, prior, architecture)) return false;
    }
    return true;
}

fn validPaths(paths: []const []const u8) bool {
    for (paths) |path| if (!validAbsolutePath(path)) return false;
    return true;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or value.len > 64) return false;
    for (value) |character| if (!(std.ascii.isAlphanumeric(character) or character == '-')) return false;
    return true;
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |character| switch (character) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...8, 11, 12, 14...0x1f => try writer.print("\\u{x:0>4}", .{character}),
        else => try writer.writeByte(character),
    };
    try writer.writeByte('"');
}

test "canonical result JSON is stable" {
    const result: Result = .{
        .operation = .info,
        .exit_status = .success,
        .summary = "ok",
        .items = &.{.{ .package = "demo", .version = "1", .architecture = "amd64" }},
    };
    const json = try result.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expectEqualStrings(
        "{\"schema\":\"io.github.cataggar.debz.command.v1\",\"api_version\":1,\"operation\":\"info\",\"exit_status\":0,\"changed\":false,\"summary\":\"ok\",\"items\":[{\"package\":\"demo\",\"version\":\"1\",\"architecture\":\"amd64\",\"detail\":null}],\"diagnostics\":[]}\n",
        json,
    );
}

test "facade validates confirmation before backend routing" {
    var called = false;
    const Fake = struct {
        fn run(context: *anyopaque, _: std.mem.Allocator, request: Request) !Result {
            const flag: *bool = @ptrCast(@alignCast(context));
            flag.* = true;
            return .{ .operation = request.operation, .exit_status = .success, .summary = "ok" };
        }

        test "redaction removes URI user information" {
            const value = try redact(std.testing.allocator, "https://user:secret@example.invalid/path");
            defer std.testing.allocator.free(value);
            try std.testing.expect(std.mem.indexOf(u8, value, "secret") == null);
            try std.testing.expect(std.mem.indexOf(u8, value, "user") == null);
        }
    };
    const request: Request = .{
        .operation = .install,
        .packages = &.{"demo"},
        .options = .{ .install_root = "/root", .cache_path = "/cache", .state_path = "/state", .architecture = "amd64" },
    };
    const result = try execute(std.testing.allocator, request, .{ .context = &called, .executeFn = Fake.run });
    try std.testing.expectEqual(@as(usize, 1), result.diagnostic_count);
    try std.testing.expectEqual(ErrorId.confirmation_required, result.diagnostics[0].id);
    try std.testing.expect(!called);
}

test "facade rejects ambiguous paths, external mutation status, and ignored package arguments" {
    var called = false;
    const Fake = struct {
        fn run(context: *anyopaque, _: std.mem.Allocator, request: Request) !Result {
            const flag: *bool = @ptrCast(@alignCast(context));
            flag.* = true;
            return .{ .operation = request.operation, .exit_status = .success, .summary = "ok" };
        }
    };
    const backend: Backend = .{ .context = &called, .executeFn = Fake.run };
    const invalid_path = try execute(std.testing.allocator, .{
        .operation = .list_available,
        .options = .{
            .install_root = "/root",
            .source_paths = &.{"/config/../sources.list"},
            .cache_path = "/cache",
            .state_path = "/state",
            .architecture = "amd64",
        },
    }, backend);
    try std.testing.expectEqual(ErrorId.invalid_request, invalid_path.diagnostics[0].id);
    const external_status = try execute(std.testing.allocator, .{
        .operation = .clean,
        .options = .{
            .install_root = "/root",
            .cache_path = "/cache",
            .state_path = "/state",
            .status_path = "/status",
            .architecture = "amd64",
            .assume_yes = true,
        },
    }, backend);
    try std.testing.expectEqual(ErrorId.invalid_request, external_status.diagnostics[0].id);
    const extra_package = try execute(std.testing.allocator, .{
        .operation = .install,
        .packages = &.{ "one", "two" },
        .options = .{
            .install_root = "/root",
            .cache_path = "/cache",
            .state_path = "/state",
            .architecture = "amd64",
            .assume_yes = true,
        },
    }, backend);
    try std.testing.expectEqual(ErrorId.invalid_request, extra_package.diagnostics[0].id);
    try std.testing.expect(!called);
}
