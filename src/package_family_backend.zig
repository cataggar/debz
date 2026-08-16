const std = @import("std");
const product = @import("product_api.zig");

pub const schema_version: u32 = 1;
pub const capability_schema = "io.github.cataggar.debz.package-family.capabilities.v1";
pub const request_schema = "io.github.cataggar.debz.package-family.request.v1";
pub const result_schema = "io.github.cataggar.debz.package-family.result.v1";
pub const provenance_basename = "transaction-result.json";

pub const Architecture = enum {
    amd64,
    arm64,

    pub fn spelling(self: Architecture) []const u8 {
        return @tagName(self);
    }
};

pub const Operation = enum {
    create,
    customize,
    update,
    recover,
    inspect,
};

pub const CacheMode = enum { online, prefer_cache, offline };
pub const RecoveryBehavior = enum { disposable_or_recoverable };

pub const Capabilities = struct {
    schema: []const u8 = capability_schema,
    version: u32 = schema_version,
    family: []const u8 = "debian",
    implementations: []const []const u8 = &.{ "ubuntu-26.04", "debian" },
    operations: []const []const u8 = &.{ "create", "customize", "update", "recover", "inspect" },
    architectures: []const []const u8 = &.{ "amd64", "arm64" },
    request_schema: []const u8 = request_schema,
    result_schema: []const u8 = result_schema,
    exact_lock_schema: []const u8 = "https://debz.dev/schema/exact-closure-lock-v1",
    provenance_schema: []const u8 = "https://debz.dev/schema/transaction-result-v1",
    recovery: RecoveryBehavior = .disposable_or_recoverable,
    invokes_apt: bool = false,

    pub fn canonicalJson(self: Capabilities, allocator: std.mem.Allocator) ![]u8 {
        return std.json.Stringify.valueAlloc(allocator, self, .{ .whitespace = .minified });
    }
};

pub fn capabilities() Capabilities {
    return .{};
}

/// Stable image-builder boundary. Every host-sensitive input is explicit;
/// debz never inherits repository, trust, proxy, cache, state, or root policy.
pub const Request = struct {
    schema: []const u8 = request_schema,
    version: u32 = schema_version,
    operation: Operation,
    root: []const u8,
    architecture: Architecture,
    foreign_architectures: []const Architecture = &.{},
    sources: []const []const u8,
    keyrings: []const []const u8,
    configs: []const []const u8 = &.{},
    cache: []const u8,
    state: []const u8,
    package: ?[]const u8 = null,
    lock_input: ?[]const u8 = null,
    lock_output: ?[]const u8 = null,
    cache_mode: CacheMode = .online,
    repository_policy: product.RepositoryPolicy = .strict_priority,
    recommends: bool = false,
    allow_downgrade: bool = false,
    conffile: product.ConffilePolicy = .keep_existing,
    credential_reference: ?[]const u8 = null,
    proxy: ?[]const u8 = null,
    deadline_ms: u64 = 300_000,
    lock_wait_ms: u64 = 30_000,
};

pub const ErrorId = enum {
    invalid_request,
    unsupported_architecture,
    backend_failed,
    lock_not_emitted,
    provenance_not_emitted,
};

pub const Diagnostic = struct {
    id: ErrorId,
    message: []const u8,
    recoverable: bool,
};

pub const Result = struct {
    schema: []const u8 = result_schema,
    version: u32 = schema_version,
    operation: Operation,
    succeeded: bool,
    changed: bool = false,
    exit_status: product.ExitStatus,
    lock_path: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
    diagnostic: ?Diagnostic = null,
};

pub const Backend = struct {
    product_backend: product.Backend,

    pub fn execute(self: Backend, allocator: std.mem.Allocator, request: Request) !Result {
        if (!validRequest(request))
            return failure(request.operation, .usage, .invalid_request, "invalid explicit package-family request", false);

        const operation: product.Operation = switch (request.operation) {
            .create, .customize => .install,
            .update => if (request.package == null) .upgrade_all else .upgrade,
            .recover => .recover,
            .inspect => .list_installed,
        };
        const packages: []const []const u8 = if (request.package) |package|
            try allocator.dupe([]const u8, &.{package})
        else
            &.{};
        defer if (request.package != null) allocator.free(packages);

        const offline = request.cache_mode == .offline;
        const response = try product.execute(allocator, .{
            .operation = operation,
            .packages = packages,
            .options = .{
                .install_root = request.root,
                .source_paths = request.sources,
                .config_paths = request.configs,
                .keyring_paths = request.keyrings,
                .cache_path = request.cache,
                .state_path = request.state,
                .architecture = request.architecture.spelling(),
                .repository_policy = request.repository_policy,
                .proxy = request.proxy,
                .credential_reference = request.credential_reference,
                .lock_input_path = request.lock_input,
                .lock_output_path = request.lock_output,
                .offline = offline,
                .cache_only = offline,
                .recommends = request.recommends,
                .allow_downgrade = request.allow_downgrade,
                .deadline_ms = request.deadline_ms,
                .lock_wait_ms = request.lock_wait_ms,
                .assume_yes = operation.mutates(),
                .noninteractive = operation.mutates(),
                .conffile = request.conffile,
            },
        }, self.product_backend);
        if (response.exit_status != .success) {
            return failure(
                request.operation,
                response.exit_status,
                .backend_failed,
                response.summary,
                response.exit_status == .transaction or response.exit_status == .recovery,
            );
        }
        const provenance_path = if (operation.mutates() and operation != .recover and request.lock_input != null)
            try std.fmt.allocPrint(allocator, "{s}/{s}", .{ request.state, provenance_basename })
        else
            null;
        return .{
            .operation = request.operation,
            .succeeded = true,
            .changed = response.changed,
            .exit_status = .success,
            .lock_path = request.lock_output orelse request.lock_input,
            .provenance_path = provenance_path,
        };
    }
};

fn validRequest(request: Request) bool {
    if (!std.mem.eql(u8, request.schema, request_schema) or request.version != schema_version) return false;
    if (!absolute(request.root) or !absolute(request.cache) or !absolute(request.state)) return false;
    if (request.sources.len == 0 or request.keyrings.len == 0 or request.deadline_ms == 0) return false;
    for (request.sources) |path| if (!absolute(path)) return false;
    for (request.configs) |path| if (!absolute(path)) return false;
    for (request.keyrings) |path| if (!absolute(path)) return false;
    for (request.foreign_architectures) |architecture|
        if (architecture == request.architecture) return false;
    if ((request.operation == .create or request.operation == .customize) and request.package == null) return false;
    if (request.operation == .recover and request.lock_input == null) return false;
    if (request.lock_output != null and request.lock_input == null) return false;
    if (request.lock_input) |path| if (!absolute(path)) return false;
    if (request.lock_output) |path| if (!absolute(path)) return false;
    if (request.credential_reference) |path| if (!absolute(path)) return false;
    return true;
}

fn absolute(path: []const u8) bool {
    return path.len > 1 and path[0] == '/' and path[path.len - 1] != '/';
}

fn failure(
    operation: Operation,
    status: product.ExitStatus,
    id: ErrorId,
    message: []const u8,
    recoverable: bool,
) Result {
    return .{
        .operation = operation,
        .succeeded = false,
        .exit_status = status,
        .diagnostic = .{ .id = id, .message = message, .recoverable = recoverable },
    };
}

const Fake = struct {
    seen: bool = false,
    operation: ?product.Operation = null,

    fn execute(context: *anyopaque, _: std.mem.Allocator, request: product.Request) !product.Result {
        const self: *Fake = @ptrCast(@alignCast(context));
        self.seen = true;
        self.operation = request.operation;
        try std.testing.expectEqualStrings("arm64", request.options.architecture);
        try std.testing.expect(request.options.cache_only);
        try std.testing.expectEqualStrings("ubuntu-minimal", request.packages[0]);
        return .{
            .operation = request.operation,
            .exit_status = .success,
            .changed = request.operation.mutates(),
            .summary = "ok",
        };
    }
};

test "capabilities are versioned and apt-free" {
    const value = capabilities();
    try std.testing.expectEqual(schema_version, value.version);
    try std.testing.expect(!value.invokes_apt);
    try std.testing.expectEqualStrings("amd64", value.architectures[0]);
    try std.testing.expectEqualStrings("arm64", value.architectures[1]);
}

test "Ubuntu create maps explicit policy to product API" {
    var fake: Fake = .{};
    const backend: Backend = .{ .product_backend = .{ .context = &fake, .executeFn = Fake.execute } };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .create,
        .root = "/build/root",
        .architecture = .arm64,
        .foreign_architectures = &.{.amd64},
        .sources = &.{"/build/sources"},
        .keyrings = &.{"/build/keyring.gpg"},
        .cache = "/build/cache",
        .state = "/build/state",
        .package = "ubuntu-minimal",
        .lock_input = "/build/core.lock.json",
        .cache_mode = .offline,
    });
    defer if (result.provenance_path) |path| std.testing.allocator.free(path);
    try std.testing.expect(result.succeeded);
    try std.testing.expectEqual(product.Operation.install, fake.operation.?);
}

test "mutations fail closed without required explicit inputs" {
    var fake: Fake = .{};
    const backend: Backend = .{ .product_backend = .{ .context = &fake, .executeFn = Fake.execute } };
    const result = try backend.execute(std.testing.allocator, .{
        .operation = .create,
        .root = "/build/root",
        .architecture = .amd64,
        .sources = &.{},
        .keyrings = &.{},
        .cache = "/build/cache",
        .state = "/build/state",
        .package = "ubuntu-minimal",
    });
    try std.testing.expect(!result.succeeded);
    try std.testing.expectEqual(ErrorId.invalid_request, result.diagnostic.?.id);
    try std.testing.expect(!fake.seen);
}
