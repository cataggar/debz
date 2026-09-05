const std = @import("std");
const absolute_path = @import("absolute_path.zig");
const product_api = @import("product_api.zig");
const solver = @import("solver.zig");
const transaction_provenance_v3 = @import("transaction_provenance_v3.zig");

pub const schema_id = "https://debz.dev/schema/system-operation-lock-v2";
pub const schema_version: u32 = 2;
pub const maximum_document_bytes: usize = 40 * 1024 * 1024;
pub const maximum_actions: usize = 100_000;

pub const PackageLockKind = enum {
    none,
    exact_v1,
    exact_v2,
};

pub const Action = struct {
    kind: solver.ActionKind,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
};

pub const Input = struct {
    attempt_id: [32]u8,
    operation: product_api.Operation,
    install_root: []const u8,
    state_path: []const u8,
    target_architecture: []const u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    executor_policy_sha256: [32]u8,
    plan_sha256: [32]u8,
    package_lock_kind: PackageLockKind,
    package_lock_sha256: ?[32]u8,
    actions: []const Action,
    repository_refresh: []const transaction_provenance_v3.RepositoryRefreshEvidence,
};

pub const Lock = struct {
    attempt_id: [32]u8,
    operation: product_api.Operation,
    install_root: []const u8,
    state_path: []const u8,
    target_architecture: []const u8,
    request_sha256: [32]u8,
    solver_policy_sha256: [32]u8,
    executor_policy_sha256: [32]u8,
    plan_sha256: [32]u8,
    package_lock_kind: PackageLockKind,
    package_lock_sha256: ?[32]u8,
    actions: []const Action,
    repository_refresh: []const transaction_provenance_v3.RepositoryRefreshEvidence,
    digest_sha256: [32]u8,

    pub fn canonicalJson(self: Lock, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        return output.toOwnedSlice();
    }
};

pub const OwnedLock = struct {
    lock: Lock,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedLock) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn create(allocator: std.mem.Allocator, input: Input) !OwnedLock {
    if (!input.operation.mutates() or input.operation == .refresh or
        input.operation == .clean or input.operation == .recover)
        return error.InvalidOperation;
    if (!absolute_path.root(input.install_root) or
        !absolute_path.nonRoot(input.state_path) or
        !validToken(input.target_architecture) or input.actions.len == 0 or
        input.actions.len > maximum_actions)
        return error.InvalidIdentity;
    if ((input.package_lock_kind == .none) !=
        (input.package_lock_sha256 == null))
        return error.InvalidPackageLock;
    var archive_action_count: usize = 0;
    for (input.actions) |action| {
        if (action.kind != .remove) archive_action_count += 1;
    }
    if (archive_action_count != 0 and input.package_lock_kind == .none)
        return error.InvalidPackageLock;
    if (input.repository_refresh.len >
        transaction_provenance_v3.maximum_repositories)
        return error.TooManyRepositories;
    if (input.package_lock_kind != .exact_v2 and
        input.repository_refresh.len != 0)
        return error.InvalidRefreshEvidence;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const actions = try owned.alloc(Action, input.actions.len);
    for (input.actions, 0..) |action, index| {
        if (!validToken(action.package) or !validToken(action.version) or
            !validToken(action.architecture))
            return error.InvalidIdentity;
        actions[index] = .{
            .kind = action.kind,
            .package = try owned.dupe(u8, action.package),
            .version = try owned.dupe(u8, action.version),
            .architecture = try owned.dupe(u8, action.architecture),
        };
        for (actions[0..index]) |prior| {
            if (std.mem.eql(u8, prior.package, action.package) and
                std.mem.eql(u8, prior.architecture, action.architecture))
                return error.DuplicateAction;
        }
    }
    const repository_refresh = try owned.alloc(
        transaction_provenance_v3.RepositoryRefreshEvidence,
        input.repository_refresh.len,
    );
    for (input.repository_refresh, 0..) |evidence, index| {
        try transaction_provenance_v3.validateRepositoryRefreshEvidence(
            evidence,
        );
        repository_refresh[index] = evidence;
        repository_refresh[index].selected_packages_path = try owned.dupe(
            u8,
            evidence.selected_packages_path,
        );
    }
    std.mem.sort(
        transaction_provenance_v3.RepositoryRefreshEvidence,
        repository_refresh,
        {},
        transaction_provenance_v3.lessRepository,
    );
    for (repository_refresh, 0..) |repository, index| {
        if (index != 0 and std.mem.eql(
            u8,
            &repository.source_config_id,
            &repository_refresh[index - 1].source_config_id,
        )) return error.DuplicateRepository;
    }
    var lock: Lock = .{
        .attempt_id = input.attempt_id,
        .operation = input.operation,
        .install_root = try owned.dupe(u8, input.install_root),
        .state_path = try owned.dupe(u8, input.state_path),
        .target_architecture = try owned.dupe(u8, input.target_architecture),
        .request_sha256 = input.request_sha256,
        .solver_policy_sha256 = input.solver_policy_sha256,
        .executor_policy_sha256 = input.executor_policy_sha256,
        .plan_sha256 = input.plan_sha256,
        .package_lock_kind = input.package_lock_kind,
        .package_lock_sha256 = input.package_lock_sha256,
        .actions = actions,
        .repository_refresh = repository_refresh,
        .digest_sha256 = undefined,
    };
    lock.digest_sha256 = digestPayload(lock);
    return .{
        .lock = lock,
        .arena = arena,
        .backing_allocator = allocator,
    };
}

const WireAction = struct {
    kind: solver.ActionKind,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
};

const WireLock = struct {
    schema: []const u8,
    version: u32,
    attempt_id: []const u8,
    operation: product_api.Operation,
    install_root: []const u8,
    state_path: []const u8,
    target_architecture: []const u8,
    request_sha256: []const u8,
    solver_policy_sha256: []const u8,
    executor_policy_sha256: []const u8,
    plan_sha256: []const u8,
    package_lock_kind: PackageLockKind,
    package_lock_sha256: ?[]const u8,
    actions: []const WireAction,
    repository_refresh: []const std.json.Value,
    digest_sha256: []const u8,
};

pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !OwnedLock {
    if (source.len > maximum_bytes or source.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(WireLock, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.schema, schema_id) or
        parsed.value.version != schema_version)
        return error.UnsupportedSchema;
    const actions = try allocator.alloc(Action, parsed.value.actions.len);
    defer allocator.free(actions);
    for (parsed.value.actions, 0..) |action, index| actions[index] = .{
        .kind = action.kind,
        .package = action.package,
        .version = action.version,
        .architecture = action.architecture,
    };
    const refresh = try allocator.alloc(
        transaction_provenance_v3.RepositoryRefreshEvidence,
        parsed.value.repository_refresh.len,
    );
    defer allocator.free(refresh);
    for (parsed.value.repository_refresh, 0..) |value, index|
        refresh[index] =
            try transaction_provenance_v3.parseRepositoryRefreshEvidence(
                value,
            );
    var result = try create(allocator, .{
        .attempt_id = try parseDigest(parsed.value.attempt_id),
        .operation = parsed.value.operation,
        .install_root = parsed.value.install_root,
        .state_path = parsed.value.state_path,
        .target_architecture = parsed.value.target_architecture,
        .request_sha256 = try parseDigest(parsed.value.request_sha256),
        .solver_policy_sha256 = try parseDigest(
            parsed.value.solver_policy_sha256,
        ),
        .executor_policy_sha256 = try parseDigest(
            parsed.value.executor_policy_sha256,
        ),
        .plan_sha256 = try parseDigest(parsed.value.plan_sha256),
        .package_lock_kind = parsed.value.package_lock_kind,
        .package_lock_sha256 = if (parsed.value.package_lock_sha256) |value|
            try parseDigest(value)
        else
            null,
        .actions = actions,
        .repository_refresh = refresh,
    });
    errdefer result.deinit();
    const expected = try parseDigest(parsed.value.digest_sha256);
    if (!std.mem.eql(u8, &expected, &result.lock.digest_sha256))
        return error.DigestMismatch;
    const canonical = try result.lock.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source))
        return error.NonCanonicalDocument;
    return result;
}

pub const Store = struct {
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,

    pub fn init(io: std.Io, dir: std.Io.Dir, name: []const u8) !Store {
        if (!safeLeaf(name)) return error.InvalidPath;
        return .{ .io = io, .dir = dir, .name = name };
    }

    pub fn read(self: Store, allocator: std.mem.Allocator) !OwnedLock {
        var file = try self.dir.openFile(self.io, self.name, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const source = try reader.interface.allocRemaining(
            allocator,
            .limited(maximum_document_bytes),
        );
        defer allocator.free(source);
        return decode(allocator, source, maximum_document_bytes);
    }

    pub fn writeAtomic(
        self: Store,
        allocator: std.mem.Allocator,
        lock: Lock,
    ) !void {
        const bytes = try lock.canonicalJson(allocator);
        defer allocator.free(bytes);
        const stage = ".system-operation-lock.new";
        self.dir.deleteFile(self.io, stage) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        {
            var file = try self.dir.createFile(self.io, stage, .{
                .exclusive = true,
                .permissions = if (@import("builtin").os.tag == .windows)
                    .default_file
                else
                    .fromMode(0o600),
                .resolve_beneath = true,
            });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, bytes);
            try file.sync(self.io);
        }
        try self.dir.rename(stage, self.dir, self.name, self.io);
        try syncDirectory(self.dir);
    }
};

fn writeDocument(lock: Lock, writer: *std.Io.Writer) !void {
    try writePayload(lock, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHex(writer, &lock.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(lock: Lock, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeString(writer, schema_id);
    try writer.print(",\"version\":{},\"attempt_id\":", .{schema_version});
    try writeHex(writer, &lock.attempt_id);
    try writer.writeAll(",\"operation\":");
    try writeString(writer, lock.operation.spelling());
    try writer.writeAll(",\"install_root\":");
    try writeString(writer, lock.install_root);
    try writer.writeAll(",\"state_path\":");
    try writeString(writer, lock.state_path);
    try writer.writeAll(",\"target_architecture\":");
    try writeString(writer, lock.target_architecture);
    inline for (.{
        .{ "request_sha256", lock.request_sha256 },
        .{ "solver_policy_sha256", lock.solver_policy_sha256 },
        .{ "executor_policy_sha256", lock.executor_policy_sha256 },
        .{ "plan_sha256", lock.plan_sha256 },
    }) |field| {
        try writer.print(",\"{s}\":", .{field[0]});
        try writeHex(writer, &field[1]);
    }
    try writer.writeAll(",\"package_lock_kind\":");
    try writeString(writer, @tagName(lock.package_lock_kind));
    try writer.writeAll(",\"package_lock_sha256\":");
    if (lock.package_lock_sha256) |digest|
        try writeHex(writer, &digest)
    else
        try writer.writeAll("null");
    try writer.writeAll(",\"actions\":[");
    for (lock.actions, 0..) |action, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"kind\":");
        try writeString(writer, @tagName(action.kind));
        try writer.writeAll(",\"package\":");
        try writeString(writer, action.package);
        try writer.writeAll(",\"version\":");
        try writeString(writer, action.version);
        try writer.writeAll(",\"architecture\":");
        try writeString(writer, action.architecture);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"repository_refresh\":[");
    for (lock.repository_refresh, 0..) |repository, index| {
        if (index != 0) try writer.writeByte(',');
        try transaction_provenance_v3.writeRepositoryRefreshEvidence(
            writer,
            repository,
        );
    }
    try writer.writeAll("]}");
}

fn digestPayload(lock: Lock) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) =
        .init(&buffer);
    writePayload(lock, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn parseDigest(value: []const u8) ![32]u8 {
    if (value.len != 64) return error.InvalidDigest;
    var result: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return error.InvalidDigest;
    }
    return result;
}

fn validToken(value: []const u8) bool {
    if (value.len == 0 or value.len > 4096) return false;
    for (value) |byte| if (byte < 0x20 or byte == 0x7f) return false;
    return true;
}

pub fn statePath(
    allocator: std.mem.Allocator,
    install_root: []const u8,
) ![]u8 {
    if (!absolute_path.root(install_root)) return error.InvalidPath;
    if (std.mem.eql(u8, install_root, "/"))
        return allocator.dupe(u8, "/var/lib/debz");
    return std.fmt.allocPrint(
        allocator,
        "{s}/var/lib/debz",
        .{install_root},
    );
}

pub fn guardPath(
    allocator: std.mem.Allocator,
    install_root: []const u8,
) ![]u8 {
    if (!absolute_path.root(install_root)) return error.InvalidPath;
    if (std.mem.eql(u8, install_root, "/"))
        return allocator.dupe(u8, "/var/lib/debz/system-operation.lock");
    return std.fmt.allocPrint(
        allocator,
        "{s}/var/lib/debz/system-operation.lock",
        .{install_root},
    );
}

fn safeLeaf(value: []const u8) bool {
    return validToken(value) and
        !std.mem.eql(u8, value, ".") and
        !std.mem.eql(u8, value, "..") and
        std.mem.indexOfAny(u8, value, "/\\") == null;
}

fn syncDirectory(dir: std.Io.Dir) !void {
    switch (@import("builtin").os.tag) {
        .linux => if (std.posix.errno(std.os.linux.fsync(dir.handle)) !=
            .SUCCESS) return error.Unexpected,
        else => {},
    }
}

fn writeHex(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 0x0f]);
    }
    try writer.writeByte('"');
}

fn writeString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...8, 11, 12, 14...31 => try writer.print(
            "\\u00{x:0>2}",
            .{byte},
        ),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

test "system_operation_lock remove-only round trips canonically" {
    var lock = try create(std.testing.allocator, .{
        .attempt_id = @splat(0xaa),
        .operation = .remove,
        .install_root = "/",
        .state_path = "/var/lib/debz",
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .solver_policy_sha256 = @splat(2),
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .package_lock_kind = .none,
        .package_lock_sha256 = null,
        .actions = &.{.{
            .kind = .remove,
            .package = "old",
            .version = "1",
            .architecture = "amd64",
        }},
        .repository_refresh = &.{},
    });
    defer lock.deinit();
    const json = try lock.lock.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    var decoded = try decode(
        std.testing.allocator,
        json,
        maximum_document_bytes,
    );
    defer decoded.deinit();
    try std.testing.expectEqual(solver.ActionKind.remove, decoded.lock.actions[0].kind);
}

test "system_operation_lock binds action request and policies" {
    const action = Action{
        .kind = .install,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
    };
    const refresh =
        transaction_provenance_v3.RepositoryRefreshEvidence{
            .source_config_id = @splat('a'),
            .snapshot_sha256 = @splat(7),
            .signed_release_date_unix = 1_000,
            .valid_until_unix = 2_000,
            .verification_time_unix = 1_100,
            .maximum_future_seconds = 300,
            .future_date_accepted = false,
            .observed_release_age_seconds = 100,
            .expiry_policy = .require_valid_until,
            .maximum_release_age_seconds = null,
            .missing_valid_until_exception_exercised = false,
            .selected_packages_path = "main/binary-amd64/Packages.gz",
            .compression = .gzip,
        };
    var first = try create(std.testing.allocator, .{
        .attempt_id = @splat(0xaa),
        .operation = .install,
        .install_root = "/",
        .state_path = "/var/lib/debz",
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .solver_policy_sha256 = @splat(2),
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .package_lock_kind = .exact_v2,
        .package_lock_sha256 = @splat(5),
        .actions = &.{action},
        .repository_refresh = &.{refresh},
    });
    defer first.deinit();
    var changed = action;
    changed.version = "2";
    inline for (.{
        "attempt",
        "state",
        "action",
        "request",
        "solver-policy",
        "executor-policy",
        "freshness",
    }) |kind| {
        var changed_refresh = refresh;
        changed_refresh.verification_time_unix += 1;
        changed_refresh.observed_release_age_seconds += 1;
        var input = Input{
            .attempt_id = @splat(0xaa),
            .operation = .install,
            .install_root = "/",
            .state_path = "/var/lib/debz",
            .target_architecture = "amd64",
            .request_sha256 = @splat(1),
            .solver_policy_sha256 = @splat(2),
            .executor_policy_sha256 = @splat(3),
            .plan_sha256 = @splat(4),
            .package_lock_kind = .exact_v2,
            .package_lock_sha256 = @splat(5),
            .actions = &.{action},
            .repository_refresh = &.{refresh},
        };
        if (std.mem.eql(u8, kind, "attempt"))
            input.attempt_id = @splat(0xbb);
        if (std.mem.eql(u8, kind, "state"))
            input.state_path = "/var/lib/debz-other";
        if (std.mem.eql(u8, kind, "action")) input.actions = &.{changed};
        if (std.mem.eql(u8, kind, "request")) input.request_sha256 = @splat(6);
        if (std.mem.eql(u8, kind, "solver-policy"))
            input.solver_policy_sha256 = @splat(6);
        if (std.mem.eql(u8, kind, "executor-policy"))
            input.executor_policy_sha256 = @splat(6);
        if (std.mem.eql(u8, kind, "freshness"))
            input.repository_refresh = &.{changed_refresh};
        var other = try create(std.testing.allocator, input);
        defer other.deinit();
        try std.testing.expect(!std.mem.eql(
            u8,
            &first.lock.digest_sha256,
            &other.lock.digest_sha256,
        ));
    }
}

test "system_operation_lock binds mixed install and removal actions" {
    const actions = [_]Action{
        .{
            .kind = .remove,
            .package = "old",
            .version = "1",
            .architecture = "amd64",
        },
        .{
            .kind = .install,
            .package = "new",
            .version = "2",
            .architecture = "amd64",
        },
    };
    var lock = try create(std.testing.allocator, .{
        .attempt_id = @splat(0xaa),
        .operation = .install,
        .install_root = "/",
        .state_path = "/var/lib/debz",
        .target_architecture = "amd64",
        .request_sha256 = @splat(1),
        .solver_policy_sha256 = @splat(2),
        .executor_policy_sha256 = @splat(3),
        .plan_sha256 = @splat(4),
        .package_lock_kind = .exact_v2,
        .package_lock_sha256 = @splat(5),
        .actions = &actions,
        .repository_refresh = &.{},
    });
    defer lock.deinit();
    try std.testing.expectEqual(@as(usize, 2), lock.lock.actions.len);
    try std.testing.expectEqual(
        solver.ActionKind.remove,
        lock.lock.actions[0].kind,
    );
    try std.testing.expectEqual(
        solver.ActionKind.install,
        lock.lock.actions[1].kind,
    );
}
