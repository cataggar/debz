const std = @import("std");
const active = @import("active_repository_config.zig");
const api = @import("product_api.zig");
const live_root = @import("live_root.zig");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const target = @import("target_apt_config.zig");
const repository_policy = @import("repository_policy.zig");
const source = @import("source.zig");
const openpgp = @import("openpgp_verifier.zig");

pub const SnapshotFacts = struct {
    configuration: struct {
        repositories: []const repository_policy.NormalizedRepository,
        canonical_deb822: []const u8,
        identity: source.RepositoryId,
    },
    manifest: target.Manifest,
    source_materials: []const target.SourceMaterial,
    keyring_materials: []const target.KeyringMaterial,
    verifier_limits: openpgp.Limits,
};

pub const Request = struct {
    root: []const u8 = "/",
    /// Logical paths beneath the selected root, never host paths for images.
    cache_path: []const u8 = "/var/cache/debz",
    state_path: []const u8 = "/var/lib/debz",
    architecture: ?[]const u8 = null,
};

/// A verified configuration view, deliberately not host-mutation permission.
/// Generic product API v1 continues to require explicit repository inputs.
pub const Context = opaque {
    fn data(self: *const Context) *const Data {
        return @ptrCast(@alignCast(self));
    }

    pub fn deinit(self: *Context) void {
        const value: *Data = @ptrCast(@alignCast(self));
        const allocator = value.allocator;
        value.loaded.deinit();
        value.root.close();
        value.arena.deinit();
        allocator.destroy(value);
    }

    pub fn snapshot(self: *const Context) SnapshotFacts {
        const loaded = &self.data().loaded.snapshot;
        return .{
            .configuration = .{
                .repositories = loaded.configuration.repositories,
                .canonical_deb822 = loaded.configuration.canonical_deb822,
                .identity = loaded.configuration.identity,
            },
            .manifest = loaded.manifest.manifest,
            .source_materials = loaded.source_materials,
            .keyring_materials = loaded.keyring_materials,
            .verifier_limits = loaded.verifier_limits,
        };
    }

    pub fn runtimeTrust(self: *const Context, allocator: std.mem.Allocator, id: source.RepositoryId) !target.RuntimeTrust {
        const loaded = &self.data().loaded.snapshot;
        for (loaded.configuration.repositories) |repository| {
            if (std.mem.eql(u8, repository.id.slice(), id.slice()))
                return loaded.runtimeTrust(allocator, repository);
        }
        return error.UnknownActiveRepository;
    }

    pub fn options(self: *const Context) api.CommonOptions {
        return self.data().options;
    }

    pub fn locksPath(self: *const Context) []const u8 {
        return self.data().locks_path;
    }

    pub fn activePath(self: *const Context) []const u8 {
        return self.data().active_path;
    }

    pub fn manifestPath(self: *const Context) []const u8 {
        return self.data().loaded.retainedManifestPath();
    }

    pub fn validate(self: *const Context) !void {
        const value = self.data();
        var reopened = try root_fs.openAbsoluteRoot(value.root.root.io, value.request.root);
        defer reopened.close();
        const held = try value.root.root.rootEntry();
        const current = try reopened.root.rootEntry();
        if (held.device != current.device or held.inode != current.inode)
            return error.ForeignActiveRoot;
        if (value.projection) |projection|
            try projection.validateRoot(value.request.root, reopened.root.dir.handle);
        try refuseActiveWork(reopened.root);
        var loaded = try active.load(value.allocator, reopened.root, value.configuration_root, value.request.state_path, value.request.architecture);
        defer loaded.deinit();
        if (!std.mem.eql(u8, &loaded.snapshot.manifest.manifest.digest_sha256, &value.loaded.snapshot.manifest.manifest.digest_sha256) or
            !std.mem.eql(u8, loaded.pointer.value.digest_sha256, value.loaded.pointer.value.digest_sha256))
            return error.ActiveConfigurationChanged;
    }
};

const Data = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    root: root_fs.OwnedRoot,
    loaded: active.Loaded,
    request: Request,
    options: api.CommonOptions,
    locks_path: []const u8,
    active_path: []const u8,
    projection: ?*const live_root.Projection,
    configuration_root: []const u8,
};

fn physicalPath(allocator: std.mem.Allocator, root: []const u8, logical: []const u8) ![]const u8 {
    _ = try root_fs.Path.fromAbsolute(logical);
    return if (std.mem.eql(u8, root, "/"))
        allocator.dupe(u8, logical)
    else
        std.fmt.allocPrint(allocator, "{s}{s}", .{ root, logical });
}

fn refuseActiveWork(root: root_fs.Root) !void {
    // Never refresh/replan around another surface's durable owned work.
    if (try root.entryIfExists(try root_fs.Path.init(root_operation.record_path)) != null)
        return error.RootOperationRecoveryRequired;
    if (try root.entryIfExists(try root_fs.Path.init(root_operation.deferred_ack_path)) != null)
        return error.RootOperationRecoveryRequired;
    if (try root.entryIfExists(try root_fs.Path.init(root_operation.native_intent_path)) != null)
        return error.RootOperationRecoveryRequired;
}

pub fn resolve(allocator: std.mem.Allocator, io: std.Io, request: Request) !*Context {
    if (std.mem.eql(u8, request.root, live_root.logical_root_path))
        return error.ProjectionAuthorityRequired;
    return resolveInternal(allocator, io, request, null);
}

/// Reads the host configuration through an authenticated private projection,
/// without changing its execution/recovery namespace or granting mutation.
pub fn resolveProjected(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: Request,
    projection: *const live_root.Projection,
) !*Context {
    return resolveInternal(allocator, io, request, projection);
}

fn resolveInternal(allocator: std.mem.Allocator, io: std.Io, request: Request, projection: ?*const live_root.Projection) !*Context {
    var root = try root_fs.openAbsoluteRoot(io, request.root);
    errdefer root.close();
    if (projection) |authority| try authority.validateRoot(request.root, root.root.dir.handle);
    const configuration_root = if (projection != null) "/" else request.root;
    _ = try root_fs.Path.fromAbsolute(request.cache_path);
    _ = try root_fs.Path.fromAbsolute(request.state_path);
    try refuseActiveWork(root.root);
    var loaded = try active.load(allocator, root.root, configuration_root, request.state_path, request.architecture);
    errdefer loaded.deinit();
    const data = try allocator.create(Data);
    errdefer allocator.destroy(data);
    var arena: std.heap.ArenaAllocator = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const saved_request: Request = .{
        .root = try owned.dupe(u8, request.root),
        .cache_path = try owned.dupe(u8, request.cache_path),
        .state_path = try owned.dupe(u8, request.state_path),
        .architecture = if (request.architecture) |architecture| try owned.dupe(u8, architecture) else null,
    };
    const lock_logical = try std.fmt.allocPrint(owned, "{s}/locks", .{request.state_path});
    const options: api.CommonOptions = .{
        .install_root = saved_request.root,
        .cache_path = try physicalPath(owned, request.root, request.cache_path),
        .state_path = try physicalPath(owned, request.root, request.state_path),
        .architecture = loaded.snapshot.manifest.manifest.native_architecture,
        .foreign_architectures = loaded.snapshot.manifest.manifest.foreign_architectures,
        .noninteractive = true,
        .conffile = .keep_existing,
    };
    const locks_path = try physicalPath(owned, request.root, lock_logical);
    const active_path = try active.logicalPath(owned, request.state_path);
    data.* = .{
        .allocator = allocator,
        .arena = arena,
        .root = root,
        .loaded = loaded,
        .request = saved_request,
        .options = options,
        .locks_path = locks_path,
        .active_path = active_path,
        .projection = projection,
        .configuration_root = if (projection != null) "/" else saved_request.root,
    };
    return @ptrCast(data);
}

const Fixture = struct {
    path: []u8,
    relative_path: []u8,
    root: root_fs.OwnedRoot,
    state: []const u8,
    manifest_path: []u8,
    generation: u8 = 0,

    const source_path = "etc/apt/sources.list.d/vendor.list";
    const keyring_path = "usr/share/keyrings/vendor.gpg";
    const source_bytes = "deb [signed-by=/usr/share/keyrings/vendor.gpg] https://vendor.invalid/ubuntu noble main\n";

    fn init(architecture: []const u8, state: []const u8) !Fixture {
        const allocator = std.testing.allocator;
        var random: [16]u8 = undefined;
        try std.Io.randomSecure(std.testing.io, &random);
        const name = std.fmt.bytesToHex(random, .lower);
        const relative = try std.fmt.allocPrint(allocator, ".zig-cache/system-context-{s}", .{name});
        errdefer allocator.free(relative);
        try std.Io.Dir.cwd().createDirPath(std.testing.io, ".zig-cache");
        try std.Io.Dir.cwd().createDir(std.testing.io, relative, .fromMode(0o700));
        errdefer std.Io.Dir.cwd().deleteTree(std.testing.io, relative) catch {};
        var dir = try std.Io.Dir.cwd().openDir(std.testing.io, relative, .{ .follow_symlinks = false });
        defer dir.close(std.testing.io);
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try dir.realPath(std.testing.io, &buffer);
        const path = try allocator.dupe(u8, buffer[0..length]);
        errdefer allocator.free(path);
        var root = try root_fs.openAbsoluteRoot(std.testing.io, path);
        errdefer root.close();
        for ([_][]const u8{ "etc/apt/sources.list.d", "usr/share/keyrings", "var/lib/dpkg" }) |directory|
            try root.root.createDirectoryPath(try root_fs.Path.init(directory), .fromMode(0o755));
        try root.root.publishFile(try root_fs.Path.init(source_path), source_bytes, .{});
        try root.root.publishFile(try root_fs.Path.init(keyring_path), &@import("fixtures/openpgp.zig").keyring, .{});
        const status = try std.fmt.allocPrint(allocator, "Package: dpkg\nStatus: install ok installed\nArchitecture: {s}\nVersion: 1.0\n\n", .{architecture});
        defer allocator.free(status);
        try root.root.publishFile(try root_fs.Path.init("var/lib/dpkg/status"), status, .{});
        const manifest_path = try std.fmt.allocPrint(allocator, "{s}/repository/operations/{s}/apt-config-snapshot-v1.json", .{ state, "1" ** 64 });
        errdefer allocator.free(manifest_path);
        return .{ .path = path, .relative_path = relative, .root = root, .state = state, .manifest_path = manifest_path };
    }

    fn activate(self: *Fixture) !void {
        return self.activateObserved(null);
    }

    fn activateObserved(self: *Fixture, observer: ?root_fs.PublishObserver) !void {
        const allocator = std.testing.allocator;
        if (self.generation != 0) {
            const id = std.fmt.bytesToHex(@as([32]u8, @splat(self.generation)), .lower);
            const next_path = try std.fmt.allocPrint(allocator, "{s}/repository/operations/{s}/apt-config-snapshot-v1.json", .{ self.state, id });
            allocator.free(self.manifest_path);
            self.manifest_path = next_path;
        }
        self.generation += 1;
        var files: target.ProductionFileSystem = .{ .io = std.testing.io, .root = self.root.root.dir, .host_root = false };
        var snapshot = try target.snapshot(allocator, .{
            .root_path = self.path,
            .source_policies = &.{.{
                .logical_path = "/" ++ source_path,
                .freshness = .{ .allow_missing_valid_until_with_max_age_seconds = 14 * 24 * 60 * 60 },
            }},
            .dependencies = .{ .filesystem = files.interface() },
        });
        defer snapshot.deinit();
        const path = try root_fs.Path.fromAbsolute(self.manifest_path);
        try self.root.root.createDirectoryPath(path.parent().?, .fromMode(0o700));
        const bytes = try snapshot.manifest.manifest.canonicalJson(allocator);
        defer allocator.free(bytes);
        try self.root.root.publishFile(path, bytes, .{ .permissions = .fromMode(0o600) });
        var locks: root_operation.SystemLockBackend = .{ .allocator = allocator, .io = std.testing.io };
        var coordinator = try root_operation.Coordinator.open(std.testing.io, self.root.root, self.path, locks.interface());
        var attempt = try coordinator.acquire(allocator, .{
            .backend = .legacy_dpkg,
            .operation = .{ .repository_bootstrap = .add },
            .request_sha256 = @splat(1),
            .policy_sha256 = @splat(2),
            .target_architecture = snapshot.manifest.manifest.native_architecture,
        });
        defer attempt.release();
        try active.publish(allocator, &attempt, self.state, self.manifest_path, snapshot.manifest.manifest, observer);
        try attempt.complete(allocator, .abandoned_before_mutation);
        try attempt.clear();
        const active_text = try active.logicalPath(allocator, self.state);
        defer allocator.free(active_text);
        const active_path = try root_fs.Path.fromAbsolute(active_text);
        const before = try self.root.root.entry(active_path);
        const retained = try self.root.root.readFileAlloc(allocator, active_path, active.maximum_document_bytes);
        defer allocator.free(retained);
        try active.publish(allocator, &attempt, self.state, self.manifest_path, snapshot.manifest.manifest, null);
        try std.testing.expectEqual(before.inode, (try self.root.root.entry(active_path)).inode);
        try self.root.root.removeFile(active_path);
        try std.testing.expectError(error.FileNotFound, active.publish(allocator, &attempt, self.state, self.manifest_path, snapshot.manifest.manifest, null));
        try std.testing.expectError(error.FileNotFound, self.root.root.entry(active_path));
        try self.root.root.publishFile(active_path, retained, .{ .permissions = .fromMode(0o600), .durable = true });
    }

    fn deinit(self: *Fixture) void {
        self.root.close();
        std.Io.Dir.cwd().deleteTree(std.testing.io, self.relative_path) catch {};
        std.testing.allocator.free(self.path);
        std.testing.allocator.free(self.relative_path);
        std.testing.allocator.free(self.manifest_path);
    }
};

test "system_product_context typed defaults preserve target trust on amd64 and arm64" {
    for ([_][]const u8{ "amd64", "arm64" }) |architecture| {
        var fixture = try Fixture.init(architecture, "/var/lib/debz");
        defer fixture.deinit();
        try fixture.activate();
        const context = try resolve(std.testing.allocator, std.testing.io, .{ .root = fixture.path });
        defer context.deinit();
        try context.validate();
        try std.testing.expectEqualStrings(architecture, context.options().architecture);
        const cache = try std.fmt.allocPrint(std.testing.allocator, "{s}/var/cache/debz", .{fixture.path});
        defer std.testing.allocator.free(cache);
        try std.testing.expectEqualStrings(cache, context.options().cache_path);
        try std.testing.expectError(error.FileNotFound, fixture.root.root.openDirectory(try root_fs.Path.init("var/cache/debz")));
        try std.testing.expect(context.options().noninteractive and context.options().conffile == .keep_existing);
        try std.testing.expect(!context.options().assume_yes and context.options().source_paths.len == 0);
        const manifest_bytes = try context.snapshot().manifest.canonicalJson(std.testing.allocator);
        defer std.testing.allocator.free(manifest_bytes);
        const generation = try active.generationPath(std.testing.allocator, fixture.state, manifest_bytes);
        defer std.testing.allocator.free(generation);
        try std.testing.expectEqualStrings(generation, context.manifestPath());
        const repository = context.snapshot().configuration.repositories[0];
        try std.testing.expectEqual(@as(u64, 14 * 24 * 60 * 60), repository.freshness.allow_missing_valid_until_with_max_age_seconds);
        var trust = try context.runtimeTrust(std.testing.allocator, repository.id);
        defer trust.deinit();
        try std.testing.expectEqualStrings("/usr/share/keyrings/vendor.gpg", trust.declared_keyrings[0]);
        try std.testing.expectEqualSlices(u8, &@import("fixtures/openpgp.zig").keyring, trust.keyrings[0].bytes);
    }
}

fn requireDeepReadonly(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => |pointer| {
            if (!pointer.is_const) @compileError("system context exposes mutable owned facts");
            requireDeepReadonly(pointer.child);
        },
        .@"struct" => |structure| inline for (structure.fields) |field| requireDeepReadonly(field.type),
        .@"union" => |structure| inline for (structure.fields) |field| requireDeepReadonly(field.type),
        .optional => |optional| requireDeepReadonly(optional.child),
        .array => |array| requireDeepReadonly(array.child),
        else => {},
    }
}

test "system_product_context exposes only deep readonly borrowed facts and detached copies" {
    var fixture = try Fixture.init("amd64", "/var/lib/debz");
    defer fixture.deinit();
    try fixture.activate();
    const context = try resolve(std.testing.allocator, std.testing.io, .{ .root = fixture.path });
    defer context.deinit();
    comptime requireDeepReadonly(@TypeOf(context.snapshot()));
    comptime requireDeepReadonly(@TypeOf(context.options()));
    var detached = context.snapshot().configuration.repositories[0];
    detached.uri = "https://untrusted.invalid/";
    detached.freshness = .require_valid_until;
    var manifest = context.snapshot().manifest;
    manifest.digest_sha256[0] ^= 1;
    try context.validate();
    try std.testing.expect(!std.mem.eql(u8, detached.uri, context.snapshot().configuration.repositories[0].uri));
    try std.testing.expectEqual(@as(u64, 14 * 24 * 60 * 60), context.snapshot().configuration.repositories[0].freshness.allow_missing_valid_until_with_max_age_seconds);
    try std.testing.expect(!std.mem.eql(u8, &manifest.digest_sha256, &context.snapshot().manifest.digest_sha256));
}

test "system_product_context allocation failures retain the published configuration" {
    var fixture = try Fixture.init("amd64", "/var/lib/debz");
    defer fixture.deinit();
    try fixture.activate();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn exercise(allocator: std.mem.Allocator, path: []const u8) !void {
            const context = try resolve(allocator, std.testing.io, .{ .root = path });
            defer context.deinit();
            try context.validate();
        }
    }.exercise, .{fixture.path});
}

test "system_product_context overrides stay root scoped and architecture never probes the host" {
    var fixture = try Fixture.init("amd64", "/srv/debz");
    defer fixture.deinit();
    try fixture.activate();
    try std.testing.expectError(error.FileNotFound, resolve(std.testing.allocator, std.testing.io, .{ .root = fixture.path }));
    const context = try resolve(std.testing.allocator, std.testing.io, .{
        .root = fixture.path,
        .state_path = fixture.state,
        .cache_path = "/srv/cache",
    });
    defer context.deinit();
    const locks = try std.fmt.allocPrint(std.testing.allocator, "{s}/srv/debz/locks", .{fixture.path});
    defer std.testing.allocator.free(locks);
    try std.testing.expectEqualStrings(locks, context.locksPath());
    try std.testing.expectError(error.ActiveArchitectureMismatch, resolve(std.testing.allocator, std.testing.io, .{
        .root = fixture.path,
        .state_path = fixture.state,
        .architecture = "arm64",
    }));
    try fixture.root.root.removeFile(try root_fs.Path.init("var/lib/dpkg/status"));
    try std.testing.expectError(error.NativeArchitectureUnavailable, context.validate());
    const explicit = try resolve(std.testing.allocator, std.testing.io, .{
        .root = fixture.path,
        .state_path = fixture.state,
        .architecture = "amd64",
    });
    defer explicit.deinit();
    try std.testing.expectEqualStrings("amd64", explicit.options().architecture);
    try std.testing.expectError(error.ProjectionAuthorityRequired, resolve(std.testing.allocator, std.testing.io, .{ .root = live_root.logical_root_path }));
}

test "system_product_context refuses source key manifest and active-pointer drift" {
    var fixture = try Fixture.init("amd64", "/var/lib/debz");
    defer fixture.deinit();
    try fixture.activate();
    const context = try resolve(std.testing.allocator, std.testing.io, .{ .root = fixture.path });
    defer context.deinit();
    try fixture.root.root.publishFile(try root_fs.Path.init(Fixture.source_path), Fixture.source_bytes ++ "# changed\n", .{});
    try std.testing.expectError(error.ActiveConfigurationChanged, context.validate());
    try fixture.root.root.publishFile(try root_fs.Path.init(Fixture.source_path), Fixture.source_bytes, .{});
    try fixture.root.root.publishFile(try root_fs.Path.init(Fixture.keyring_path), "replaced key", .{});
    try std.testing.expectError(error.ActiveConfigurationChanged, context.validate());
    try fixture.root.root.removeFile(try root_fs.Path.init(Fixture.keyring_path));
    try fixture.root.root.createSymbolicLink(try root_fs.Path.init(Fixture.keyring_path), "vendor.other.gpg");
    try std.testing.expectError(error.UnsafeActiveConfigFile, context.validate());
    try fixture.root.root.removeFile(try root_fs.Path.init(Fixture.keyring_path));
    try fixture.root.root.publishFile(try root_fs.Path.init(Fixture.keyring_path), &@import("fixtures/openpgp.zig").keyring, .{ .permissions = .fromMode(0o664) });
    try std.testing.expectError(error.UnsafeActiveConfigFile, context.validate());
    try fixture.root.root.publishFile(try root_fs.Path.init(Fixture.keyring_path), &@import("fixtures/openpgp.zig").keyring, .{});
    const manifest = try root_fs.Path.fromAbsolute(context.manifestPath());
    try fixture.root.root.publishFile(manifest, "truncated", .{ .permissions = .fromMode(0o600) });
    try std.testing.expectError(error.ActiveManifestChanged, context.validate());
    const active_path = try root_fs.Path.fromAbsolute(context.activePath());
    try fixture.root.root.publishFile(active_path, "{\"unexpected\":true}", .{ .permissions = .fromMode(0o600) });
    try std.testing.expectError(error.InvalidActiveConfig, context.validate());
}

test "system_product_context public operation manifest changes preserve immutable generation" {
    var fixture = try Fixture.init("amd64", "/var/lib/debz");
    defer fixture.deinit();
    try fixture.activate();
    const context = try resolve(std.testing.allocator, std.testing.io, .{ .root = fixture.path });
    defer context.deinit();
    const path = try root_fs.Path.fromAbsolute(context.manifestPath());
    const before = try fixture.root.root.readFileAlloc(std.testing.allocator, path, target.maximum_document_bytes);
    defer std.testing.allocator.free(before);
    try fixture.root.root.publishFile(try root_fs.Path.fromAbsolute(fixture.manifest_path), "truncated public operation manifest", .{ .permissions = .fromMode(0o600) });
    try context.validate();
    const reopened = try resolve(std.testing.allocator, std.testing.io, .{ .root = fixture.path });
    defer reopened.deinit();
    try reopened.validate();
    try std.testing.expectEqualStrings(context.manifestPath(), reopened.manifestPath());
    const after = try fixture.root.root.readFileAlloc(std.testing.allocator, path, target.maximum_document_bytes);
    defer std.testing.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
}

test "system_product_context refuses copied configuration and unrecorded target sources" {
    var first = try Fixture.init("amd64", "/var/lib/debz");
    defer first.deinit();
    var second = try Fixture.init("amd64", "/var/lib/debz");
    defer second.deinit();
    try first.activate();
    try second.activate();
    const path = try root_fs.Path.init("var/lib/debz/repository/active-config-v1.json");
    const bytes = try first.root.root.readFileAlloc(std.testing.allocator, path, active.maximum_document_bytes);
    defer std.testing.allocator.free(bytes);
    try second.root.root.publishFile(path, bytes, .{ .permissions = .fromMode(0o600) });
    try std.testing.expectError(error.ForeignActiveRoot, resolve(std.testing.allocator, std.testing.io, .{ .root = second.path }));
    try first.root.root.publishFile(try root_fs.Path.init("etc/apt/sources.list.d/extra.list"), "deb [signed-by=/usr/share/keyrings/vendor.gpg] https://extra.vendor.invalid/ubuntu noble main\n", .{});
    try std.testing.expectError(error.ActiveConfigurationChanged, resolve(std.testing.allocator, std.testing.io, .{ .root = first.path }));
}

test "system_product_context refuses retained work before importing changed configuration" {
    var fixture = try Fixture.init("amd64", "/var/lib/debz");
    defer fixture.deinit();
    try fixture.activate();
    const context = try resolve(std.testing.allocator, std.testing.io, .{ .root = fixture.path });
    defer context.deinit();
    try fixture.root.root.publishFile(try root_fs.Path.init(Fixture.source_path), "changed", .{});
    for ([_][]const u8{ root_operation.record_path, root_operation.deferred_ack_path, root_operation.native_intent_path }) |path| {
        const work = try root_fs.Path.init(path);
        try fixture.root.root.publishFile(work, "held evidence", .{ .permissions = .fromMode(0o600) });
        try std.testing.expectError(error.RootOperationRecoveryRequired, context.validate());
        try std.testing.expectError(error.RootOperationRecoveryRequired, resolve(std.testing.allocator, std.testing.io, .{ .root = fixture.path }));
        const retained = try fixture.root.root.readFileAlloc(std.testing.allocator, work, 64);
        defer std.testing.allocator.free(retained);
        try std.testing.expectEqualStrings("held evidence", retained);
        try fixture.root.root.removeFile(work);
    }
}

test "system_product_context interrupted active publication retains exact ownership and historical evidence" {
    for ([_]root_fs.PublishPoint{ .before_rename, .after_rename }) |point| {
        var fixture = try Fixture.init("amd64", "/var/lib/debz");
        defer fixture.deinit();
        try fixture.activate();
        const active_path = try root_fs.Path.init("var/lib/debz/repository/active-config-v1.json");
        const previous = try fixture.root.root.readFileAlloc(std.testing.allocator, active_path, active.maximum_document_bytes);
        defer std.testing.allocator.free(previous);
        const old_manifest_path = try std.testing.allocator.dupe(u8, fixture.manifest_path);
        defer std.testing.allocator.free(old_manifest_path);
        const old_manifest = try fixture.root.root.readFileAlloc(std.testing.allocator, try root_fs.Path.fromAbsolute(old_manifest_path), target.maximum_document_bytes);
        defer std.testing.allocator.free(old_manifest);
        try fixture.root.root.publishFile(try root_fs.Path.init(Fixture.source_path), Fixture.source_bytes ++ "# new verified snapshot\n", .{});
        const Crash = struct {
            point: root_fs.PublishPoint,
            hit: bool = false,

            fn observe(raw: *anyopaque, observed: root_fs.PublishPoint) !void {
                const self: *@This() = @ptrCast(@alignCast(raw));
                if (observed == self.point) {
                    self.hit = true;
                    return error.InjectedActivePublicationCrash;
                }
            }
        };
        var crash: Crash = .{ .point = point };
        try std.testing.expectError(error.InjectedActivePublicationCrash, fixture.activateObserved(.{ .context = &crash, .hitFn = Crash.observe }));
        try std.testing.expect(crash.hit);
        const retained = try fixture.root.root.readFileAlloc(std.testing.allocator, active_path, active.maximum_document_bytes);
        defer std.testing.allocator.free(retained);
        if (point == .before_rename)
            try std.testing.expectEqualSlices(u8, previous, retained)
        else
            try std.testing.expect(!std.mem.eql(u8, previous, retained));
        const historical = try fixture.root.root.readFileAlloc(std.testing.allocator, try root_fs.Path.fromAbsolute(old_manifest_path), target.maximum_document_bytes);
        defer std.testing.allocator.free(historical);
        try std.testing.expectEqualSlices(u8, old_manifest, historical);
        const record = try fixture.root.root.readFileAlloc(std.testing.allocator, try root_fs.Path.init(root_operation.record_path), root_operation.maximum_document_bytes);
        defer std.testing.allocator.free(record);
        var owner = try root_operation.decode(std.testing.allocator, record, root_operation.maximum_document_bytes);
        defer owner.deinit();
        try std.testing.expect(owner.record.operation == .repository_bootstrap);
        try std.testing.expect(!owner.record.mutation_started);
        try std.testing.expectError(error.RootOperationRecoveryRequired, resolve(std.testing.allocator, std.testing.io, .{ .root = fixture.path }));
    }
}
