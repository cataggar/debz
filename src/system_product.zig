const std = @import("std");
const api = @import("product_api.zig");
const production_backend = @import("production_backend.zig");
const system_operation_lock = @import("system_operation_lock.zig");
const target_apt_config = @import("target_apt_config.zig");
const transaction_executor = @import("transaction_executor.zig");

pub const default_cache_path = "/var/cache/debz";
pub const default_state_path = "/var/lib/debz";
pub const default_lock_directory = "/var/lib/debz/locks";
pub const active_manifest_name = "active-apt-config-snapshot-v2.json";

pub fn execute(
    allocator: std.mem.Allocator,
    io: std.Io,
    request: api.Request,
) !api.Result {
    if (!api.validPackageArguments(request))
        return api.failure(
            request.operation,
            .usage,
            .invalid_request,
            "invalid package argument count or spelling",
        );
    if (hasExplicitRepositories(request.options)) {
        var backend: production_backend.Backend = .{ .io = io };
        return api.execute(allocator, request, backend.interface());
    }

    var resolved = request;
    const install_root = if (request.options.install_root.len == 0)
        "/"
    else
        request.options.install_root;
    resolved.options.install_root = install_root;
    resolved.options.cache_path = if (request.options.cache_path.len == 0)
        try pathUnderRoot(allocator, install_root, default_cache_path)
    else
        request.options.cache_path;
    resolved.options.state_path = if (request.options.state_path.len == 0)
        try pathUnderRoot(allocator, install_root, default_state_path)
    else
        request.options.state_path;

    if (request.options.foreign_architectures.len != 0 or
        request.options.default_release != null or
        request.options.proxy != null or
        request.options.credential_reference != null)
        return api.failure(
            request.operation,
            .usage,
            .invalid_request,
            "active system configuration cannot be mixed with explicit repository policy inputs",
        );

    var target_files = target_apt_config.ProductionFileSystem.init(
        io,
        install_root,
    ) catch return api.failure(
        request.operation,
        .usage,
        .configuration_required,
        "selected install root is unsafe or unavailable",
    );
    defer target_files.deinit();
    const operation_guard_required = usesRepositories(request.operation);
    var operation_locks = transaction_executor.SystemLockManager{
        .allocator = allocator,
        .io = io,
    };
    var operation_guard: ?transaction_executor.LockToken = null;
    defer if (operation_guard) |token|
        operation_locks.interface().release(token);
    if (operation_guard_required) {
        operation_guard = acquireOperationGuard(
            allocator,
            install_root,
            resolved.options.lock_wait_ms,
            operation_locks.interface(),
        ) catch |err| return api.failure(
            request.operation,
            .recovery,
            .recovery_required,
            try std.fmt.allocPrint(
                allocator,
                "system operation lock is unavailable: {s}",
                .{@errorName(err)},
            ),
        );
    }

    var architecture_process = target_apt_config.SystemProcessRunner{ .io = io };

    var active_snapshot: ?target_apt_config.Snapshot = null;
    defer if (active_snapshot) |*snapshot| snapshot.deinit();
    if (request.operation == .recover) {
        resolved.options.architecture = if (request.options.architecture.len != 0)
            request.options.architecture
        else
            "recovery";
    } else if (usesRepositories(request.operation)) {
        active_snapshot = loadActiveSnapshot(
            allocator,
            io,
            install_root,
            resolved.options.state_path,
            .{
                .filesystem = target_files.interface(),
                .process = architecture_process.interface(),
            },
        ) catch return api.failure(
            request.operation,
            .usage,
            .configuration_required,
            "active repository configuration is missing, unsafe, or no longer matches target files; run 'debz repo add' again",
        );
        resolveActiveArchitectures(
            request.options,
            active_snapshot.?.manifest.manifest,
            &resolved.options,
        ) catch
            return api.failure(
                request.operation,
                .usage,
                .invalid_request,
                "explicit architecture does not match the active target configuration",
            );
    } else if (request.options.architecture.len == 0) {
        resolved.options.architecture = target_apt_config.discoverNativeArchitecture(
            allocator,
            .{
                .root_path = install_root,
                .dependencies = .{
                    .filesystem = target_files.interface(),
                    .process = architecture_process.interface(),
                },
            },
        ) catch return api.failure(
            request.operation,
            .usage,
            .configuration_required,
            "target dpkg native architecture is unavailable",
        );
    }

    if (request.operation.mutates()) {
        resolved.options.assume_yes = true;
        resolved.options.noninteractive = true;
        if (resolved.options.conffile == .unspecified)
            resolved.options.conffile = .keep_existing;
    }

    var backend: production_backend.Backend = .{
        .io = io,
        .system_profile = true,
        .system_snapshot = if (active_snapshot) |*snapshot| snapshot else null,
        .system_operation_guard_held = operation_guard != null,
        .recovery_architecture_override = if (request.operation == .recover and
            request.options.architecture.len != 0)
            request.options.architecture
        else
            null,
    };
    return api.execute(allocator, resolved, backend.interface());
}

fn acquireOperationGuard(
    allocator: std.mem.Allocator,
    install_root: []const u8,
    wait_ms: u64,
    locks: transaction_executor.LockManager,
) !transaction_executor.LockToken {
    const path = try system_operation_lock.guardPath(
        allocator,
        install_root,
    );
    defer allocator.free(path);
    return locks.acquire(path, wait_ms);
}

fn resolveActiveArchitectures(
    requested: api.CommonOptions,
    manifest: target_apt_config.Manifest,
    resolved: *api.CommonOptions,
) !void {
    if (requested.architecture.len != 0 and
        !std.mem.eql(
            u8,
            requested.architecture,
            manifest.native_architecture,
        ))
        return error.ArchitectureMismatch;
    resolved.architecture = manifest.native_architecture;
    resolved.foreign_architectures = manifest.foreign_architectures;
}

fn hasExplicitRepositories(options: api.CommonOptions) bool {
    return options.source_paths.len != 0 or
        options.config_paths.len != 0 or
        options.keyring_paths.len != 0;
}

fn usesRepositories(operation: api.Operation) bool {
    return switch (operation) {
        .list_installed, .why, .clean => false,
        else => true,
    };
}

fn pathUnderRoot(
    allocator: std.mem.Allocator,
    root: []const u8,
    logical: []const u8,
) ![]u8 {
    if (std.mem.eql(u8, root, "/")) return allocator.dupe(u8, logical);
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ root, logical });
}

fn loadActiveSnapshot(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: []const u8,
    state_path: []const u8,
    dependencies: target_apt_config.Dependencies,
) !target_apt_config.Snapshot {
    var state = try openAbsoluteDirectory(io, state_path);
    defer state.close(io);
    var repository = try state.openDir(io, "repository", .{
        .follow_symlinks = false,
    });
    defer repository.close(io);
    const store = try target_apt_config.Store.init(
        io,
        repository,
        active_manifest_name,
    );
    var manifest = try store.read(
        allocator,
        target_apt_config.maximum_document_bytes,
    );
    defer manifest.deinit();
    return target_apt_config.loadRecordedSnapshot(allocator, .{
        .root_path = root,
        .manifest = manifest.manifest,
        .dependencies = dependencies,
    });
}

fn openAbsoluteDirectory(io: std.Io, path: []const u8) !std.Io.Dir {
    if (!std.fs.path.isAbsolute(path)) return error.InvalidAbsolutePath;
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{
        .follow_symlinks = false,
    });
    errdefer current.close(io);
    if (std.mem.eql(u8, path, "/")) return current;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
            return error.AmbiguousPath;
        const next = try current.openDir(io, component, .{
            .follow_symlinks = false,
        });
        current.close(io);
        current = next;
    }
    return current;
}

test "system defaults stay rooted in the selected target" {
    const host_cache = try pathUnderRoot(std.testing.allocator, "/", default_cache_path);
    defer std.testing.allocator.free(host_cache);
    try std.testing.expectEqualStrings(default_cache_path, host_cache);
    const image_state = try pathUnderRoot(
        std.testing.allocator,
        "/image",
        default_state_path,
    );
    defer std.testing.allocator.free(image_state);
    try std.testing.expectEqualStrings("/image/var/lib/debz", image_state);
}

test "system active configuration preserves foreign architectures" {
    const foreign = [_][]const u8{ "arm64", "i386" };
    const manifest: target_apt_config.Manifest = .{
        .native_architecture = "amd64",
        .foreign_architectures = &foreign,
        .sources = &.{},
        .configuration_id = @splat('a'),
        .repository_ids = &.{},
        .keyrings = &.{},
        .global_trust_compatibility = false,
        .exclusions = &.{},
        .digest_sha256 = @splat(0),
    };
    const requested: api.CommonOptions = .{
        .install_root = "/",
        .cache_path = "/var/cache/debz",
        .state_path = "/var/lib/debz",
        .architecture = "",
    };
    var resolved = requested;
    try resolveActiveArchitectures(requested, manifest, &resolved);
    try std.testing.expectEqualStrings("amd64", resolved.architecture);
    try std.testing.expectEqualSlices(
        []const u8,
        &foreign,
        resolved.foreign_architectures,
    );
    var conflict = requested;
    conflict.architecture = "arm64";
    try std.testing.expectError(
        error.ArchitectureMismatch,
        resolveActiveArchitectures(conflict, manifest, &resolved),
    );
}

test "system active configuration guard serializes before loading" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root");
    var real: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.dir.realPath(std.testing.io, &real);
    const install_root = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/root",
        .{real[0..length]},
    );
    defer std.testing.allocator.free(install_root);
    const guard_path = try system_operation_lock.guardPath(
        std.testing.allocator,
        install_root,
    );
    defer std.testing.allocator.free(guard_path);
    var first_manager = transaction_executor.SystemLockManager{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    const first = first_manager.interface();
    const token = try first.acquire(guard_path, 100);
    defer first.release(token);
    var second_manager = transaction_executor.SystemLockManager{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
    };
    try std.testing.expectError(
        error.LockTimeout,
        acquireOperationGuard(
            std.testing.allocator,
            install_root,
            1,
            second_manager.interface(),
        ),
    );
}
