const std = @import("std");
const api = @import("product_api.zig");
const production_backend = @import("production_backend.zig");
const target_apt_config = @import("target_apt_config.zig");

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
    var architecture_process = target_apt_config.SystemProcessRunner{ .io = io };

    var active_snapshot: ?target_apt_config.Snapshot = null;
    defer if (active_snapshot) |*snapshot| snapshot.deinit();
    if (usesRepositories(request.operation)) {
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
        const recorded = active_snapshot.?.manifest.manifest.native_architecture;
        if (request.options.architecture.len != 0 and
            !std.mem.eql(u8, request.options.architecture, recorded))
            return api.failure(
                request.operation,
                .usage,
                .invalid_request,
                "explicit architecture does not match the active target configuration",
            );
        resolved.options.architecture = recorded;
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
    };
    return api.execute(allocator, resolved, backend.interface());
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
