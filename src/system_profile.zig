//! Strict system profile version 1.
//!
//! A profile is the only system-facade source of repository, trust, network,
//! architecture, cache, state, and conffile policy. Loading never consults
//! APT configuration, environment variables, ambient keyrings, proxy settings,
//! or credentials.
const std = @import("std");
const builtin = @import("builtin");
const absolute_path = @import("absolute_path.zig");

const Io = std.Io;
const File = Io.File;

pub const schema_id = "https://debz.dev/schema/system-profile-v1";
pub const schema_version: u32 = 1;
pub const default_profile_path = "/etc/debz/default.json";
pub const default_cache_path = "/var/cache/debz";
pub const default_state_path = "/var/lib/debz";

pub const maximum_profile_bytes: usize = 256 * 1024;
pub const maximum_trusted_file_bytes: u64 = 16 * 1024 * 1024;
pub const maximum_path_bytes: usize = 4096;
pub const maximum_repositories: usize = 32;
pub const maximum_keyrings: usize = 32;
pub const maximum_foreign_architectures: usize = 16;
pub const maximum_trusted_files: usize =
    1 + maximum_repositories * 2 + maximum_keyrings + 1;

pub const RepositoryPolicy = enum {
    strict_priority,
    best_version,
};

pub const ConffilePolicy = enum {
    keep_existing,
    use_package_version,
};

pub const Repository = struct {
    source_path: []const u8,
    config_path: ?[]const u8 = null,
};

/// Null proxy and credential fields mean disabled. They never mean "discover
/// from APT or the process environment".
pub const NetworkPolicy = struct {
    proxy_url: ?[]const u8 = null,
    credential_reference: ?[]const u8 = null,
};

pub const Profile = struct {
    repositories: []const Repository,
    keyring_paths: []const []const u8,
    architecture: []const u8,
    foreign_architectures: []const []const u8 = &.{},
    repository_policy: RepositoryPolicy = .strict_priority,
    cache_path: []const u8 = default_cache_path,
    state_path: []const u8 = default_state_path,
    default_conffile: ConffilePolicy = .keep_existing,
    network: NetworkPolicy = .{},
};

pub const Limits = struct {
    maximum_profile_bytes: usize = maximum_profile_bytes,
    maximum_trusted_file_bytes: u64 = maximum_trusted_file_bytes,
    maximum_repositories: usize = maximum_repositories,
    maximum_keyrings: usize = maximum_keyrings,
    maximum_foreign_architectures: usize = maximum_foreign_architectures,
    maximum_trusted_files: usize = maximum_trusted_files,
};

/// The metadata required to decide whether a profile or referenced trust file
/// is safe to consume. `modeled` must be true so uid zero is an observation,
/// not a platform placeholder.
pub const Metadata = struct {
    kind: File.Kind,
    size: u64,
    mode: u32,
    uid: u32,
    modeled: bool = true,
};

pub const ReadResult = struct {
    bytes: []u8,
    metadata: Metadata,
};

/// Injected filesystem seam used by both production loading and unit tests.
/// Production implementations must open every component and leaf without
/// following symbolic links. `readFn` returns bytes and metadata from the same
/// opened file descriptor.
pub const FileSystem = struct {
    context: *anyopaque,
    readFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
        usize,
    ) anyerror!ReadResult,
    inspectFn: *const fn (*anyopaque, []const u8) anyerror!Metadata,

    pub fn read(
        self: FileSystem,
        allocator: std.mem.Allocator,
        path: []const u8,
        maximum_bytes: usize,
    ) !ReadResult {
        return self.readFn(self.context, allocator, path, maximum_bytes);
    }

    pub fn inspect(self: FileSystem, path: []const u8) !Metadata {
        return self.inspectFn(self.context, path);
    }
};

pub const LoadedProfile = struct {
    profile: Profile,
    profile_path: []const u8,
    profile_sha256: [32]u8,
    trusted_file_count: usize,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *LoadedProfile) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

const WireProfile = struct {
    schema: []const u8,
    version: u32,
    repositories: []const Repository,
    keyring_paths: []const []const u8,
    architecture: []const u8,
    foreign_architectures: []const []const u8 = &.{},
    repository_policy: RepositoryPolicy = .strict_priority,
    cache_path: []const u8 = default_cache_path,
    state_path: []const u8 = default_state_path,
    default_conffile: ConffilePolicy = .keep_existing,
    network: NetworkPolicy = .{},
};

pub const LoadError = error{
    InvalidLimits,
    InvalidProfilePath,
    InvalidTrustedPath,
    NotRegularFile,
    OwnershipUnavailable,
    NotRootOwned,
    InsecurePermissions,
    EmptyTrustedFile,
    TrustedFileTooLarge,
    ProfileChangedWhileReading,
    InvalidDocument,
    UnsupportedSchema,
    TooManyRepositories,
    TooManyKeyrings,
    TooManyArchitectures,
    TooManyTrustedFiles,
    MissingRepository,
    MissingKeyring,
    InvalidArchitecture,
    DuplicateArchitecture,
    InvalidRepository,
    DuplicateRepository,
    DuplicateKeyring,
    InvalidCachePath,
    InvalidStatePath,
    InvalidProxy,
};

/// Loads and owns a strict profile and validates every trust-bearing file it
/// references. Unknown JSON fields are rejected.
pub fn load(
    allocator: std.mem.Allocator,
    file_system: FileSystem,
    profile_path: []const u8,
    limits: Limits,
) !LoadedProfile {
    try validateLimits(limits);
    if (!validTrustedPath(profile_path)) return error.InvalidProfilePath;

    const source = try file_system.read(
        allocator,
        profile_path,
        limits.maximum_profile_bytes,
    );
    defer allocator.free(source.bytes);
    try validateTrustedMetadata(source.metadata, limits.maximum_profile_bytes);
    if (source.metadata.size != source.bytes.len)
        return error.ProfileChangedWhileReading;

    var parsed = std.json.parseFromSlice(WireProfile, allocator, source.bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    }) catch return error.InvalidDocument;
    defer parsed.deinit();
    const wire = parsed.value;
    if (!std.mem.eql(u8, wire.schema, schema_id) or
        wire.version != schema_version)
        return error.UnsupportedSchema;

    const profile: Profile = .{
        .repositories = wire.repositories,
        .keyring_paths = wire.keyring_paths,
        .architecture = wire.architecture,
        .foreign_architectures = wire.foreign_architectures,
        .repository_policy = wire.repository_policy,
        .cache_path = wire.cache_path,
        .state_path = wire.state_path,
        .default_conffile = wire.default_conffile,
        .network = wire.network,
    };
    try validateProfile(profile, limits);

    var trusted_file_count: usize = 1 + profile.keyring_paths.len;
    for (profile.repositories) |repository|
        trusted_file_count += 1 + @intFromBool(repository.config_path != null);
    trusted_file_count += @intFromBool(
        profile.network.credential_reference != null,
    );
    if (trusted_file_count > limits.maximum_trusted_files)
        return error.TooManyTrustedFiles;

    for (profile.repositories) |repository| {
        try validateReference(file_system, repository.source_path, limits);
        if (repository.config_path) |path| {
            try validateReference(file_system, path, limits);
        }
    }
    for (profile.keyring_paths) |path| {
        try validateReference(file_system, path, limits);
    }
    if (profile.network.credential_reference) |path| {
        try validateReference(file_system, path, limits);
    }

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const repositories = try owned.alloc(Repository, profile.repositories.len);
    for (profile.repositories, 0..) |repository, index| {
        repositories[index] = .{
            .source_path = try owned.dupe(u8, repository.source_path),
            .config_path = try dupeOptional(owned, repository.config_path),
        };
    }
    const keyrings = try dupeStrings(owned, profile.keyring_paths);
    const foreign = try dupeStrings(owned, profile.foreign_architectures);
    const profile_path_owned = try owned.dupe(u8, profile_path);
    const owned_profile: Profile = .{
        .repositories = repositories,
        .keyring_paths = keyrings,
        .architecture = try owned.dupe(u8, profile.architecture),
        .foreign_architectures = foreign,
        .repository_policy = profile.repository_policy,
        .cache_path = try owned.dupe(u8, profile.cache_path),
        .state_path = try owned.dupe(u8, profile.state_path),
        .default_conffile = profile.default_conffile,
        .network = .{
            .proxy_url = try dupeOptional(owned, profile.network.proxy_url),
            .credential_reference = try dupeOptional(
                owned,
                profile.network.credential_reference,
            ),
        },
    };
    return .{
        .profile = owned_profile,
        .profile_path = profile_path_owned,
        .profile_sha256 = sha256(source.bytes),
        .trusted_file_count = trusted_file_count,
        .arena = arena,
        .backing_allocator = allocator,
    };
}

fn validateLimits(limits: Limits) LoadError!void {
    if (limits.maximum_profile_bytes == 0 or
        limits.maximum_profile_bytes > maximum_profile_bytes or
        limits.maximum_trusted_file_bytes == 0 or
        limits.maximum_trusted_file_bytes > maximum_trusted_file_bytes or
        limits.maximum_repositories == 0 or
        limits.maximum_repositories > maximum_repositories or
        limits.maximum_keyrings == 0 or
        limits.maximum_keyrings > maximum_keyrings or
        limits.maximum_foreign_architectures > maximum_foreign_architectures or
        limits.maximum_trusted_files == 0 or
        limits.maximum_trusted_files > maximum_trusted_files)
        return error.InvalidLimits;
}

fn validateProfile(profile: Profile, limits: Limits) LoadError!void {
    if (profile.repositories.len == 0) return error.MissingRepository;
    if (profile.repositories.len > limits.maximum_repositories)
        return error.TooManyRepositories;
    if (profile.keyring_paths.len == 0) return error.MissingKeyring;
    if (profile.keyring_paths.len > limits.maximum_keyrings)
        return error.TooManyKeyrings;
    if (profile.foreign_architectures.len > limits.maximum_foreign_architectures)
        return error.TooManyArchitectures;
    if (!validArchitecture(profile.architecture)) return error.InvalidArchitecture;
    if (!absolute_path.nonRoot(profile.cache_path) or
        profile.cache_path.len > maximum_path_bytes)
        return error.InvalidCachePath;
    if (!absolute_path.nonRoot(profile.state_path) or
        profile.state_path.len > maximum_path_bytes)
        return error.InvalidStatePath;

    for (profile.foreign_architectures, 0..) |architecture, index| {
        if (!validArchitecture(architecture)) return error.InvalidArchitecture;
        if (std.mem.eql(u8, architecture, profile.architecture))
            return error.DuplicateArchitecture;
        for (profile.foreign_architectures[0..index]) |previous|
            if (std.mem.eql(u8, architecture, previous))
                return error.DuplicateArchitecture;
    }
    for (profile.repositories, 0..) |repository, index| {
        if (!validTrustedPath(repository.source_path))
            return error.InvalidRepository;
        if (repository.config_path) |path| {
            if (!validTrustedPath(path) or
                std.mem.eql(u8, path, repository.source_path))
                return error.InvalidRepository;
        }
        for (profile.repositories[0..index]) |previous| {
            if (std.mem.eql(u8, repository.source_path, previous.source_path))
                return error.DuplicateRepository;
            if (repository.config_path) |path| {
                if (previous.config_path) |prior|
                    if (std.mem.eql(u8, path, prior))
                        return error.DuplicateRepository;
            }
        }
    }
    for (profile.keyring_paths, 0..) |path, index| {
        if (!validTrustedPath(path)) return error.InvalidTrustedPath;
        for (profile.keyring_paths[0..index]) |previous|
            if (std.mem.eql(u8, path, previous))
                return error.DuplicateKeyring;
    }
    if (profile.network.proxy_url) |proxy| {
        const uri = std.Uri.parse(proxy) catch return error.InvalidProxy;
        if (uri.user != null or uri.password != null or uri.host == null)
            return error.InvalidProxy;
        if (!std.ascii.eqlIgnoreCase(uri.scheme, "http") and
            !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
            return error.InvalidProxy;
    }
    if (profile.network.credential_reference) |path|
        if (!validTrustedPath(path)) return error.InvalidTrustedPath;
}

fn validateReference(
    file_system: FileSystem,
    path: []const u8,
    limits: Limits,
) !void {
    if (!validTrustedPath(path)) return error.InvalidTrustedPath;
    try validateTrustedMetadata(
        try file_system.inspect(path),
        limits.maximum_trusted_file_bytes,
    );
}

pub fn validateTrustedMetadata(metadata: Metadata, maximum_bytes: u64) LoadError!void {
    if (metadata.kind != .file) return error.NotRegularFile;
    if (!metadata.modeled) return error.OwnershipUnavailable;
    if (metadata.uid != 0) return error.NotRootOwned;
    if (metadata.mode & 0o022 != 0) return error.InsecurePermissions;
    if (metadata.size == 0) return error.EmptyTrustedFile;
    if (metadata.size > maximum_bytes) return error.TrustedFileTooLarge;
}

fn validTrustedPath(path: []const u8) bool {
    return path.len <= maximum_path_bytes and absolute_path.nonRoot(path);
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or value.len > 64) return false;
    for (value) |byte|
        if (!(std.ascii.isLower(byte) or std.ascii.isDigit(byte) or byte == '-'))
            return false;
    return true;
}

fn dupeOptional(
    allocator: std.mem.Allocator,
    value: ?[]const u8,
) std.mem.Allocator.Error!?[]const u8 {
    return if (value) |bytes| try allocator.dupe(u8, bytes) else null;
}

fn dupeStrings(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) std.mem.Allocator.Error![]const []const u8 {
    const result = try allocator.alloc([]const u8, values.len);
    for (values, 0..) |value, index|
        result[index] = try allocator.dupe(u8, value);
    return result;
}

fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

/// Production no-follow filesystem implementation. It reads uid, mode, kind,
/// and size from the opened descriptor on Linux.
pub const SystemFileSystem = struct {
    io: Io,

    pub fn interface(self: *SystemFileSystem) FileSystem {
        return .{
            .context = self,
            .readFn = read,
            .inspectFn = inspect,
        };
    }

    fn read(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        maximum_bytes: usize,
    ) !ReadResult {
        const self: *SystemFileSystem = @ptrCast(@alignCast(context));
        var file = try openAbsoluteFileNoFollow(self.io, path);
        defer file.close(self.io);
        const metadata = try metadataFromOpenFile(self.io, file);
        if (metadata.size > maximum_bytes) return error.StreamTooLong;
        var reader = file.reader(self.io, &.{});
        const bytes = try reader.interface.allocRemaining(
            allocator,
            .limited(maximum_bytes),
        );
        return .{ .bytes = bytes, .metadata = metadata };
    }

    fn inspect(context: *anyopaque, path: []const u8) !Metadata {
        const self: *SystemFileSystem = @ptrCast(@alignCast(context));
        var file = try openAbsoluteFileNoFollow(self.io, path);
        defer file.close(self.io);
        return metadataFromOpenFile(self.io, file);
    }
};

pub fn loadSystem(
    io: Io,
    allocator: std.mem.Allocator,
    profile_path: []const u8,
    limits: Limits,
) !LoadedProfile {
    var system: SystemFileSystem = .{ .io = io };
    return load(allocator, system.interface(), profile_path, limits);
}

fn openAbsoluteFileNoFollow(io: Io, path: []const u8) !File {
    if (!validTrustedPath(path)) return error.InvalidPath;
    const parent_path = std.fs.path.dirname(path) orelse return error.InvalidPath;
    const leaf = std.fs.path.basename(path);
    var parent = try openAbsoluteDirectoryNoFollow(io, parent_path);
    defer parent.close(io);
    return parent.openFile(io, leaf, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
        .resolve_beneath = true,
    });
}

fn openAbsoluteDirectoryNoFollow(io: Io, path: []const u8) !Io.Dir {
    if (std.mem.eql(u8, path, "/"))
        return Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
    if (!absolute_path.nonRoot(path)) return error.InvalidPath;
    var current = try Io.Dir.openDirAbsolute(io, "/", .{ .follow_symlinks = false });
    errdefer current.close(io);
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        const next = try current.openDir(io, component, .{
            .follow_symlinks = false,
        });
        current.close(io);
        current = next;
    }
    return current;
}

fn metadataFromOpenFile(io: Io, file: File) !Metadata {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const request: linux.STATX = .{
            .TYPE = true,
            .MODE = true,
            .UID = true,
            .SIZE = true,
        };
        var raw = std.mem.zeroes(linux.Statx);
        const empty: [*:0]const u8 = "";
        const flags: u32 = linux.AT.EMPTY_PATH | linux.AT.SYMLINK_NOFOLLOW |
            linux.AT.NO_AUTOMOUNT;
        switch (linux.errno(linux.statx(file.handle, empty, flags, request, &raw))) {
            .SUCCESS => {},
            .ACCES => return error.AccessDenied,
            .NOENT => return error.FileNotFound,
            .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
        const filled: u32 = @bitCast(raw.mask);
        const wanted: u32 = @bitCast(request);
        if (filled & wanted != wanted) return error.Unexpected;
        return .{
            .kind = statxKind(raw.mode),
            .size = raw.size,
            .mode = @as(u32, raw.mode) & 0o7777,
            .uid = raw.uid,
            .modeled = true,
        };
    }
    const stat = try file.stat(io);
    return .{
        .kind = stat.kind,
        .size = stat.size,
        .mode = if (builtin.os.tag == .windows)
            0
        else
            @intCast(stat.permissions.toMode() & 0o7777),
        .uid = 0,
        .modeled = false,
    };
}

fn statxKind(mode: u16) File.Kind {
    const S = std.os.linux.S;
    return switch (mode & S.IFMT) {
        S.IFDIR => .directory,
        S.IFCHR => .character_device,
        S.IFBLK => .block_device,
        S.IFREG => .file,
        S.IFIFO => .named_pipe,
        S.IFLNK => .sym_link,
        S.IFSOCK => .unix_domain_socket,
        else => .unknown,
    };
}

const FakeFileSystem = struct {
    profile_source: []const u8,
    profile_mode: u32 = 0o640,
    profile_uid: u32 = 0,
    profile_kind: File.Kind = .file,
    override_path: ?[]const u8 = null,
    override_metadata: Metadata = .{
        .kind = .file,
        .size = 1,
        .mode = 0o644,
        .uid = 0,
    },

    fn interface(self: *FakeFileSystem) FileSystem {
        return .{ .context = self, .readFn = read, .inspectFn = inspect };
    }

    fn read(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        path: []const u8,
        _: usize,
    ) !ReadResult {
        const self: *FakeFileSystem = @ptrCast(@alignCast(context));
        if (!std.mem.eql(u8, path, default_profile_path)) return error.FileNotFound;
        return .{
            .bytes = try allocator.dupe(u8, self.profile_source),
            .metadata = .{
                .kind = self.profile_kind,
                .size = self.profile_source.len,
                .mode = self.profile_mode,
                .uid = self.profile_uid,
            },
        };
    }

    fn inspect(context: *anyopaque, path: []const u8) !Metadata {
        const self: *FakeFileSystem = @ptrCast(@alignCast(context));
        if (self.override_path) |expected|
            if (std.mem.eql(u8, expected, path))
                return self.override_metadata;
        return .{ .kind = .file, .size = 32, .mode = 0o644, .uid = 0 };
    }
};

const valid_profile_json =
    \\{"schema":"https://debz.dev/schema/system-profile-v1","version":1,
    \\"repositories":[{"source_path":"/etc/debz/debian.sources","config_path":"/etc/debz/debian.json"}],
    \\"keyring_paths":["/usr/share/keyrings/debian-archive-keyring.gpg"],
    \\"architecture":"amd64","foreign_architectures":["i386"],
    \\"repository_policy":"strict_priority","cache_path":"/var/cache/debz",
    \\"state_path":"/var/lib/debz","default_conffile":"keep_existing",
    \\"network":{"proxy_url":null,"credential_reference":null}}
;

const defaulted_profile_json =
    \\{"schema":"https://debz.dev/schema/system-profile-v1","version":1,
    \\"repositories":[{"source_path":"/etc/debz/debian.sources"}],
    \\"keyring_paths":["/usr/share/keyrings/debian-archive-keyring.gpg"],
    \\"architecture":"amd64"}
;

test "system_profile.test.strict profile loads only explicit trusted inputs" {
    var fake: FakeFileSystem = .{ .profile_source = valid_profile_json };
    var loaded = try load(
        std.testing.allocator,
        fake.interface(),
        default_profile_path,
        .{},
    );
    defer loaded.deinit();
    try std.testing.expectEqualStrings("amd64", loaded.profile.architecture);
    try std.testing.expectEqualStrings(default_cache_path, loaded.profile.cache_path);
    try std.testing.expectEqualStrings(default_state_path, loaded.profile.state_path);
    try std.testing.expectEqual(@as(usize, 4), loaded.trusted_file_count);
    try std.testing.expect(loaded.profile.network.proxy_url == null);
    try std.testing.expect(loaded.profile.network.credential_reference == null);
}

test "system_profile.test.omitted locations select only debz safe defaults" {
    var fake: FakeFileSystem = .{ .profile_source = defaulted_profile_json };
    var loaded = try load(
        std.testing.allocator,
        fake.interface(),
        default_profile_path,
        .{},
    );
    defer loaded.deinit();
    try std.testing.expectEqualStrings(default_cache_path, loaded.profile.cache_path);
    try std.testing.expectEqualStrings(default_state_path, loaded.profile.state_path);
    try std.testing.expectEqual(ConffilePolicy.keep_existing, loaded.profile.default_conffile);
    try std.testing.expect(loaded.profile.network.proxy_url == null);
    try std.testing.expect(loaded.profile.network.credential_reference == null);
}

test "system_profile.test.unknown fields and unsafe paths are rejected" {
    const unknown =
        \\{"schema":"https://debz.dev/schema/system-profile-v1","version":1,
        \\"repositories":[],"keyring_paths":[],"architecture":"amd64","ambient_apt":true}
    ;
    var fake: FakeFileSystem = .{ .profile_source = unknown };
    try std.testing.expectError(
        error.InvalidDocument,
        load(std.testing.allocator, fake.interface(), default_profile_path, .{}),
    );
    try std.testing.expectError(
        error.InvalidProfilePath,
        load(std.testing.allocator, fake.interface(), "/etc/debz/../default.json", .{}),
    );
    fake.profile_source = valid_profile_json;
    try std.testing.expectError(
        error.TooManyTrustedFiles,
        load(std.testing.allocator, fake.interface(), default_profile_path, .{
            .maximum_trusted_files = 3,
        }),
    );
}

test "system_profile.test.trusted files require root ownership and safe modes" {
    var fake: FakeFileSystem = .{
        .profile_source = valid_profile_json,
        .override_path = "/etc/debz/debian.sources",
        .override_metadata = .{
            .kind = .file,
            .size = 32,
            .mode = 0o664,
            .uid = 0,
        },
    };
    try std.testing.expectError(
        error.InsecurePermissions,
        load(std.testing.allocator, fake.interface(), default_profile_path, .{}),
    );
    fake.override_metadata = .{
        .kind = .file,
        .size = 32,
        .mode = 0o644,
        .uid = 1000,
    };
    try std.testing.expectError(
        error.NotRootOwned,
        load(std.testing.allocator, fake.interface(), default_profile_path, .{}),
    );
    fake.override_metadata = .{
        .kind = .sym_link,
        .size = 32,
        .mode = 0o644,
        .uid = 0,
    };
    try std.testing.expectError(
        error.NotRegularFile,
        load(std.testing.allocator, fake.interface(), default_profile_path, .{}),
    );
}

test "system_profile.test.profile file itself is trust validated" {
    var fake: FakeFileSystem = .{
        .profile_source = valid_profile_json,
        .profile_mode = 0o662,
    };
    try std.testing.expectError(
        error.InsecurePermissions,
        load(std.testing.allocator, fake.interface(), default_profile_path, .{}),
    );
    fake.profile_mode = 0o640;
    fake.profile_uid = 1000;
    try std.testing.expectError(
        error.NotRootOwned,
        load(std.testing.allocator, fake.interface(), default_profile_path, .{}),
    );
    fake.profile_uid = 0;
    fake.profile_kind = .sym_link;
    try std.testing.expectError(
        error.NotRegularFile,
        load(std.testing.allocator, fake.interface(), default_profile_path, .{}),
    );
}

test "system_profile.test.profile schema uses the shared absolute path grammar" {
    const source = try Io.Dir.cwd().readFileAlloc(
        std.testing.io,
        "schema/system-profile-v1.json",
        std.testing.allocator,
        .limited(maximum_profile_bytes),
    );
    defer std.testing.allocator.free(source);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, source, .{});
    defer parsed.deinit();
    const pattern = parsed.value.object.get("$defs").?.object
        .get("absolutePath").?.object.get("pattern").?.string;
    try std.testing.expectEqualStrings(absolute_path.schema_pattern, pattern);
}
