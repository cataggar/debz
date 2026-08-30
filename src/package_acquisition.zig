const std = @import("std");
const acquisition = @import("repository_acquisition.zig");
const metadata_cache = @import("metadata_cache.zig");
const packages_index = @import("packages_index.zig");
const solver = @import("solver.zig");
const source = @import("source.zig");
const exact_lock = @import("exact_lock.zig");

const Dir = std.Io.Dir;
const File = std.Io.File;

pub const namespace = "packages-v1";
pub const Digest = metadata_cache.Digest;

pub const SelectedPackage = struct {
    repository_id: source.RepositoryId,
    repository_priority: i32,
    record: *const packages_index.PackageRecord,
    repository_base_uri: acquisition.Uri,
    authenticated_snapshot_sha256: ?[32]u8,

    /// Accepts only a package origin emitted by a solver context and a
    /// cryptographically verified repository import.
    pub fn fromSolverSelection(
        repository: solver.RepositoryInput,
        origin: solver.PackageOrigin,
        repository_base_uri: acquisition.Uri,
    ) SelectionError!SelectedPackage {
        if (repository.eligibility != .verified_refresh) return error.UnauthenticatedRepository;
        return checked(repository, origin, repository_base_uri);
    }

    /// Test-only trust boundary, matching `SolverRepositoryInput.trustedTest`.
    pub fn fromTrustedTest(
        repository: solver.RepositoryInput,
        origin: solver.PackageOrigin,
        repository_base_uri: acquisition.Uri,
    ) SelectionError!SelectedPackage {
        if (repository.eligibility != .trusted_test) return error.UnauthenticatedRepository;
        return checked(repository, origin, repository_base_uri);
    }

    fn checked(
        repository: solver.RepositoryInput,
        origin: solver.PackageOrigin,
        repository_base_uri: acquisition.Uri,
    ) SelectionError!SelectedPackage {
        if (!std.mem.eql(u8, repository.repository_id.slice(), origin.repository_id.slice()) or
            repository.priority != origin.repository_priority or
            origin.record_index >= repository.packages.records.len)
            return error.ConflictingProvenance;
        const record = &repository.packages.records[origin.record_index];
        if (!std.mem.eql(u8, record.control.package.text, origin.package) or
            !std.mem.eql(u8, record.control.version.value.original, origin.version) or
            !std.mem.eql(u8, record.control.architecture.text, origin.architecture) or
            !std.mem.eql(u8, record.location.source, origin.source_location))
            return error.ConflictingProvenance;
        try validateBaseUri(repository_base_uri);
        return .{
            .repository_id = repository.repository_id,
            .repository_priority = repository.priority,
            .record = record,
            .repository_base_uri = repository_base_uri,
            .authenticated_snapshot_sha256 = repository.authenticated_snapshot_sha256,
        };
    }
};

pub const SelectionError = error{
    UnauthenticatedRepository,
    ConflictingProvenance,
    UnsupportedScheme,
    CredentialBearingBaseUri,
    InvalidBaseUri,
};

pub const Mode = enum { online, cache_only };
pub const Workflow = enum { transaction, download_only };
pub const Outcome = enum { cache_hit, downloaded };
pub const CacheIntegrityPolicy = enum { verify_sha256 };
pub const CorruptCachePolicy = enum { fail, repair_online };

pub const Policy = struct {
    mode: Mode,
    workflow: Workflow = .transaction,
    maximum_package_bytes: usize,
    cache_integrity: CacheIntegrityPolicy = .verify_sha256,
    corrupt_cache: CorruptCachePolicy = .fail,
    proxy: acquisition.ProxyPolicy = .direct,
    deadlines: acquisition.Deadlines,
    redirect_limit: u16,
    retry: acquisition.RetryPolicy = .{},
    credentials: acquisition.CredentialsProvider = .none,
    cache_lock: LockPolicy = .fail_fast,
};

pub const Request = struct {
    selected: SelectedPackage,
    policy: Policy,
    exact_lock_package: ?exact_lock.Package = null,
};

pub const Provenance = struct {
    repository_id: source.RepositoryId,
    repository_priority: i32,
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    resolved_uri: []u8,
    expected_sha256: Digest,
    declared_size: u64,
    cache_key: [64]u8,
    outcome: Outcome,
    workflow: Workflow,
    attempts: u16,

    pub fn deinit(self: *Provenance, allocator: std.mem.Allocator) void {
        allocator.free(self.package);
        allocator.free(self.version);
        allocator.free(self.architecture);
        allocator.free(self.resolved_uri);
        self.* = undefined;
    }
};

/// An owned, already revalidated package object. Keeping bytes owned by the
/// handle makes concurrent garbage collection unable to invalidate a reader.
pub const VerifiedPackage = struct {
    bytes: []u8,
    provenance: Provenance,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *VerifiedPackage) void {
        self.allocator.free(self.bytes);
        self.provenance.deinit(self.allocator);
        self.* = undefined;
    }
};

pub const Error = SelectionError || error{
    InvalidConfiguration,
    PackageTooLarge,
    SizeMismatch,
    DigestMismatch,
    CacheMiss,
    CorruptObject,
    LockBusy,
    LockPackageMismatch,
};

pub const LockPolicy = union(enum) {
    fail_fast,
    injected: Lock,
};

pub const Lock = struct {
    context: *anyopaque,
    acquireFn: *const fn (*anyopaque) anyerror!*anyopaque,
    releaseFn: *const fn (*anyopaque, *anyopaque) void,
};

pub const PublishHooks = struct {
    context: ?*anyopaque = null,
    stagedFn: ?*const fn (?*anyopaque) anyerror!void = null,

    fn staged(self: PublishHooks) !void {
        if (self.stagedFn) |run| try run(self.context);
    }
};

pub const CacheLimits = struct {
    maximum_object_bytes: usize,
};

pub const GcOptions = struct {
    retained: []const Digest = &.{},
    maximum_directory_entries: usize,
    maximum_objects_scanned: usize,
    maximum_objects_deleted: usize,
    maximum_bytes_deleted: u64,
    lock: LockPolicy = .fail_fast,
};

pub const GcResult = struct {
    scanned: usize,
    deleted: usize,
    bytes_deleted: u64,
    complete: bool,
};

pub const CleanupResult = struct {
    scanned: usize,
    deleted: usize,
    complete: bool,
};

pub const Cache = struct {
    io: std.Io,
    root: Dir,
    owns_root: bool,
    packages: Dir,
    objects: Dir,
    staging: Dir,
    locks: Dir,
    limits: CacheLimits,

    pub fn init(io: std.Io, root_path: []const u8, limits: CacheLimits) !Cache {
        if (root_path.len == 0) return error.InvalidConfiguration;
        try Dir.cwd().createDirPath(io, root_path);
        const root = try Dir.cwd().openDir(io, root_path, .{ .follow_symlinks = false });
        errdefer root.close(io);
        var result = try initFromDir(io, root, limits);
        result.owns_root = true;
        return result;
    }

    pub fn initFromDir(io: std.Io, root: Dir, limits: CacheLimits) !Cache {
        if (limits.maximum_object_bytes == 0) return error.InvalidConfiguration;
        try ensureDirectory(io, root, namespace, dirPermissions(false));
        const packages = try root.openDir(io, namespace, .{ .follow_symlinks = false });
        errdefer packages.close(io);
        try ensureDirectory(io, packages, "objects", dirPermissions(false));
        try ensureDirectory(io, packages, "staging", dirPermissions(true));
        try ensureDirectory(io, packages, "locks", dirPermissions(true));
        const objects = try packages.openDir(io, "objects", .{ .iterate = true, .follow_symlinks = false });
        errdefer objects.close(io);
        const staging = try packages.openDir(io, "staging", .{ .iterate = true, .follow_symlinks = false });
        errdefer staging.close(io);
        const locks = try packages.openDir(io, "locks", .{ .follow_symlinks = false });
        errdefer locks.close(io);
        return .{
            .io = io,
            .root = root,
            .owns_root = false,
            .packages = packages,
            .objects = objects,
            .staging = staging,
            .locks = locks,
            .limits = limits,
        };
    }

    pub fn deinit(self: *Cache) void {
        self.locks.close(self.io);
        self.staging.close(self.io);
        self.objects.close(self.io);
        self.packages.close(self.io);
        if (self.owns_root) self.root.close(self.io);
        self.* = undefined;
    }

    pub fn lookup(
        self: *Cache,
        allocator: std.mem.Allocator,
        digest: Digest,
        expected_size: u64,
        integrity: CacheIntegrityPolicy,
    ) ![]u8 {
        _ = integrity;
        if (expected_size > self.limits.maximum_object_bytes) return error.PackageTooLarge;
        var name: [64]u8 = undefined;
        digest.formatHex(&name);
        const bytes = secureReadAlloc(
            self.objects,
            self.io,
            &name,
            allocator,
            .limited(@intCast(expected_size +| 1)),
        ) catch |err| switch (err) {
            error.FileNotFound => return error.CacheMiss,
            error.StreamTooLong, error.SymLinkLoop, error.NotDir, error.AccessDenied => return error.CorruptObject,
            else => |e| return e,
        };
        errdefer allocator.free(bytes);
        if (bytes.len != expected_size or !Digest.of(bytes).eql(digest)) return error.CorruptObject;
        return bytes;
    }

    pub fn publish(
        self: *Cache,
        allocator: std.mem.Allocator,
        digest: Digest,
        expected_size: u64,
        bytes: []const u8,
        lock: LockPolicy,
        hooks: PublishHooks,
    ) !void {
        if (expected_size > self.limits.maximum_object_bytes or bytes.len > self.limits.maximum_object_bytes)
            return error.PackageTooLarge;
        if (bytes.len != expected_size) return error.SizeMismatch;
        if (!Digest.of(bytes).eql(digest)) return error.DigestMismatch;

        var held = try self.acquire(lock);
        defer held.release(self);
        var name: [64]u8 = undefined;
        digest.formatHex(&name);

        if (self.lookup(allocator, digest, expected_size, .verify_sha256)) |existing| {
            allocator.free(existing);
            return;
        } else |err| switch (err) {
            error.CacheMiss => {},
            error.CorruptObject => self.objects.deleteFile(self.io, &name) catch |delete_err| switch (delete_err) {
                error.FileNotFound => {},
                else => |e| return e,
            },
            else => |e| return e,
        }

        const stage = try stageName(digest);
        defer self.staging.deleteFile(self.io, &stage) catch {};
        {
            var file = try self.staging.createFile(self.io, &stage, .{
                .exclusive = true,
                .permissions = filePermissions(),
                .resolve_beneath = true,
            });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, bytes);
            try file.sync(self.io);
        }
        try hooks.staged();
        try self.staging.rename(&stage, self.objects, &name, self.io);
        try syncDirectory(self.io, self.objects);
    }

    pub fn cleanupStaging(
        self: *Cache,
        allocator: std.mem.Allocator,
        maximum_entries: usize,
        lock: LockPolicy,
    ) !CleanupResult {
        var held = try self.acquire(lock);
        defer held.release(self);
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |name| allocator.free(name);
            names.deinit(allocator);
        }
        var iterator = self.staging.iterate();
        while (try iterator.next(self.io)) |entry| {
            if (names.items.len == maximum_entries) return .{
                .scanned = maximum_entries,
                .deleted = 0,
                .complete = false,
            };
            try names.append(allocator, try allocator.dupe(u8, entry.name));
        }
        sortNames(names.items);
        var deleted: usize = 0;
        for (names.items) |name| {
            self.staging.deleteFile(self.io, name) catch |err| switch (err) {
                error.FileNotFound => continue,
                else => |e| return e,
            };
            deleted += 1;
        }
        return .{ .scanned = names.items.len, .deleted = deleted, .complete = true };
    }

    /// Deterministically deletes sorted, unretained CAS objects within all
    /// configured object, byte, scan, and directory-entry bounds.
    pub fn garbageCollect(
        self: *Cache,
        allocator: std.mem.Allocator,
        options: GcOptions,
    ) !GcResult {
        var held = try self.acquire(options.lock);
        defer held.release(self);
        var names: std.ArrayList([]u8) = .empty;
        defer {
            for (names.items) |name| allocator.free(name);
            names.deinit(allocator);
        }
        var iterator = self.objects.iterate();
        while (try iterator.next(self.io)) |entry| {
            if (names.items.len == options.maximum_directory_entries)
                return .{ .scanned = 0, .deleted = 0, .bytes_deleted = 0, .complete = false };
            try names.append(allocator, try allocator.dupe(u8, entry.name));
        }
        sortNames(names.items);
        var result: GcResult = .{ .scanned = 0, .deleted = 0, .bytes_deleted = 0, .complete = true };
        for (names.items) |name| {
            if (result.scanned == options.maximum_objects_scanned) {
                result.complete = false;
                break;
            }
            result.scanned += 1;
            const digest = Digest.parseHex(name) catch {
                result.complete = false;
                continue;
            };
            if (containsDigest(options.retained, digest)) continue;
            if (result.deleted == options.maximum_objects_deleted) {
                result.complete = false;
                continue;
            }
            var file = self.objects.openFile(self.io, name, .{
                .follow_symlinks = false,
                .resolve_beneath = true,
            }) catch {
                result.complete = false;
                continue;
            };
            const stat = file.stat(self.io) catch {
                file.close(self.io);
                result.complete = false;
                continue;
            };
            file.close(self.io);
            if (stat.size > options.maximum_bytes_deleted -| result.bytes_deleted) {
                result.complete = false;
                continue;
            }
            try self.objects.deleteFile(self.io, name);
            result.deleted += 1;
            result.bytes_deleted += stat.size;
        }
        return result;
    }

    const HeldLock = union(enum) {
        file: File,
        injected: struct { lock: Lock, token: *anyopaque },

        fn release(self: *HeldLock, cache: *Cache) void {
            switch (self.*) {
                .file => |file| file.close(cache.io),
                .injected => |held| held.lock.releaseFn(held.lock.context, held.token),
            }
        }
    };

    fn acquire(self: *Cache, policy: LockPolicy) !HeldLock {
        return switch (policy) {
            .fail_fast => .{ .file = self.locks.createFile(self.io, "writer.lock", .{
                .lock = .exclusive,
                .lock_nonblocking = true,
                .permissions = filePermissions(),
                .resolve_beneath = true,
            }) catch |err| switch (err) {
                error.WouldBlock => return error.LockBusy,
                else => |e| return e,
            } },
            .injected => |lock| .{ .injected = .{
                .lock = lock,
                .token = lock.acquireFn(lock.context) catch return error.LockBusy,
            } },
        };
    }
};

pub fn acquirePackage(
    allocator: std.mem.Allocator,
    cache: *Cache,
    request: Request,
    dependencies: acquisition.Dependencies,
) !VerifiedPackage {
    const record = request.selected.record;
    const declared_size = record.transport.size.value;
    if (request.exact_lock_package) |locked| {
        if (!std.mem.eql(u8, locked.name, record.control.package.text) or
            !std.mem.eql(u8, locked.version, record.control.version.value.original) or
            !std.mem.eql(u8, locked.architecture, record.control.architecture.text) or
            !std.mem.eql(u8, &locked.repository_id, request.selected.repository_id.slice()) or
            request.selected.authenticated_snapshot_sha256 == null or
            !std.mem.eql(u8, &locked.repository_snapshot_sha256, &request.selected.authenticated_snapshot_sha256.?) or
            !std.mem.eql(u8, &locked.sha256, &record.transport.sha256.bytes) or
            locked.declared_size != declared_size)
            return error.LockPackageMismatch;
    }
    if (request.policy.maximum_package_bytes == 0 or
        declared_size > request.policy.maximum_package_bytes or
        declared_size > cache.limits.maximum_object_bytes)
        return error.PackageTooLarge;
    const digest: Digest = .{ .bytes = record.transport.sha256.bytes };
    var cache_key: [64]u8 = undefined;
    digest.formatHex(&cache_key);
    const resolved = try resolvePackageUri(allocator, request.selected.repository_base_uri, record.transport.filename.value);
    defer allocator.free(resolved.text);

    if (cache.lookup(allocator, digest, declared_size, request.policy.cache_integrity)) |bytes| {
        return makeResult(allocator, request, bytes, resolved.uri, digest, cache_key, .cache_hit, 0);
    } else |cache_err| switch (cache_err) {
        error.CacheMiss => {},
        error.CorruptObject => {
            if (request.policy.mode == .cache_only or request.policy.corrupt_cache == .fail)
                return error.CorruptObject;
        },
        else => |e| return e,
    }
    if (request.policy.mode == .cache_only) return error.CacheMiss;

    var downloaded = try acquisition.acquire(allocator, .{
        .uri = resolved.uri,
        .proxy = request.policy.proxy,
        .deadlines = request.policy.deadlines,
        .redirect_limit = request.policy.redirect_limit,
        .retry = request.policy.retry,
        .max_response_bytes = @intCast(@min(
            request.policy.maximum_package_bytes,
            std.math.add(u64, declared_size, 1) catch declared_size,
        )),
        .credentials = request.policy.credentials,
    }, dependencies);
    defer downloaded.deinit(allocator);
    if (downloaded.bytes.len != declared_size) return error.SizeMismatch;
    if (!Digest.of(downloaded.bytes).eql(digest)) return error.DigestMismatch;
    try cache.publish(
        allocator,
        digest,
        declared_size,
        downloaded.bytes,
        request.policy.cache_lock,
        .{},
    );
    const owned = try allocator.dupe(u8, downloaded.bytes);
    return makeResult(
        allocator,
        request,
        owned,
        try acquisition.Uri.parse(downloaded.provenance.effective_uri),
        digest,
        cache_key,
        .downloaded,
        downloaded.provenance.timing.attempts,
    );
}

fn makeResult(
    allocator: std.mem.Allocator,
    request: Request,
    bytes: []u8,
    effective_uri: acquisition.Uri,
    digest: Digest,
    cache_key: [64]u8,
    outcome: Outcome,
    attempts: u16,
) !VerifiedPackage {
    errdefer allocator.free(bytes);
    const package = try allocator.dupe(u8, request.selected.record.control.package.text);
    errdefer allocator.free(package);
    const version = try allocator.dupe(u8, request.selected.record.control.version.value.original);
    errdefer allocator.free(version);
    const architecture = try allocator.dupe(u8, request.selected.record.control.architecture.text);
    errdefer allocator.free(architecture);
    const resolved_uri = try acquisition.redactUri(allocator, effective_uri);
    errdefer allocator.free(resolved_uri);
    return .{
        .bytes = bytes,
        .allocator = allocator,
        .provenance = .{
            .repository_id = request.selected.repository_id,
            .repository_priority = request.selected.repository_priority,
            .package = package,
            .version = version,
            .architecture = architecture,
            .resolved_uri = resolved_uri,
            .expected_sha256 = digest,
            .declared_size = request.selected.record.transport.size.value,
            .cache_key = cache_key,
            .outcome = outcome,
            .workflow = request.policy.workflow,
            .attempts = attempts,
        },
    };
}

fn validateBaseUri(uri: acquisition.Uri) SelectionError!void {
    if (!std.ascii.eqlIgnoreCase(uri.scheme, "file") and
        !std.ascii.eqlIgnoreCase(uri.scheme, "http") and
        !std.ascii.eqlIgnoreCase(uri.scheme, "https"))
        return error.UnsupportedScheme;
    if (uri.user != null or uri.password != null) return error.CredentialBearingBaseUri;
    if (uri.query != null or uri.fragment != null) return error.InvalidBaseUri;
}

fn resolvePackageUri(
    allocator: std.mem.Allocator,
    base: acquisition.Uri,
    filename: []const u8,
) !struct { text: []u8, uri: acquisition.Uri } {
    try validateBaseUri(base);
    if (filename.len == 0 or filename[0] == '/' or filename[0] == '\\' or
        std.mem.indexOfScalar(u8, filename, '\\') != null or
        std.mem.indexOfScalar(u8, filename, 0) != null)
        return error.InvalidBaseUri;
    var segments = std.mem.splitScalar(u8, filename, '/');
    while (segments.next()) |segment| {
        if (segment.len == 0 or std.mem.eql(u8, segment, ".") or std.mem.eql(u8, segment, ".."))
            return error.InvalidBaseUri;
    }
    const base_text = try acquisition.redactUri(allocator, base);
    defer allocator.free(base_text);
    const separator = if (std.mem.endsWith(u8, base_text, "/")) "" else "/";
    const text = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{ base_text, separator, filename });
    errdefer allocator.free(text);
    return .{ .text = text, .uri = acquisition.Uri.parse(text) catch return error.InvalidBaseUri };
}

fn containsDigest(values: []const Digest, wanted: Digest) bool {
    for (values) |value| if (value.eql(wanted)) return true;
    return false;
}

fn sortNames(names: [][]u8) void {
    std.mem.sort([]u8, names, {}, struct {
        fn less(_: void, a: []u8, b: []u8) bool {
            return std.mem.lessThan(u8, a, b);
        }
    }.less);
}

var stage_counter: std.atomic.Value(u64) = .init(0);

fn stageName(digest: Digest) ![96]u8 {
    var digest_hex: [64]u8 = undefined;
    digest.formatHex(&digest_hex);
    var result: [96]u8 = undefined;
    const written = try std.fmt.bufPrint(&result, "package-{s}-{x:0>16}.tmp", .{
        digest_hex[0..8],
        stage_counter.fetchAdd(1, .monotonic),
    });
    @memset(result[written.len..], '_');
    return result;
}

fn ensureDirectory(io: std.Io, parent: Dir, name: []const u8, permissions: File.Permissions) !void {
    parent.createDir(io, name, permissions) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => |e| return e,
    };
    var child = try parent.openDir(io, name, .{ .follow_symlinks = false });
    child.close(io);
}

fn filePermissions() File.Permissions {
    return if (@import("builtin").os.tag == .windows) .default_file else .fromMode(0o600);
}

fn dirPermissions(private: bool) File.Permissions {
    if (@import("builtin").os.tag == .windows) return .default_dir;
    return .fromMode(if (private) 0o700 else 0o755);
}

fn syncDirectory(io: std.Io, dir: Dir) !void {
    _ = io;
    switch (@import("builtin").os.tag) {
        .linux => if (std.posix.errno(std.os.linux.fsync(dir.handle)) != .SUCCESS)
            return error.Unexpected,
        else => {},
    }
}

fn secureReadAlloc(
    dir: Dir,
    io: std.Io,
    path: []const u8,
    allocator: std.mem.Allocator,
    limit: std.Io.Limit,
) ![]u8 {
    var file = try dir.openFile(io, path, .{ .follow_symlinks = false, .resolve_beneath = true });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, limit) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => |e| return e,
    };
}

const TestResponse = struct {
    status: u16 = 200,
    body: []const u8,
    location: ?[]const u8 = null,
    failure: ?anyerror = null,
};

const TestTransport = struct {
    responses: []const TestResponse = &.{},
    count: usize = 0,
    now_ms: u64 = 0,
    authorization_seen: [8]bool = @splat(false),
    proxy_seen: bool = false,

    fn dependencies(self: *TestTransport) acquisition.Dependencies {
        return .{
            .transport = .{ .context = self, .requestFn = request },
            .files = .{ .context = self, .readFn = readFile },
            .clock = .{ .context = self, .nowMsFn = nowMs, .sleepMsFn = sleepMs },
        };
    }

    fn request(
        context: ?*anyopaque,
        allocator: std.mem.Allocator,
        value: acquisition.HttpRequest,
    ) !acquisition.HttpResponse {
        const self: *TestTransport = @ptrCast(@alignCast(context.?));
        if (self.count >= self.responses.len) return error.ConnectionResetByPeer;
        const index = self.count;
        self.count += 1;
        self.authorization_seen[index] = value.authorization != null;
        self.proxy_seen = value.proxy.http != null or value.proxy.https != null;
        const response = self.responses[index];
        if (response.failure) |failure| return failure;
        if (response.body.len > value.max_response_bytes) return error.ResponseTooLarge;
        return .{
            .status = response.status,
            .body = try allocator.dupe(u8, response.body),
            .location = if (response.location) |location| try allocator.dupe(u8, location) else null,
        };
    }

    fn readFile(
        _: ?*anyopaque,
        _: std.mem.Allocator,
        _: []const u8,
        _: usize,
        _: acquisition.Deadlines,
    ) !acquisition.FileRead {
        return error.FileNotFound;
    }

    fn nowMs(context: ?*anyopaque) u64 {
        const self: *TestTransport = @ptrCast(@alignCast(context.?));
        return self.now_ms;
    }

    fn sleepMs(context: ?*anyopaque, milliseconds: u64) !void {
        const self: *TestTransport = @ptrCast(@alignCast(context.?));
        self.now_ms += milliseconds;
    }
};

const TestSelection = struct {
    index_bytes: []u8,
    index: *packages_index.Index,
    repository: solver.RepositoryInput,
    origin: solver.PackageOrigin,
    selected: SelectedPackage,

    fn deinit(self: *TestSelection, allocator: std.mem.Allocator) void {
        self.index.deinit();
        allocator.destroy(self.index);
        allocator.free(self.index_bytes);
        self.* = undefined;
    }
};

fn testSelection(allocator: std.mem.Allocator, payload: []const u8) !TestSelection {
    const digest = Digest.of(payload);
    var digest_hex: [64]u8 = undefined;
    digest.formatHex(&digest_hex);
    const bytes = try std.fmt.allocPrint(
        allocator,
        \\Package: demo
        \\Version: 1.2.3-1
        \\Architecture: amd64
        \\Description: test package
        \\Filename: pool/main/d/demo_1.2.3-1_amd64.deb
        \\Size: {d}
        \\SHA256: {s}
        \\
    ,
        .{ payload.len, &digest_hex },
    );
    errdefer allocator.free(bytes);
    const repository_id: source.RepositoryId = .{ .bytes = @splat('a') };
    const index = try allocator.create(packages_index.Index);
    errdefer allocator.destroy(index);
    index.* = switch (try packages_index.parseBorrowed(allocator, bytes, .{
        .repository_id = repository_id,
        .component = "main",
        .architecture = "amd64",
        .source_location = "dists/stable/main/binary-amd64/Packages",
    }, .{})) {
        .index => |value| value,
        .diagnostic => return error.InvalidTestIndex,
    };
    errdefer index.deinit();
    const repository = solver.RepositoryInput.trustedTest(repository_id, 500, index);
    const record = &index.records[0];
    const origin: solver.PackageOrigin = .{
        .repository_id = repository_id,
        .repository_priority = 500,
        .record_index = 0,
        .package = record.control.package.text,
        .version = record.control.version.value.original,
        .architecture = record.control.architecture.text,
        .source_location = record.location.source,
    };
    return .{
        .index_bytes = bytes,
        .index = index,
        .repository = repository,
        .origin = origin,
        .selected = try SelectedPackage.fromTrustedTest(
            repository,
            origin,
            try acquisition.Uri.parse("https://packages.example/repository"),
        ),
    };
}

fn testPolicy(mode: Mode) Policy {
    return .{
        .mode = mode,
        .maximum_package_bytes = 1024,
        .deadlines = .{ .connect_ms = 50, .read_ms = 100, .overall_ms = 500 },
        .redirect_limit = 2,
    };
}

fn testCache(tmp: *std.testing.TmpDir) !Cache {
    return Cache.initFromDir(std.testing.io, tmp.dir, .{ .maximum_object_bytes = 1024 });
}

test "authenticated solver selection rejects untrusted and conflicting provenance" {
    var selection = try testSelection(std.testing.allocator, "package payload");
    defer selection.deinit(std.testing.allocator);
    var untrusted = selection.repository;
    untrusted.eligibility = .untrusted;
    try std.testing.expectError(error.UnauthenticatedRepository, SelectedPackage.fromSolverSelection(
        untrusted,
        selection.origin,
        try acquisition.Uri.parse("https://packages.example/repository"),
    ));
    var conflicting = selection.origin;
    conflicting.version = "different";
    try std.testing.expectError(error.ConflictingProvenance, SelectedPackage.fromTrustedTest(
        selection.repository,
        conflicting,
        try acquisition.Uri.parse("https://packages.example/repository"),
    ));
    try std.testing.expectError(error.CredentialBearingBaseUri, SelectedPackage.fromTrustedTest(
        selection.repository,
        selection.origin,
        try acquisition.Uri.parse("https://user:secret@packages.example/repository"),
    ));
}

test "package_acquisition.test.exact lock rejects repository and artifact substitution" {
    var selection = try testSelection(std.testing.allocator, "package payload");
    defer selection.deinit(std.testing.allocator);
    selection.selected.authenticated_snapshot_sha256 = @splat(1);
    var cache_dir = std.testing.tmpDir(.{});
    defer cache_dir.cleanup();
    var cache = try testCache(&cache_dir);
    defer cache.deinit();
    var transport: TestTransport = .{};
    const locked: exact_lock.Package = .{
        .name = "demo",
        .version = "1.2.3-1",
        .architecture = "amd64",
        .repository_id = selection.repository.repository_id.bytes,
        .repository_snapshot_sha256 = @splat(2),
        .sha256 = selection.index.records[0].transport.sha256.bytes,
        .declared_size = selection.index.records[0].transport.size.value,
        .retention = .requested,
        .dpkg_selection_hold = false,
    };
    try std.testing.expectError(error.LockPackageMismatch, acquirePackage(
        std.testing.allocator,
        &cache,
        .{ .selected = selection.selected, .policy = testPolicy(.cache_only), .exact_lock_package = locked },
        transport.dependencies(),
    ));
}

test "verified download publishes CAS and cache-only hit performs no network" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    var selection = try testSelection(std.testing.allocator, "package payload");
    defer selection.deinit(std.testing.allocator);
    var transport: TestTransport = .{ .responses = &.{.{ .body = "package payload" }} };

    var downloaded = try acquirePackage(std.testing.allocator, &cache, .{
        .selected = selection.selected,
        .policy = testPolicy(.online),
    }, transport.dependencies());
    defer downloaded.deinit();
    try std.testing.expectEqual(Outcome.downloaded, downloaded.provenance.outcome);
    try std.testing.expectEqualStrings("package payload", downloaded.bytes);
    try std.testing.expectEqualStrings(
        "https://packages.example/repository/pool/main/d/demo_1.2.3-1_amd64.deb",
        downloaded.provenance.resolved_uri,
    );

    var offline_transport: TestTransport = .{};
    var cached = try acquirePackage(std.testing.allocator, &cache, .{
        .selected = selection.selected,
        .policy = .{
            .mode = .cache_only,
            .workflow = .download_only,
            .maximum_package_bytes = 1024,
            .deadlines = .{ .connect_ms = 1, .read_ms = 1, .overall_ms = 1 },
            .redirect_limit = 0,
        },
    }, offline_transport.dependencies());
    defer cached.deinit();
    try std.testing.expectEqual(@as(usize, 0), offline_transport.count);
    try std.testing.expectEqual(Outcome.cache_hit, cached.provenance.outcome);
    try std.testing.expectEqual(Workflow.download_only, cached.provenance.workflow);
}

test "package locations reject platform path separators" {
    try std.testing.expectError(
        error.InvalidBaseUri,
        resolvePackageUri(
            std.testing.allocator,
            try acquisition.Uri.parse("file:///repository"),
            "pool\\..\\outside.deb",
        ),
    );
}

test "verified result owns package identity provenance" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    var selection = try testSelection(std.testing.allocator, "owned");
    var transport: TestTransport = .{ .responses = &.{.{ .body = "owned" }} };
    var result = try acquirePackage(std.testing.allocator, &cache, .{
        .selected = selection.selected,
        .policy = testPolicy(.online),
    }, transport.dependencies());
    selection.deinit(std.testing.allocator);
    defer result.deinit();
    try std.testing.expectEqualStrings("demo", result.provenance.package);
    try std.testing.expectEqualStrings("1.2.3-1", result.provenance.version);
    try std.testing.expectEqualStrings("amd64", result.provenance.architecture);
}

test "cache-only miss never invokes transport" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    var selection = try testSelection(std.testing.allocator, "missing");
    defer selection.deinit(std.testing.allocator);
    var transport: TestTransport = .{};
    try std.testing.expectError(error.CacheMiss, acquirePackage(std.testing.allocator, &cache, .{
        .selected = selection.selected,
        .policy = testPolicy(.cache_only),
    }, transport.dependencies()));
    try std.testing.expectEqual(@as(usize, 0), transport.count);
}

test "size digest truncation and over-limit failures never publish" {
    const failures = [_]struct { body: []const u8, expected: anyerror }{
        .{ .body = "short", .expected = error.SizeMismatch },
        .{ .body = "package payloae", .expected = error.DigestMismatch },
        .{ .body = "package payload plus", .expected = error.ResponseTooLarge },
    };
    for (failures) |failure| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var cache = try testCache(&tmp);
        defer cache.deinit();
        var selection = try testSelection(std.testing.allocator, "package payload");
        defer selection.deinit(std.testing.allocator);
        var transport: TestTransport = .{ .responses = &.{.{ .body = failure.body }} };
        try std.testing.expectError(failure.expected, acquirePackage(std.testing.allocator, &cache, .{
            .selected = selection.selected,
            .policy = testPolicy(.online),
        }, transport.dependencies()));
        const digest: Digest = .{ .bytes = selection.selected.record.transport.sha256.bytes };
        try std.testing.expectError(
            error.CacheMiss,
            cache.lookup(std.testing.allocator, digest, "package payload".len, .verify_sha256),
        );
        var stages = cache.staging.iterate();
        try std.testing.expect(try stages.next(std.testing.io) == null);
    }
}

test "corrupt cache fails closed or is repaired only by explicit online policy" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    var selection = try testSelection(std.testing.allocator, "correct");
    defer selection.deinit(std.testing.allocator);
    const digest: Digest = .{ .bytes = selection.selected.record.transport.sha256.bytes };
    var name: [64]u8 = undefined;
    digest.formatHex(&name);
    try cache.objects.writeFile(std.testing.io, .{ .sub_path = &name, .data = "corrupt" });
    var no_network: TestTransport = .{};
    try std.testing.expectError(error.CorruptObject, acquirePackage(std.testing.allocator, &cache, .{
        .selected = selection.selected,
        .policy = testPolicy(.cache_only),
    }, no_network.dependencies()));
    try std.testing.expectEqual(@as(usize, 0), no_network.count);

    var transport: TestTransport = .{ .responses = &.{.{ .body = "correct" }} };
    var policy = testPolicy(.online);
    policy.corrupt_cache = .repair_online;
    var repaired = try acquirePackage(std.testing.allocator, &cache, .{
        .selected = selection.selected,
        .policy = policy,
    }, transport.dependencies());
    defer repaired.deinit();
    try std.testing.expectEqualStrings("correct", repaired.bytes);
}

const InterruptPublish = struct {
    fn staged(_: ?*anyopaque) !void {
        return error.Interrupted;
    }
};

test "interrupted publication exposes no partial object and cleans staging" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    const bytes = "complete";
    const digest = Digest.of(bytes);
    try std.testing.expectError(error.Interrupted, cache.publish(
        std.testing.allocator,
        digest,
        bytes.len,
        bytes,
        .fail_fast,
        .{ .stagedFn = InterruptPublish.staged },
    ));
    try std.testing.expectError(
        error.CacheMiss,
        cache.lookup(std.testing.allocator, digest, bytes.len, .verify_sha256),
    );
    var stages = cache.staging.iterate();
    try std.testing.expect(try stages.next(std.testing.io) == null);
}

test "redirect credentials are origin scoped and observable provenance is redacted" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    var selection = try testSelection(std.testing.allocator, "payload");
    defer selection.deinit(std.testing.allocator);
    var transport: TestTransport = .{ .responses = &.{
        .{ .status = 302, .body = "", .location = "https://mirror.example/file.deb?token=secret" },
        .{ .body = "payload" },
    } };
    const Credentials = struct {
        fn get(_: ?*anyopaque, _: acquisition.Uri) !?acquisition.Credential {
            return .{ .authorization = "Bearer top-secret" };
        }
    };
    var policy = testPolicy(.online);
    policy.credentials = .{ .getFn = Credentials.get };
    var result = try acquirePackage(std.testing.allocator, &cache, .{
        .selected = selection.selected,
        .policy = policy,
    }, transport.dependencies());
    defer result.deinit();
    try std.testing.expect(transport.authorization_seen[0]);
    try std.testing.expect(!transport.authorization_seen[1]);
    try std.testing.expect(std.mem.indexOf(u8, result.provenance.resolved_uri, "secret") == null);
    try std.testing.expectEqualStrings(
        "https://mirror.example/file.deb?REDACTED",
        result.provenance.resolved_uri,
    );
}

test "retry proxy and deadline policy are passed through acquisition" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    var selection = try testSelection(std.testing.allocator, "retry");
    defer selection.deinit(std.testing.allocator);
    var transport: TestTransport = .{ .responses = &.{
        .{ .body = "", .failure = error.ConnectionResetByPeer },
        .{ .body = "retry" },
    } };
    var policy = testPolicy(.online);
    policy.retry.max_attempts = 2;
    policy.proxy.http = .{ .uri = try acquisition.Uri.parse("http://proxy.example:8080") };
    var result = try acquirePackage(std.testing.allocator, &cache, .{
        .selected = selection.selected,
        .policy = policy,
    }, transport.dependencies());
    defer result.deinit();
    try std.testing.expectEqual(@as(usize, 2), transport.count);
    try std.testing.expect(transport.proxy_seen);
    try std.testing.expectEqual(@as(u16, 2), result.provenance.attempts);
}

test "TLS non-retryable and deadline failures publish nothing" {
    const cases = [_]struct { failure: anyerror, attempts: u16, expected_count: usize }{
        .{ .failure = error.CertificateNotYetValid, .attempts = 3, .expected_count = 1 },
        .{ .failure = error.ConnectDeadlineExceeded, .attempts = 1, .expected_count = 1 },
        .{ .failure = error.ReadDeadlineExceeded, .attempts = 1, .expected_count = 1 },
    };
    for (cases) |case| {
        var tmp = std.testing.tmpDir(.{});
        defer tmp.cleanup();
        var cache = try testCache(&tmp);
        defer cache.deinit();
        var selection = try testSelection(std.testing.allocator, "deadlines");
        defer selection.deinit(std.testing.allocator);
        var transport: TestTransport = .{ .responses = &.{
            .{ .body = "", .failure = case.failure },
            .{ .body = "deadlines" },
            .{ .body = "deadlines" },
        } };
        var policy = testPolicy(.online);
        policy.retry.max_attempts = case.attempts;
        try std.testing.expectError(case.failure, acquirePackage(std.testing.allocator, &cache, .{
            .selected = selection.selected,
            .policy = policy,
        }, transport.dependencies()));
        try std.testing.expectEqual(case.expected_count, transport.count);
        const digest: Digest = .{ .bytes = selection.selected.record.transport.sha256.bytes };
        try std.testing.expectError(
            error.CacheMiss,
            cache.lookup(std.testing.allocator, digest, "deadlines".len, .verify_sha256),
        );
    }
}

const BusyLock = struct {
    fn acquire(_: *anyopaque) !*anyopaque {
        return error.Busy;
    }
    fn release(_: *anyopaque, _: *anyopaque) void {}
};

const ConcurrentPublish = struct {
    cache: *Cache,
    staged: std.atomic.Value(bool) = .init(false),
    release: std.atomic.Value(bool) = .init(false),
    failure: ?anyerror = null,

    fn stagedHook(context: ?*anyopaque) !void {
        const self: *ConcurrentPublish = @ptrCast(@alignCast(context.?));
        self.staged.store(true, .release);
        while (!self.release.load(.acquire)) std.atomic.spinLoopHint();
    }

    fn run(self: *ConcurrentPublish) void {
        self.cache.publish(
            std.testing.allocator,
            Digest.of("concurrent"),
            "concurrent".len,
            "concurrent",
            .fail_fast,
            .{ .context = self, .stagedFn = stagedHook },
        ) catch |err| {
            self.failure = err;
        };
    }
};

test "concurrent publishers cannot expose or replace staged bytes" {
    if (@import("builtin").single_threaded) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var first_cache = try testCache(&tmp);
    defer first_cache.deinit();
    var second_cache = try testCache(&tmp);
    defer second_cache.deinit();
    var context: ConcurrentPublish = .{ .cache = &first_cache };
    const thread = try std.Thread.spawn(.{}, ConcurrentPublish.run, .{&context});
    var joined = false;
    defer if (!joined) {
        context.release.store(true, .release);
        thread.join();
    };
    while (!context.staged.load(.acquire)) std.atomic.spinLoopHint();

    try std.testing.expectError(error.LockBusy, second_cache.publish(
        std.testing.allocator,
        Digest.of("concurrent"),
        "concurrent".len,
        "concurrent",
        .fail_fast,
        .{},
    ));
    try std.testing.expectError(
        error.CacheMiss,
        second_cache.lookup(
            std.testing.allocator,
            Digest.of("concurrent"),
            "concurrent".len,
            .verify_sha256,
        ),
    );
    context.release.store(true, .release);
    thread.join();
    joined = true;
    try std.testing.expect(context.failure == null);
    const bytes = try second_cache.lookup(
        std.testing.allocator,
        Digest.of("concurrent"),
        "concurrent".len,
        .verify_sha256,
    );
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("concurrent", bytes);
}

test "writer and garbage collector expose stable lock-busy semantics" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    var token: u8 = 0;
    const lock: LockPolicy = .{ .injected = .{
        .context = &token,
        .acquireFn = BusyLock.acquire,
        .releaseFn = BusyLock.release,
    } };
    try std.testing.expectError(
        error.LockBusy,
        cache.publish(std.testing.allocator, Digest.of("bytes"), 5, "bytes", lock, .{}),
    );
    try std.testing.expectError(error.LockBusy, cache.garbageCollect(std.testing.allocator, .{
        .maximum_directory_entries = 1,
        .maximum_objects_scanned = 1,
        .maximum_objects_deleted = 1,
        .maximum_bytes_deleted = 1,
        .lock = lock,
    }));
}

test "duplicate publication is idempotent and competing digests remain isolated" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    const first = "first";
    const second = "second";
    try cache.publish(std.testing.allocator, Digest.of(first), first.len, first, .fail_fast, .{});
    try cache.publish(std.testing.allocator, Digest.of(first), first.len, first, .fail_fast, .{});
    try cache.publish(std.testing.allocator, Digest.of(second), second.len, second, .fail_fast, .{});
    const first_bytes = try cache.lookup(std.testing.allocator, Digest.of(first), first.len, .verify_sha256);
    defer std.testing.allocator.free(first_bytes);
    const second_bytes = try cache.lookup(std.testing.allocator, Digest.of(second), second.len, .verify_sha256);
    defer std.testing.allocator.free(second_bytes);
    try std.testing.expectEqualStrings(first, first_bytes);
    try std.testing.expectEqualStrings(second, second_bytes);
}

test "bounded deterministic garbage collection retains explicit active references" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    const retained = Digest.of("retained");
    try cache.publish(std.testing.allocator, retained, "retained".len, "retained", .fail_fast, .{});
    try cache.publish(std.testing.allocator, Digest.of("delete-a"), "delete-a".len, "delete-a", .fail_fast, .{});
    try cache.publish(std.testing.allocator, Digest.of("delete-b"), "delete-b".len, "delete-b", .fail_fast, .{});
    const result = try cache.garbageCollect(std.testing.allocator, .{
        .retained = &.{retained},
        .maximum_directory_entries = 10,
        .maximum_objects_scanned = 10,
        .maximum_objects_deleted = 1,
        .maximum_bytes_deleted = 1024,
    });
    try std.testing.expectEqual(@as(usize, 1), result.deleted);
    try std.testing.expect(!result.complete);
    const bytes = try cache.lookup(std.testing.allocator, retained, "retained".len, .verify_sha256);
    defer std.testing.allocator.free(bytes);
    try std.testing.expectEqualStrings("retained", bytes);
}

test "abandoned staging cleanup is bounded" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    try cache.staging.writeFile(std.testing.io, .{ .sub_path = "abandoned", .data = "partial" });
    const bounded = try cache.cleanupStaging(std.testing.allocator, 0, .fail_fast);
    try std.testing.expect(!bounded.complete);
    const cleaned = try cache.cleanupStaging(std.testing.allocator, 2, .fail_fast);
    try std.testing.expect(cleaned.complete);
    try std.testing.expectEqual(@as(usize, 1), cleaned.deleted);
}

test "cache rejects object symlinks and bounds non-object garbage entries" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();
    const digest = Digest.of("outside");
    var name: [64]u8 = undefined;
    digest.formatHex(&name);
    try cache.objects.symLink(std.testing.io, "../../writer.lock", &name, .{});
    try std.testing.expectError(
        error.CorruptObject,
        cache.lookup(std.testing.allocator, digest, "outside".len, .verify_sha256),
    );
    const bounded = try cache.garbageCollect(std.testing.allocator, .{
        .maximum_directory_entries = 0,
        .maximum_objects_scanned = 1,
        .maximum_objects_deleted = 1,
        .maximum_bytes_deleted = 1024,
    });
    try std.testing.expect(!bounded.complete);
    try std.testing.expectEqual(@as(usize, 0), bounded.scanned);
}
