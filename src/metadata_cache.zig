const std = @import("std");

const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const namespace = "metadata-v1";
const manifest_magic = "debz-metadata-manifest-v1";
const manifest_limit = 4096;

pub const CacheError = error{
    CacheMiss,
    CorruptManifest,
    CorruptObject,
    DigestMismatch,
    InvalidCacheKey,
    InvalidRootPath,
    LockBusy,
    ObjectTooLarge,
    SizeMismatch,
};

pub const Digest = struct {
    bytes: [Sha256.digest_length]u8,

    pub fn of(bytes: []const u8) Digest {
        var result: Digest = undefined;
        Sha256.hash(bytes, &result.bytes, .{});
        return result;
    }

    pub fn eql(a: Digest, b: Digest) bool {
        return std.crypto.timing_safe.eql([Sha256.digest_length]u8, a.bytes, b.bytes);
    }

    pub fn formatHex(self: Digest, out: *[Sha256.digest_length * 2]u8) void {
        _ = std.fmt.bufPrint(out, "{x}", .{self.bytes}) catch unreachable;
    }

    pub fn parseHex(text: []const u8) error{InvalidDigest}!Digest {
        if (text.len != Sha256.digest_length * 2) return error.InvalidDigest;
        var result: Digest = undefined;
        _ = std.fmt.hexToBytes(&result.bytes, text) catch return error.InvalidDigest;
        return result;
    }
};

pub const ObjectIdentity = struct {
    digest: Digest,
    size: u64,
};

pub const RepositoryId = struct {
    value: []const u8,

    pub fn init(value: []const u8) error{InvalidCacheKey}!RepositoryId {
        try validateKey(value);
        return .{ .value = value };
    }
};

pub const SnapshotId = struct {
    value: []const u8,

    pub fn init(value: []const u8) error{InvalidCacheKey}!SnapshotId {
        try validateKey(value);
        return .{ .value = value };
    }
};

pub const VerificationKind = enum {
    in_release,
    detached_release,
    trusted_snapshot,
};

pub const Provenance = struct {
    verification: VerificationKind,
    verified_at_unix: i64,
    verifier_input: ?Digest = null,
};

pub const Record = struct {
    bytes: []u8,
    identity: ObjectIdentity,
    provenance: Provenance,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Record) void {
        self.allocator.free(self.bytes);
        self.* = undefined;
    }
};

pub const PublishOptions = struct {
    lock: LockPolicy = .fail_fast,
    hooks: Hooks = .{},
};

pub const LockPolicy = union(enum) {
    /// Uses a non-blocking advisory lock and returns `error.LockBusy`.
    fail_fast,
    /// Caller-provided locking can implement bounded waits or process-local locks.
    injected: Lock,
};

pub const Lock = struct {
    context: *anyopaque,
    acquireFn: *const fn (*anyopaque) anyerror!*anyopaque,
    releaseFn: *const fn (*anyopaque, *anyopaque) void,
};

pub const HookPoint = enum {
    object_staged,
    object_published,
    manifest_staged,
};

pub const Hooks = struct {
    context: ?*anyopaque = null,
    runFn: ?*const fn (?*anyopaque, HookPoint) anyerror!void = null,

    fn run(self: Hooks, point: HookPoint) !void {
        if (self.runFn) |runFn| try runFn(self.context, point);
    }
};

pub const Limits = struct {
    max_object_bytes: usize = 64 * 1024 * 1024,
};

pub const GcOptions = struct {
    max_objects_scanned: usize,
    max_objects_deleted: usize,
    lock: LockPolicy = .fail_fast,
};

pub const GcResult = struct {
    scanned: usize,
    deleted: usize,
    complete: bool,
};

pub const Cache = struct {
    io: Io,
    root: Dir,
    owns_root: bool,
    metadata: Dir,
    objects: Dir,
    manifests: Dir,
    staging: Dir,
    locks: Dir,
    limits: Limits,

    /// Opens only the caller-selected path; no host cache location is consulted.
    pub fn init(io: Io, root_path: []const u8, limits: Limits) !Cache {
        if (root_path.len == 0) return error.InvalidRootPath;
        try Dir.cwd().createDirPath(io, root_path);
        const root = try Dir.cwd().openDir(io, root_path, .{ .follow_symlinks = false });
        errdefer root.close(io);
        var cache = try initFromDir(io, root, limits);
        cache.owns_root = true;
        return cache;
    }

    /// Uses an explicit caller-owned directory handle as the cache root.
    pub fn initFromDir(io: Io, root: Dir, limits: Limits) !Cache {
        try ensureDirectory(io, root, namespace, dirPermissions(false));
        const metadata = try root.openDir(io, namespace, .{ .follow_symlinks = false });
        errdefer metadata.close(io);

        try ensureDirectory(io, metadata, "objects", dirPermissions(false));
        try ensureDirectory(io, metadata, "manifests", dirPermissions(false));
        try ensureDirectory(io, metadata, "staging", dirPermissions(true));
        try ensureDirectory(io, metadata, "locks", dirPermissions(true));

        const objects = try metadata.openDir(io, "objects", .{ .iterate = true, .follow_symlinks = false });
        errdefer objects.close(io);
        const manifests = try metadata.openDir(io, "manifests", .{ .iterate = true, .follow_symlinks = false });
        errdefer manifests.close(io);
        const staging = try metadata.openDir(io, "staging", .{ .iterate = true, .follow_symlinks = false });
        errdefer staging.close(io);
        const locks = try metadata.openDir(io, "locks", .{ .follow_symlinks = false });
        errdefer locks.close(io);

        return .{
            .io = io,
            .root = root,
            .owns_root = false,
            .metadata = metadata,
            .objects = objects,
            .manifests = manifests,
            .staging = staging,
            .locks = locks,
            .limits = limits,
        };
    }

    pub fn deinit(self: *Cache) void {
        self.locks.close(self.io);
        self.staging.close(self.io);
        self.manifests.close(self.io);
        self.objects.close(self.io);
        self.metadata.close(self.io);
        if (self.owns_root) self.root.close(self.io);
        self.* = undefined;
    }

    /// Verifies bytes before making the immutable object or manifest visible.
    pub fn publish(
        self: *Cache,
        repository: RepositoryId,
        snapshot: SnapshotId,
        provenance: Provenance,
        expected: ObjectIdentity,
        bytes: []const u8,
        options: PublishOptions,
    ) !void {
        try validateKey(repository.value);
        try validateKey(snapshot.value);
        if (bytes.len != expected.size) return error.SizeMismatch;
        if (bytes.len > self.limits.max_object_bytes) return error.ObjectTooLarge;
        const actual = Digest.of(bytes);
        if (!actual.eql(expected.digest)) return error.DigestMismatch;

        var held = try self.acquire(options.lock);
        defer held.release(self);

        var digest_hex: [64]u8 = undefined;
        expected.digest.formatHex(&digest_hex);
        const object_stage = try stageName("object", expected.digest);
        defer self.staging.deleteFile(self.io, &object_stage) catch {};

        {
            var staged_object = try self.staging.createFile(self.io, &object_stage, .{
                .exclusive = true,
                .permissions = filePermissions(),
                .resolve_beneath = true,
            });
            defer staged_object.close(self.io);
            try staged_object.writeStreamingAll(self.io, bytes);
            try staged_object.sync(self.io);
        }
        try options.hooks.run(.object_staged);

        try self.staging.rename(&object_stage, self.objects, &digest_hex, self.io);
        try syncDirectory(self.io, self.objects);
        try options.hooks.run(.object_published);

        const manifest_name = manifestName(repository, snapshot);
        const manifest_stage = try stageName("manifest", expected.digest);
        defer self.staging.deleteFile(self.io, &manifest_stage) catch {};
        var manifest_buffer: [manifest_limit]u8 = undefined;
        const manifest_bytes = try encodeManifest(
            &manifest_buffer,
            repository,
            snapshot,
            provenance,
            expected,
        );
        {
            var staged_manifest = try self.staging.createFile(self.io, &manifest_stage, .{
                .exclusive = true,
                .permissions = filePermissions(),
                .resolve_beneath = true,
            });
            defer staged_manifest.close(self.io);
            try staged_manifest.writeStreamingAll(self.io, manifest_bytes);
            try staged_manifest.sync(self.io);
        }
        try options.hooks.run(.manifest_staged);
        try self.staging.rename(&manifest_stage, self.manifests, &manifest_name, self.io);
        try syncDirectory(self.io, self.manifests);
    }

    /// Cache-only lookup fails closed if either the manifest or object is absent or invalid.
    pub fn lookup(
        self: *Cache,
        allocator: std.mem.Allocator,
        repository: RepositoryId,
        snapshot: SnapshotId,
    ) !Record {
        try validateKey(repository.value);
        try validateKey(snapshot.value);
        const manifest_name = manifestName(repository, snapshot);
        const raw_manifest = secureReadAlloc(
            self.manifests,
            self.io,
            &manifest_name,
            allocator,
            .limited(manifest_limit),
        ) catch |err| switch (err) {
            error.FileNotFound => return error.CacheMiss,
            error.StreamTooLong => return error.CorruptManifest,
            error.SymLinkLoop, error.NotDir, error.AccessDenied => return error.CorruptManifest,
            else => |e| return e,
        };
        defer allocator.free(raw_manifest);
        const manifest = decodeManifest(raw_manifest, repository, snapshot) catch
            return error.CorruptManifest;
        if (manifest.identity.size > self.limits.max_object_bytes) return error.ObjectTooLarge;

        var digest_hex: [64]u8 = undefined;
        manifest.identity.digest.formatHex(&digest_hex);
        const bytes = secureReadAlloc(
            self.objects,
            self.io,
            &digest_hex,
            allocator,
            .limited(@intCast(manifest.identity.size + 1)),
        ) catch |err| switch (err) {
            error.FileNotFound => return error.CacheMiss,
            error.StreamTooLong => return error.CorruptObject,
            error.SymLinkLoop, error.NotDir, error.AccessDenied => return error.CorruptObject,
            else => |e| return e,
        };
        errdefer allocator.free(bytes);
        if (bytes.len != manifest.identity.size) return error.CorruptObject;
        if (!Digest.of(bytes).eql(manifest.identity.digest)) return error.CorruptObject;
        return .{
            .bytes = bytes,
            .identity = manifest.identity,
            .provenance = manifest.provenance,
            .allocator = allocator,
        };
    }

    /// Deletes at most the requested number of unreferenced metadata objects.
    pub fn garbageCollect(
        self: *Cache,
        allocator: std.mem.Allocator,
        options: GcOptions,
    ) !GcResult {
        var held = try self.acquire(options.lock);
        defer held.release(self);

        var referenced: std.AutoHashMap([32]u8, void) = .init(allocator);
        defer referenced.deinit();

        var manifests = self.manifests.iterate();
        while (try manifests.next(self.io)) |entry| {
            if (entry.kind != .file) return error.CorruptManifest;
            const raw = secureReadAlloc(
                self.manifests,
                self.io,
                entry.name,
                allocator,
                .limited(manifest_limit),
            ) catch return error.CorruptManifest;
            defer allocator.free(raw);
            const manifest = decodeManifestUncheckedKeys(raw) catch return error.CorruptManifest;
            try referenced.put(manifest.identity.digest.bytes, {});
        }

        var result: GcResult = .{ .scanned = 0, .deleted = 0, .complete = true };
        var objects = self.objects.iterate();
        while (try objects.next(self.io)) |entry| {
            if (result.scanned == options.max_objects_scanned) {
                result.complete = false;
                break;
            }
            result.scanned += 1;
            if (entry.kind != .file) continue;
            const digest = Digest.parseHex(entry.name) catch continue;
            if (!referenced.contains(digest.bytes) and result.deleted < options.max_objects_deleted) {
                try self.objects.deleteFile(self.io, entry.name);
                result.deleted += 1;
            }
        }
        return result;
    }

    const HeldLock = union(enum) {
        file: File,
        injected: struct {
            lock: Lock,
            token: *anyopaque,
        },

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

const Manifest = struct {
    identity: ObjectIdentity,
    provenance: Provenance,
};

fn validateKey(value: []const u8) error{InvalidCacheKey}!void {
    if (value.len == 0 or value.len > 255 or
        std.mem.eql(u8, value, ".") or std.mem.eql(u8, value, ".."))
        return error.InvalidCacheKey;
    for (value) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '-' or byte == '_' or byte == '.'))
            return error.InvalidCacheKey;
    }
}

fn manifestName(repository: RepositoryId, snapshot: SnapshotId) [64]u8 {
    var hasher = Sha256.init(.{});
    hasher.update(repository.value);
    hasher.update(&.{0});
    hasher.update(snapshot.value);
    var digest: Digest = undefined;
    hasher.final(&digest.bytes);
    var result: [64]u8 = undefined;
    digest.formatHex(&result);
    return result;
}

var stage_counter: std.atomic.Value(u64) = .init(0);

fn stageName(prefix: []const u8, digest: Digest) ![96]u8 {
    var digest_hex: [64]u8 = undefined;
    digest.formatHex(&digest_hex);
    var result: [96]u8 = undefined;
    const serial = stage_counter.fetchAdd(1, .monotonic);
    const written = try std.fmt.bufPrint(&result, "{s}-{s}-{x:0>16}.tmp", .{
        prefix,
        digest_hex[0..8],
        serial,
    });
    @memset(result[written.len..], '_');
    return result;
}

fn encodeManifest(
    buffer: []u8,
    repository: RepositoryId,
    snapshot: SnapshotId,
    provenance: Provenance,
    identity: ObjectIdentity,
) ![]const u8 {
    var digest_hex: [64]u8 = undefined;
    identity.digest.formatHex(&digest_hex);
    var verifier_hex: [64]u8 = undefined;
    const verifier = if (provenance.verifier_input) |digest| blk: {
        digest.formatHex(&verifier_hex);
        break :blk verifier_hex[0..];
    } else "-";
    return std.fmt.bufPrint(buffer,
        \\{s}
        \\repository={s}
        \\snapshot={s}
        \\digest={s}
        \\size={d}
        \\verification={s}
        \\verified-at={d}
        \\verifier-input={s}
        \\
    , .{
        manifest_magic,
        repository.value,
        snapshot.value,
        &digest_hex,
        identity.size,
        @tagName(provenance.verification),
        provenance.verified_at_unix,
        verifier,
    });
}

fn decodeManifest(
    bytes: []const u8,
    repository: RepositoryId,
    snapshot: SnapshotId,
) !Manifest {
    const parsed = try parseManifest(bytes);
    if (!std.mem.eql(u8, parsed.repository, repository.value) or
        !std.mem.eql(u8, parsed.snapshot, snapshot.value))
        return error.ManifestMismatch;
    return parsed.manifest;
}

fn decodeManifestUncheckedKeys(bytes: []const u8) !Manifest {
    return (try parseManifest(bytes)).manifest;
}

fn parseManifest(bytes: []const u8) !struct {
    repository: []const u8,
    snapshot: []const u8,
    manifest: Manifest,
} {
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    if (!std.mem.eql(u8, lines.next() orelse return error.InvalidManifest, manifest_magic))
        return error.InvalidManifest;
    const repository = try field(lines.next(), "repository");
    const snapshot = try field(lines.next(), "snapshot");
    try validateKey(repository);
    try validateKey(snapshot);
    const digest = try Digest.parseHex(try field(lines.next(), "digest"));
    const size = std.fmt.parseUnsigned(u64, try field(lines.next(), "size"), 10) catch
        return error.InvalidManifest;
    const verification = std.meta.stringToEnum(
        VerificationKind,
        try field(lines.next(), "verification"),
    ) orelse return error.InvalidManifest;
    const verified_at = std.fmt.parseInt(i64, try field(lines.next(), "verified-at"), 10) catch
        return error.InvalidManifest;
    const verifier_text = try field(lines.next(), "verifier-input");
    const verifier = if (std.mem.eql(u8, verifier_text, "-"))
        null
    else
        try Digest.parseHex(verifier_text);
    if (lines.next()) |remaining| {
        if (remaining.len != 0 or lines.next() != null) return error.InvalidManifest;
    }
    return .{
        .repository = repository,
        .snapshot = snapshot,
        .manifest = .{
            .identity = .{ .digest = digest, .size = size },
            .provenance = .{
                .verification = verification,
                .verified_at_unix = verified_at,
                .verifier_input = verifier,
            },
        },
    };
}

fn field(line_optional: ?[]const u8, name: []const u8) ![]const u8 {
    const line = line_optional orelse return error.InvalidManifest;
    if (!std.mem.startsWith(u8, line, name) or line.len <= name.len or line[name.len] != '=')
        return error.InvalidManifest;
    return line[name.len + 1 ..];
}

fn ensureDirectory(io: Io, parent: Dir, name: []const u8, permissions: File.Permissions) !void {
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

fn syncDirectory(io: Io, dir: Dir) !void {
    switch (@import("builtin").os.tag) {
        .windows, .wasi => return,
        else => try (File{ .handle = dir.handle, .flags = .{ .nonblocking = false } }).sync(io),
    }
}

fn secureReadAlloc(
    dir: Dir,
    io: Io,
    path: []const u8,
    allocator: std.mem.Allocator,
    limit: Io.Limit,
) ![]u8 {
    var file = try dir.openFile(io, path, .{
        .follow_symlinks = false,
        .resolve_beneath = true,
    });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, limit) catch |err| switch (err) {
        error.ReadFailed => return reader.err.?,
        else => |e| return e,
    };
}

fn testCache(tmp: *std.testing.TmpDir) !Cache {
    return Cache.initFromDir(std.testing.io, tmp.dir, .{ .max_object_bytes = 1024 });
}

const test_repository = RepositoryId{ .value = "example-repository" };
const test_snapshot = SnapshotId{ .value = "bookworm-20260814" };
const test_provenance = Provenance{
    .verification = .in_release,
    .verified_at_unix = 1_786_733_717,
};

test "publish and cache-only lookup verify content identity" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();

    const bytes = "verified package metadata";
    const identity: ObjectIdentity = .{ .digest = Digest.of(bytes), .size = bytes.len };
    try cache.publish(test_repository, test_snapshot, test_provenance, identity, bytes, .{});
    var record = try cache.lookup(std.testing.allocator, test_repository, test_snapshot);
    defer record.deinit();
    try std.testing.expectEqualStrings(bytes, record.bytes);
    try std.testing.expect(record.identity.digest.eql(identity.digest));
}

test "failed verification publishes no manifest and cleans staging" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();

    const wrong: ObjectIdentity = .{ .digest = Digest.of("other"), .size = 4 };
    try std.testing.expectError(
        error.DigestMismatch,
        cache.publish(test_repository, test_snapshot, test_provenance, wrong, "data", .{}),
    );
    try std.testing.expectError(
        error.CacheMiss,
        cache.lookup(std.testing.allocator, test_repository, test_snapshot),
    );
    var staging = cache.staging.iterate();
    try std.testing.expect(try staging.next(std.testing.io) == null);
}

const Interrupt = struct {
    point: HookPoint,

    fn run(context: ?*anyopaque, point: HookPoint) !void {
        const self: *Interrupt = @ptrCast(@alignCast(context.?));
        if (self.point == point) return error.Interrupted;
    }
};

test "interruption before manifest rename preserves old complete snapshot" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();

    const old = "old metadata";
    try cache.publish(test_repository, test_snapshot, test_provenance, .{
        .digest = Digest.of(old),
        .size = old.len,
    }, old, .{});

    const new = "new metadata";
    var interrupt: Interrupt = .{ .point = .manifest_staged };
    try std.testing.expectError(error.Interrupted, cache.publish(
        test_repository,
        test_snapshot,
        test_provenance,
        .{ .digest = Digest.of(new), .size = new.len },
        new,
        .{ .hooks = .{ .context = &interrupt, .runFn = Interrupt.run } },
    ));

    var record = try cache.lookup(std.testing.allocator, test_repository, test_snapshot);
    defer record.deinit();
    try std.testing.expectEqualStrings(old, record.bytes);
}

test "corrupt object and mismatched manifest fail closed" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();

    const bytes = "metadata";
    const identity: ObjectIdentity = .{ .digest = Digest.of(bytes), .size = bytes.len };
    try cache.publish(test_repository, test_snapshot, test_provenance, identity, bytes, .{});
    var digest_hex: [64]u8 = undefined;
    identity.digest.formatHex(&digest_hex);
    try cache.objects.writeFile(std.testing.io, .{ .sub_path = &digest_hex, .data = "tampered" });
    try std.testing.expectError(
        error.CorruptObject,
        cache.lookup(std.testing.allocator, test_repository, test_snapshot),
    );

    const manifest_name = manifestName(test_repository, test_snapshot);
    try cache.manifests.writeFile(std.testing.io, .{
        .sub_path = &manifest_name,
        .data = "not a manifest\n",
    });
    try std.testing.expectError(
        error.CorruptManifest,
        cache.lookup(std.testing.allocator, test_repository, test_snapshot),
    );
}

test "object symlink escape fails closed" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();

    const bytes = "metadata";
    const identity: ObjectIdentity = .{ .digest = Digest.of(bytes), .size = bytes.len };
    try cache.publish(test_repository, test_snapshot, test_provenance, identity, bytes, .{});
    var digest_hex: [64]u8 = undefined;
    identity.digest.formatHex(&digest_hex);
    try cache.objects.deleteFile(std.testing.io, &digest_hex);
    try cache.objects.symLink(std.testing.io, "../../writer.lock", &digest_hex, .{});
    try std.testing.expectError(
        error.CorruptObject,
        cache.lookup(std.testing.allocator, test_repository, test_snapshot),
    );
}

const DenyLock = struct {
    fn acquire(_: *anyopaque) !*anyopaque {
        return error.TimedOut;
    }
    fn release(_: *anyopaque, _: *anyopaque) void {}
};

test "injected bounded lock failure is explicit" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();

    var context: u8 = 0;
    const bytes = "metadata";
    try std.testing.expectError(error.LockBusy, cache.publish(
        test_repository,
        test_snapshot,
        test_provenance,
        .{ .digest = Digest.of(bytes), .size = bytes.len },
        bytes,
        .{ .lock = .{ .injected = .{
            .context = &context,
            .acquireFn = DenyLock.acquire,
            .releaseFn = DenyLock.release,
        } } },
    ));
}

test "garbage collection is bounded and preserves referenced objects" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    var cache = try testCache(&tmp);
    defer cache.deinit();

    const bytes = "referenced";
    const identity: ObjectIdentity = .{ .digest = Digest.of(bytes), .size = bytes.len };
    try cache.publish(test_repository, test_snapshot, test_provenance, identity, bytes, .{});
    const orphan = Digest.of("orphan");
    var orphan_hex: [64]u8 = undefined;
    orphan.formatHex(&orphan_hex);
    try cache.objects.writeFile(std.testing.io, .{ .sub_path = &orphan_hex, .data = "orphan" });

    const result = try cache.garbageCollect(std.testing.allocator, .{
        .max_objects_scanned = 10,
        .max_objects_deleted = 1,
    });
    try std.testing.expectEqual(@as(usize, 1), result.deleted);
    var record = try cache.lookup(std.testing.allocator, test_repository, test_snapshot);
    record.deinit();
}

test "cache keys reject traversal" {
    try std.testing.expectError(error.InvalidCacheKey, RepositoryId.init("../escape"));
    try std.testing.expectError(error.InvalidCacheKey, SnapshotId.init("nested/path"));
}

test "metadata namespace symlink is rejected" {
    if (@import("builtin").os.tag == .windows) return error.SkipZigTest;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.symLink(std.testing.io, ".", namespace, .{ .is_directory = true });
    _ = Cache.initFromDir(std.testing.io, tmp.dir, .{}) catch |err| switch (err) {
        error.SymLinkLoop, error.NotDir => return,
        else => return err,
    };
    return error.TestExpectedError;
}
