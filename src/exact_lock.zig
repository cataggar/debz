const std = @import("std");

pub const schema_id = "https://debz.dev/schema/exact-closure-lock-v1";
pub const schema_version: u32 = 1;
pub const maximum_document_bytes: usize = 16 * 1024 * 1024;

pub const Retention = enum {
    requested,
    dependency,
    retained,
};

pub const Repository = struct {
    id: [64]u8,
    snapshot_sha256: [32]u8,
    release_sha256: [32]u8,
    index_sha256: [32]u8,
    signer_fingerprints: []const [20]u8,
};

pub const Package = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    repository_id: [64]u8,
    repository_snapshot_sha256: [32]u8,
    sha256: [32]u8,
    declared_size: u64,
    retention: Retention,
    /// This is dpkg selection intent. Exact lock enforcement is represented by
    /// the lock document itself and never inferred from this flag.
    dpkg_selection_hold: bool,
};

pub const Input = struct {
    target_architecture: []const u8,
    request_sha256: [32]u8,
    policy_sha256: [32]u8,
    repositories: []const Repository,
    packages: []const Package,
    authenticated_metadata: bool,
};

pub const Lock = struct {
    target_architecture: []const u8,
    request_sha256: [32]u8,
    policy_sha256: [32]u8,
    repositories: []const Repository,
    packages: []const Package,
    digest_sha256: [32]u8,

    pub fn canonicalJson(self: Lock, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        return output.toOwnedSlice();
    }

    pub fn findPackage(self: Lock, name: []const u8, version: []const u8, architecture: []const u8) ?Package {
        for (self.packages) |package| {
            if (std.mem.eql(u8, package.name, name) and
                std.mem.eql(u8, package.version, version) and
                std.mem.eql(u8, package.architecture, architecture))
                return package;
        }
        return null;
    }

    pub fn findIdentity(self: Lock, name: []const u8, architecture: []const u8) ?Package {
        for (self.packages) |package| {
            if (std.mem.eql(u8, package.name, name) and
                std.mem.eql(u8, package.architecture, architecture))
                return package;
        }
        return null;
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

pub const ValidationError = error{
    UnauthenticatedMetadata,
    EmptyArchitecture,
    EmptyClosure,
    InvalidIdentity,
    MissingSigner,
    DuplicateSigner,
    DuplicateRepository,
    UnusedRepository,
    DuplicatePackage,
    MissingRepository,
    RepositorySnapshotMismatch,
    NonCanonicalDocument,
    UnsupportedSchema,
    DigestMismatch,
    DocumentTooLarge,
    InvalidDigest,
};

pub fn create(allocator: std.mem.Allocator, input: Input) (std.mem.Allocator.Error || ValidationError)!OwnedLock {
    if (!input.authenticated_metadata) return error.UnauthenticatedMetadata;
    if (input.target_architecture.len == 0) return error.EmptyArchitecture;
    if (input.packages.len == 0) return error.EmptyClosure;

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const repositories = try owned.alloc(Repository, input.repositories.len);
    for (input.repositories, 0..) |repository, index| {
        if (!validLowerHex(&repository.id)) return error.InvalidIdentity;
        if (repository.signer_fingerprints.len == 0) return error.MissingSigner;
        const fingerprints = try owned.dupe([20]u8, repository.signer_fingerprints);
        std.mem.sort([20]u8, fingerprints, {}, lessBytes20);
        for (fingerprints, 0..) |fingerprint, signer_index| {
            if (signer_index != 0 and std.mem.eql(u8, &fingerprint, &fingerprints[signer_index - 1]))
                return error.DuplicateSigner;
        }
        repositories[index] = repository;
        repositories[index].signer_fingerprints = fingerprints;
    }
    std.mem.sort(Repository, repositories, {}, lessRepository);
    for (repositories, 0..) |repository, index| {
        if (index != 0 and std.mem.eql(u8, &repository.id, &repositories[index - 1].id))
            return error.DuplicateRepository;
    }

    const packages = try owned.alloc(Package, input.packages.len);
    for (input.packages, 0..) |package, index| {
        if (package.name.len == 0 or package.version.len == 0 or package.architecture.len == 0 or
            !validLowerHex(&package.repository_id))
            return error.InvalidIdentity;
        const repository = findRepository(repositories, package.repository_id) orelse
            return error.MissingRepository;
        if (!std.mem.eql(u8, &repository.snapshot_sha256, &package.repository_snapshot_sha256))
            return error.RepositorySnapshotMismatch;
        packages[index] = package;
        packages[index].name = try owned.dupe(u8, package.name);
        packages[index].version = try owned.dupe(u8, package.version);
        packages[index].architecture = try owned.dupe(u8, package.architecture);
    }
    std.mem.sort(Package, packages, {}, lessPackage);
    for (packages, 0..) |package, index| {
        if (index != 0 and samePackageIdentity(package, packages[index - 1]))
            return error.DuplicatePackage;
    }
    for (repositories) |repository| {
        var referenced = false;
        for (packages) |package| {
            if (std.mem.eql(u8, &repository.id, &package.repository_id)) {
                referenced = true;
                break;
            }
        }
        if (!referenced) return error.UnusedRepository;
    }

    var lock: Lock = .{
        .target_architecture = try owned.dupe(u8, input.target_architecture),
        .request_sha256 = input.request_sha256,
        .policy_sha256 = input.policy_sha256,
        .repositories = repositories,
        .packages = packages,
        .digest_sha256 = undefined,
    };
    lock.digest_sha256 = digestPayload(lock);
    return .{ .lock = lock, .arena = arena, .backing_allocator = allocator };
}

const WireRepository = struct {
    id: []const u8,
    snapshot_sha256: []const u8,
    release_sha256: []const u8,
    index_sha256: []const u8,
    signer_fingerprints: []const []const u8,
};

const WirePackage = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    repository_id: []const u8,
    repository_snapshot_sha256: []const u8,
    sha256: []const u8,
    declared_size: u64,
    retention: Retention,
    dpkg_selection_hold: bool,
};

const WireLock = struct {
    schema: []const u8,
    version: u32,
    target_architecture: []const u8,
    request_sha256: []const u8,
    policy_sha256: []const u8,
    repositories: []const WireRepository,
    packages: []const WirePackage,
    digest_sha256: []const u8,
};

pub fn decode(
    allocator: std.mem.Allocator,
    source: []const u8,
    maximum_bytes: usize,
) !OwnedLock {
    if (source.len > maximum_bytes or source.len > maximum_document_bytes) return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(WireLock, allocator, source, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.schema, schema_id) or parsed.value.version != schema_version)
        return error.UnsupportedSchema;

    const repositories = try allocator.alloc(Repository, parsed.value.repositories.len);
    var repositories_initialized: usize = 0;
    defer {
        for (repositories[0..repositories_initialized]) |repository| allocator.free(repository.signer_fingerprints);
        allocator.free(repositories);
    }
    for (parsed.value.repositories, 0..) |repository, index| {
        const id = try parseRepositoryId(repository.id);
        const signers = try allocator.alloc([20]u8, repository.signer_fingerprints.len);
        errdefer allocator.free(signers);
        for (repository.signer_fingerprints, 0..) |fingerprint, signer_index|
            signers[signer_index] = try parseHex(20, fingerprint);
        repositories[index] = .{
            .id = id,
            .snapshot_sha256 = try parseHex(32, repository.snapshot_sha256),
            .release_sha256 = try parseHex(32, repository.release_sha256),
            .index_sha256 = try parseHex(32, repository.index_sha256),
            .signer_fingerprints = signers,
        };
        repositories_initialized += 1;
    }

    const packages = try allocator.alloc(Package, parsed.value.packages.len);
    defer allocator.free(packages);
    for (parsed.value.packages, 0..) |package, index| packages[index] = .{
        .name = package.name,
        .version = package.version,
        .architecture = package.architecture,
        .repository_id = try parseRepositoryId(package.repository_id),
        .repository_snapshot_sha256 = try parseHex(32, package.repository_snapshot_sha256),
        .sha256 = try parseHex(32, package.sha256),
        .declared_size = package.declared_size,
        .retention = package.retention,
        .dpkg_selection_hold = package.dpkg_selection_hold,
    };

    var result = try create(allocator, .{
        .target_architecture = parsed.value.target_architecture,
        .request_sha256 = try parseHex(32, parsed.value.request_sha256),
        .policy_sha256 = try parseHex(32, parsed.value.policy_sha256),
        .repositories = repositories,
        .packages = packages,
        .authenticated_metadata = true,
    });
    errdefer result.deinit();
    const expected = try parseHex(32, parsed.value.digest_sha256);
    if (!std.mem.eql(u8, &expected, &result.lock.digest_sha256)) return error.DigestMismatch;
    const canonical = try result.lock.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, source)) return error.NonCanonicalDocument;
    return result;
}

pub const Store = struct {
    io: std.Io,
    dir: std.Io.Dir,
    name: []const u8,

    pub fn init(io: std.Io, dir: std.Io.Dir, name: []const u8) !Store {
        if (!safeLeaf(name)) return error.AmbiguousPath;
        return .{ .io = io, .dir = dir, .name = name };
    }

    pub fn read(self: Store, allocator: std.mem.Allocator, maximum_bytes: usize) !OwnedLock {
        if (maximum_bytes > maximum_document_bytes) return error.DocumentTooLarge;
        var file = try self.dir.openFile(self.io, self.name, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const bytes = try reader.interface.allocRemaining(allocator, .limited(maximum_bytes));
        defer allocator.free(bytes);
        return decode(allocator, bytes, maximum_bytes);
    }

    pub fn writeAtomic(self: Store, allocator: std.mem.Allocator, lock: Lock) !void {
        const bytes = try lock.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
        const stage = ".debz-lock.new";
        self.dir.deleteFile(self.io, stage) catch |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        };
        {
            var file = try self.dir.createFile(self.io, stage, .{
                .exclusive = true,
                .permissions = if (@import("builtin").os.tag == .windows) .default_file else .fromMode(0o600),
                .resolve_beneath = true,
            });
            defer file.close(self.io);
            try file.writeStreamingAll(self.io, bytes);
            try file.sync(self.io);
        }
        try self.dir.rename(stage, self.dir, self.name, self.io);
        switch (@import("builtin").os.tag) {
            .linux => if (std.posix.errno(std.os.linux.fsync(self.dir.handle)) != .SUCCESS)
                return error.Unexpected,
            else => {},
        }
    }
};

fn digestPayload(lock: Lock) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(lock, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeDocument(lock: Lock, writer: *std.Io.Writer) !void {
    try writePayload(lock, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHexString(writer, &lock.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(lock: Lock, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeJsonString(writer, schema_id);
    try writer.print(",\"version\":{},\"target_architecture\":", .{schema_version});
    try writeJsonString(writer, lock.target_architecture);
    try writer.writeAll(",\"request_sha256\":");
    try writeHexString(writer, &lock.request_sha256);
    try writer.writeAll(",\"policy_sha256\":");
    try writeHexString(writer, &lock.policy_sha256);
    try writer.writeAll(",\"repositories\":[");
    for (lock.repositories, 0..) |repository, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"id\":");
        try writeJsonString(writer, &repository.id);
        try writer.writeAll(",\"snapshot_sha256\":");
        try writeHexString(writer, &repository.snapshot_sha256);
        try writer.writeAll(",\"release_sha256\":");
        try writeHexString(writer, &repository.release_sha256);
        try writer.writeAll(",\"index_sha256\":");
        try writeHexString(writer, &repository.index_sha256);
        try writer.writeAll(",\"signer_fingerprints\":[");
        for (repository.signer_fingerprints, 0..) |fingerprint, signer_index| {
            if (signer_index != 0) try writer.writeByte(',');
            try writeHexString(writer, &fingerprint);
        }
        try writer.writeAll("]}");
    }
    try writer.writeAll("],\"packages\":[");
    for (lock.packages, 0..) |package, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"name\":");
        try writeJsonString(writer, package.name);
        try writer.writeAll(",\"version\":");
        try writeJsonString(writer, package.version);
        try writer.writeAll(",\"architecture\":");
        try writeJsonString(writer, package.architecture);
        try writer.writeAll(",\"repository_id\":");
        try writeJsonString(writer, &package.repository_id);
        try writer.writeAll(",\"repository_snapshot_sha256\":");
        try writeHexString(writer, &package.repository_snapshot_sha256);
        try writer.writeAll(",\"sha256\":");
        try writeHexString(writer, &package.sha256);
        try writer.print(",\"declared_size\":{},\"retention\":", .{package.declared_size});
        try writeJsonString(writer, @tagName(package.retention));
        try writer.print(",\"dpkg_selection_hold\":{}}}", .{package.dpkg_selection_hold});
    }
    try writer.writeAll("]}");
}

fn writeJsonString(writer: *std.Io.Writer, value: []const u8) !void {
    try writer.writeByte('"');
    for (value) |byte| switch (byte) {
        '"' => try writer.writeAll("\\\""),
        '\\' => try writer.writeAll("\\\\"),
        '\n' => try writer.writeAll("\\n"),
        '\r' => try writer.writeAll("\\r"),
        '\t' => try writer.writeAll("\\t"),
        0...8, 11, 12, 14...31 => try writer.print("\\u00{x:0>2}", .{byte}),
        else => try writer.writeByte(byte),
    };
    try writer.writeByte('"');
}

fn writeHexString(writer: *std.Io.Writer, bytes: []const u8) !void {
    const alphabet = "0123456789abcdef";
    try writer.writeByte('"');
    for (bytes) |byte| {
        try writer.writeByte(alphabet[byte >> 4]);
        try writer.writeByte(alphabet[byte & 15]);
    }
    try writer.writeByte('"');
}

fn parseHex(comptime size: usize, value: []const u8) ValidationError![size]u8 {
    if (value.len != size * 2) return error.InvalidDigest;
    var result: [size]u8 = undefined;
    _ = std.fmt.hexToBytes(&result, value) catch return error.InvalidDigest;
    return result;
}

fn parseRepositoryId(value: []const u8) ValidationError![64]u8 {
    if (value.len != 64 or !validLowerHex(value)) return error.InvalidIdentity;
    var result: [64]u8 = undefined;
    @memcpy(&result, value);
    return result;
}

fn validLowerHex(value: []const u8) bool {
    for (value) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    return true;
}

fn findRepository(repositories: []const Repository, id: [64]u8) ?Repository {
    for (repositories) |repository| if (std.mem.eql(u8, &repository.id, &id)) return repository;
    return null;
}

fn lessRepository(_: void, left: Repository, right: Repository) bool {
    return std.mem.order(u8, &left.id, &right.id) == .lt;
}

fn lessPackage(_: void, left: Package, right: Package) bool {
    const name = std.mem.order(u8, left.name, right.name);
    if (name != .eq) return name == .lt;
    const arch = std.mem.order(u8, left.architecture, right.architecture);
    if (arch != .eq) return arch == .lt;
    const version = std.mem.order(u8, left.version, right.version);
    if (version != .eq) return version == .lt;
    return std.mem.order(u8, &left.repository_id, &right.repository_id) == .lt;
}

fn samePackageIdentity(left: Package, right: Package) bool {
    return std.mem.eql(u8, left.name, right.name) and
        std.mem.eql(u8, left.architecture, right.architecture);
}

fn lessBytes20(_: void, left: [20]u8, right: [20]u8) bool {
    return std.mem.order(u8, &left, &right) == .lt;
}

fn safeLeaf(name: []const u8) bool {
    return name.len != 0 and
        !std.mem.eql(u8, name, ".") and
        !std.mem.eql(u8, name, "..") and
        std.mem.indexOfScalar(u8, name, '/') == null and
        std.mem.indexOfScalar(u8, name, '\\') == null;
}

test "exact_lock.test.canonical roundtrip tamper holds and closure ordering" {
    const repo_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(1);
    const repositories = [_]Repository{.{
        .id = repo_id,
        .snapshot_sha256 = snapshot,
        .release_sha256 = @splat(2),
        .index_sha256 = @splat(3),
        .signer_fingerprints = &.{@splat(4)},
    }};
    const packages = [_]Package{
        .{ .name = "zlib", .version = "1:1.2-3", .architecture = "amd64", .repository_id = repo_id, .repository_snapshot_sha256 = snapshot, .sha256 = @splat(5), .declared_size = 12, .retention = .dependency, .dpkg_selection_hold = false },
        .{ .name = "app", .version = "2.0~rc1", .architecture = "amd64", .repository_id = repo_id, .repository_snapshot_sha256 = snapshot, .sha256 = @splat(6), .declared_size = 34, .retention = .requested, .dpkg_selection_hold = true },
    };
    var owned = try create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(7),
        .policy_sha256 = @splat(8),
        .repositories = &repositories,
        .packages = &packages,
        .authenticated_metadata = true,
    });
    defer owned.deinit();
    try std.testing.expectEqualStrings("app", owned.lock.packages[0].name);
    try std.testing.expect(owned.lock.packages[0].dpkg_selection_hold);
    try std.testing.expectEqual(Retention.dependency, owned.lock.packages[1].retention);

    const json = try owned.lock.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    var decoded = try decode(std.testing.allocator, json, maximum_document_bytes);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(u8, &owned.lock.digest_sha256, &decoded.lock.digest_sha256);

    var tampered = try std.testing.allocator.dupe(u8, json);
    defer std.testing.allocator.free(tampered);
    tampered[std.mem.indexOf(u8, tampered, "2.0~rc1").?] = '3';
    try std.testing.expectError(error.DigestMismatch, decode(std.testing.allocator, tampered, maximum_document_bytes));
    try std.testing.expectError(error.UnauthenticatedMetadata, create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(0),
        .policy_sha256 = @splat(0),
        .repositories = &repositories,
        .packages = &packages,
        .authenticated_metadata = false,
    }));
    var substituted = packages;
    substituted[0].repository_snapshot_sha256 = @splat(9);
    try std.testing.expectError(error.RepositorySnapshotMismatch, create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(0),
        .policy_sha256 = @splat(0),
        .repositories = &repositories,
        .packages = &substituted,
        .authenticated_metadata = true,
    }));
    var unknown = try std.testing.allocator.dupe(u8, json);
    defer std.testing.allocator.free(unknown);
    const version_offset = std.mem.indexOf(u8, unknown, "\"version\":1").? + "\"version\":".len;
    unknown[version_offset] = '2';
    try std.testing.expectError(error.UnsupportedSchema, decode(std.testing.allocator, unknown, maximum_document_bytes));
}

test "exact_lock.test.rejects ambiguous repository ownership and identities" {
    const snapshot: [32]u8 = @splat(1);
    const package: Package = .{
        .name = "demo",
        .version = "1",
        .architecture = "amd64",
        .repository_id = @splat('a'),
        .repository_snapshot_sha256 = snapshot,
        .sha256 = @splat(2),
        .declared_size = 1,
        .retention = .requested,
        .dpkg_selection_hold = false,
    };
    const duplicate_signers = [_][20]u8{ @splat(3), @splat(3) };
    const duplicate_repository: Repository = .{
        .id = @splat('a'),
        .snapshot_sha256 = snapshot,
        .release_sha256 = @splat(4),
        .index_sha256 = @splat(5),
        .signer_fingerprints = &duplicate_signers,
    };
    try std.testing.expectError(error.DuplicateSigner, create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(6),
        .policy_sha256 = @splat(7),
        .repositories = &.{duplicate_repository},
        .packages = &.{package},
        .authenticated_metadata = true,
    }));

    var uppercase_repository = duplicate_repository;
    uppercase_repository.id = @splat('A');
    try std.testing.expectError(error.InvalidIdentity, create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(6),
        .policy_sha256 = @splat(7),
        .repositories = &.{uppercase_repository},
        .packages = &.{package},
        .authenticated_metadata = true,
    }));

    const unused_repository: Repository = .{
        .id = @splat('b'),
        .snapshot_sha256 = @splat(8),
        .release_sha256 = @splat(9),
        .index_sha256 = @splat(10),
        .signer_fingerprints = &.{@splat(11)},
    };
    var used_repository = duplicate_repository;
    used_repository.signer_fingerprints = &.{@splat(3)};
    try std.testing.expectError(error.UnusedRepository, create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(6),
        .policy_sha256 = @splat(7),
        .repositories = &.{ used_repository, unused_repository },
        .packages = &.{package},
        .authenticated_metadata = true,
    }));
}
