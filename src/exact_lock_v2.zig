const std = @import("std");
const package_origin = @import("package_origin.zig");

pub const schema_id = "https://debz.dev/schema/exact-closure-lock-v2";
pub const schema_version: u32 = 2;
pub const maximum_document_bytes: usize = 16 * 1024 * 1024;
pub const maximum_repositories: usize = 16_384;
pub const maximum_local_artifacts: usize = 65_536;
pub const maximum_packages: usize = 100_000;
pub const maximum_signer_fingerprints: usize = 65_536;
pub const maximum_validation_items: usize = 200_000;

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

pub const AuthenticatedRepositoryOrigin = struct {
    repository_id: [64]u8,
    repository_snapshot_sha256: [32]u8,
};

pub const PackageOrigin = union(enum) {
    authenticated_repository: AuthenticatedRepositoryOrigin,
    local_artifact: package_origin.LocalArtifactEvidence,
};

pub const Package = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    origin: PackageOrigin,
    sha256: [32]u8,
    declared_size: u64,
    retention: Retention,
    dpkg_selection_hold: bool,
};

pub const Input = struct {
    target_architecture: []const u8,
    request_sha256: [32]u8,
    policy_sha256: [32]u8,
    repositories: []const Repository,
    local_artifacts: []const package_origin.LocalArtifactEvidence,
    packages: []const Package,
    verified_origins: bool,
};

pub const Lock = struct {
    target_architecture: []const u8,
    request_sha256: [32]u8,
    policy_sha256: [32]u8,
    repositories: []const Repository,
    local_artifacts: []const package_origin.LocalArtifactEvidence,
    packages: []const Package,
    digest_sha256: [32]u8,

    pub fn canonicalJson(self: Lock, allocator: std.mem.Allocator) ![]u8 {
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        return output.toOwnedSlice();
    }

    pub fn findPackage(
        self: Lock,
        name: []const u8,
        version: []const u8,
        architecture: []const u8,
    ) ?Package {
        const index = self.findPackageIndex(name, version, architecture) orelse
            return null;
        return self.packages[index];
    }

    pub fn findPackageIndex(
        self: Lock,
        name: []const u8,
        version: []const u8,
        architecture: []const u8,
    ) ?usize {
        var low: usize = 0;
        var high = self.packages.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            const package = self.packages[middle];
            switch (comparePackageKey(package, name, architecture, version)) {
                .lt => low = middle + 1,
                .gt => high = middle,
                .eq => return middle,
            }
        }
        return null;
    }

    pub fn findIdentity(self: Lock, name: []const u8, architecture: []const u8) ?Package {
        var low: usize = 0;
        var high = self.packages.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            const package = self.packages[middle];
            const name_order = std.mem.order(u8, package.name, name);
            const order = if (name_order == .eq)
                std.mem.order(u8, package.architecture, architecture)
            else
                name_order;
            switch (order) {
                .lt => low = middle + 1,
                .gt => high = middle,
                .eq => return package,
            }
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
    UnverifiedOrigin,
    EmptyArchitecture,
    EmptyClosure,
    InvalidIdentity,
    MissingSigner,
    DuplicateSigner,
    DuplicateRepository,
    UnusedRepository,
    DuplicateArtifact,
    UnusedArtifact,
    DuplicatePackage,
    MissingRepository,
    MissingArtifact,
    RepositorySnapshotMismatch,
    ArtifactEvidenceMismatch,
    NonCanonicalDocument,
    UnsupportedSchema,
    DigestMismatch,
    DocumentTooLarge,
    InvalidDigest,
    TooManyRepositories,
    TooManyArtifacts,
    TooManyPackages,
    TooManySigners,
    ValidationWorkLimitExceeded,
};

pub fn create(
    allocator: std.mem.Allocator,
    input: Input,
) (std.mem.Allocator.Error || ValidationError || package_origin.ValidationError)!OwnedLock {
    if (!input.verified_origins) return error.UnverifiedOrigin;
    if (input.target_architecture.len == 0) return error.EmptyArchitecture;
    if (input.packages.len == 0) return error.EmptyClosure;
    if (input.repositories.len > maximum_repositories) return error.TooManyRepositories;
    if (input.local_artifacts.len > maximum_local_artifacts) return error.TooManyArtifacts;
    if (input.packages.len > maximum_packages) return error.TooManyPackages;
    var signer_count: usize = 0;
    for (input.repositories) |repository| {
        signer_count = std.math.add(usize, signer_count, repository.signer_fingerprints.len) catch
            return error.ValidationWorkLimitExceeded;
        if (signer_count > maximum_signer_fingerprints) return error.TooManySigners;
    }
    const evidence_count = std.math.add(
        usize,
        input.repositories.len,
        input.local_artifacts.len,
    ) catch return error.ValidationWorkLimitExceeded;
    const validation_items = std.math.add(
        usize,
        evidence_count,
        input.packages.len,
    ) catch return error.ValidationWorkLimitExceeded;
    if (validation_items > maximum_validation_items)
        return error.ValidationWorkLimitExceeded;

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
            if (signer_index != 0 and
                std.mem.eql(u8, &fingerprint, &fingerprints[signer_index - 1]))
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

    const local_artifacts = try owned.alloc(
        package_origin.LocalArtifactEvidence,
        input.local_artifacts.len,
    );
    for (input.local_artifacts, 0..) |artifact, index| {
        try package_origin.validateLocalArtifact(artifact);
        local_artifacts[index] = try dupeLocalArtifact(owned, artifact);
    }
    std.mem.sort(
        package_origin.LocalArtifactEvidence,
        local_artifacts,
        {},
        lessLocalArtifact,
    );
    for (local_artifacts, 0..) |artifact, index| {
        if (index != 0 and std.mem.eql(
            u8,
            &artifact.artifact_id,
            &local_artifacts[index - 1].artifact_id,
        )) return error.DuplicateArtifact;
    }
    const referenced_repositories = try owned.alloc(bool, repositories.len);
    @memset(referenced_repositories, false);
    const referenced_artifacts = try owned.alloc(bool, local_artifacts.len);
    @memset(referenced_artifacts, false);

    const packages = try owned.alloc(Package, input.packages.len);
    for (input.packages, 0..) |package, index| {
        if (!validIdentity(package.name) or
            !validIdentity(package.version) or
            !validIdentity(package.architecture))
            return error.InvalidIdentity;
        packages[index] = package;
        packages[index].name = try owned.dupe(u8, package.name);
        packages[index].version = try owned.dupe(u8, package.version);
        packages[index].architecture = try owned.dupe(u8, package.architecture);
        switch (package.origin) {
            .authenticated_repository => |origin| {
                const repository_index = findRepositoryIndex(
                    repositories,
                    origin.repository_id,
                ) orelse
                    return error.MissingRepository;
                const repository = repositories[repository_index];
                if (!std.mem.eql(
                    u8,
                    &repository.snapshot_sha256,
                    &origin.repository_snapshot_sha256,
                )) return error.RepositorySnapshotMismatch;
                referenced_repositories[repository_index] = true;
            },
            .local_artifact => |origin| {
                try package_origin.validateLocalArtifact(origin);
                const artifact_index = findLocalArtifactIndex(
                    local_artifacts,
                    origin.artifact_id,
                ) orelse
                    return error.MissingArtifact;
                const artifact = local_artifacts[artifact_index];
                if (!package_origin.eqlLocalArtifact(artifact, origin) or
                    !std.mem.eql(u8, package.name, origin.package) or
                    !std.mem.eql(u8, package.version, origin.version) or
                    !std.mem.eql(u8, package.architecture, origin.architecture) or
                    !std.mem.eql(u8, &package.sha256, &origin.sha256) or
                    package.declared_size != origin.size)
                    return error.ArtifactEvidenceMismatch;
                packages[index].origin = .{
                    .local_artifact = try dupeLocalArtifact(owned, origin),
                };
                referenced_artifacts[artifact_index] = true;
            },
        }
    }
    std.mem.sort(Package, packages, {}, lessPackage);
    for (packages, 0..) |package, index| {
        if (index != 0 and samePackageIdentity(package, packages[index - 1]))
            return error.DuplicatePackage;
    }

    for (referenced_repositories) |referenced|
        if (!referenced) return error.UnusedRepository;
    for (referenced_artifacts) |referenced|
        if (!referenced) return error.UnusedArtifact;

    var lock: Lock = .{
        .target_architecture = try owned.dupe(u8, input.target_architecture),
        .request_sha256 = input.request_sha256,
        .policy_sha256 = input.policy_sha256,
        .repositories = repositories,
        .local_artifacts = local_artifacts,
        .packages = packages,
        .digest_sha256 = undefined,
    };
    lock.digest_sha256 = digestPayload(lock);
    return .{ .lock = lock, .arena = arena, .backing_allocator = allocator };
}

const OriginType = enum {
    authenticated_repository,
    local_artifact,
};

const WireRepository = struct {
    id: []const u8,
    snapshot_sha256: []const u8,
    release_sha256: []const u8,
    index_sha256: []const u8,
    signer_fingerprints: []const []const u8,
};

const WireIdentity = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
};

const WireLocalArtifact = struct {
    artifact_id: []const u8,
    sha256: []const u8,
    size: u64,
    package: WireIdentity,
    acquisition_url: []const u8,
    trust_mode: package_origin.LocalArtifactTrustMode,
};

const WireOrigin = struct {
    type: OriginType,
    repository_id: ?[]const u8 = null,
    repository_snapshot_sha256: ?[]const u8 = null,
    artifact_id: ?[]const u8 = null,
    sha256: ?[]const u8 = null,
    size: ?u64 = null,
    package: ?WireIdentity = null,
    acquisition_url: ?[]const u8 = null,
    trust_mode: ?package_origin.LocalArtifactTrustMode = null,
};

const WirePackage = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    origin: WireOrigin,
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
    local_artifacts: []const WireLocalArtifact,
    packages: []const WirePackage,
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

    const repositories = try allocator.alloc(Repository, parsed.value.repositories.len);
    var repositories_initialized: usize = 0;
    defer {
        for (repositories[0..repositories_initialized]) |repository|
            allocator.free(repository.signer_fingerprints);
        allocator.free(repositories);
    }
    for (parsed.value.repositories, 0..) |repository, index| {
        const signers = try allocator.alloc([20]u8, repository.signer_fingerprints.len);
        errdefer allocator.free(signers);
        for (repository.signer_fingerprints, 0..) |fingerprint, signer_index|
            signers[signer_index] = try parseHex(20, fingerprint);
        repositories[index] = .{
            .id = try parseId(repository.id),
            .snapshot_sha256 = try parseHex(32, repository.snapshot_sha256),
            .release_sha256 = try parseHex(32, repository.release_sha256),
            .index_sha256 = try parseHex(32, repository.index_sha256),
            .signer_fingerprints = signers,
        };
        repositories_initialized += 1;
    }

    const local_artifacts = try allocator.alloc(
        package_origin.LocalArtifactEvidence,
        parsed.value.local_artifacts.len,
    );
    defer allocator.free(local_artifacts);
    for (parsed.value.local_artifacts, 0..) |artifact, index|
        local_artifacts[index] = try parseLocalArtifact(artifact);

    const packages = try allocator.alloc(Package, parsed.value.packages.len);
    defer allocator.free(packages);
    for (parsed.value.packages, 0..) |package, index| {
        packages[index] = .{
            .name = package.name,
            .version = package.version,
            .architecture = package.architecture,
            .origin = try parseOrigin(package.origin),
            .sha256 = try parseHex(32, package.sha256),
            .declared_size = package.declared_size,
            .retention = package.retention,
            .dpkg_selection_hold = package.dpkg_selection_hold,
        };
    }

    var result = try create(allocator, .{
        .target_architecture = parsed.value.target_architecture,
        .request_sha256 = try parseHex(32, parsed.value.request_sha256),
        .policy_sha256 = try parseHex(32, parsed.value.policy_sha256),
        .repositories = repositories,
        .local_artifacts = local_artifacts,
        .packages = packages,
        .verified_origins = true,
    });
    errdefer result.deinit();
    const expected = try parseHex(32, parsed.value.digest_sha256);
    if (!std.mem.eql(u8, &expected, &result.lock.digest_sha256))
        return error.DigestMismatch;
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
        const stage = ".debz-lock-v2.new";
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
        switch (@import("builtin").os.tag) {
            .linux => if (std.posix.errno(std.os.linux.fsync(self.dir.handle)) != .SUCCESS)
                return error.Unexpected,
            else => {},
        }
    }
};

fn parseOrigin(origin: WireOrigin) ValidationError!PackageOrigin {
    return switch (origin.type) {
        .authenticated_repository => blk: {
            if (origin.repository_id == null or
                origin.repository_snapshot_sha256 == null or
                origin.artifact_id != null or
                origin.sha256 != null or
                origin.size != null or
                origin.package != null or
                origin.acquisition_url != null or
                origin.trust_mode != null)
                return error.InvalidIdentity;
            break :blk .{ .authenticated_repository = .{
                .repository_id = try parseId(origin.repository_id.?),
                .repository_snapshot_sha256 = try parseHex(
                    32,
                    origin.repository_snapshot_sha256.?,
                ),
            } };
        },
        .local_artifact => blk: {
            if (origin.repository_id != null or
                origin.repository_snapshot_sha256 != null or
                origin.artifact_id == null or
                origin.sha256 == null or
                origin.size == null or
                origin.package == null or
                origin.acquisition_url == null or
                origin.trust_mode == null)
                return error.InvalidIdentity;
            const identity = origin.package.?;
            break :blk .{ .local_artifact = .{
                .artifact_id = try parseId(origin.artifact_id.?),
                .sha256 = try parseHex(32, origin.sha256.?),
                .size = origin.size.?,
                .package = identity.name,
                .version = identity.version,
                .architecture = identity.architecture,
                .acquisition_url = origin.acquisition_url.?,
                .trust_mode = origin.trust_mode.?,
            } };
        },
    };
}

fn parseLocalArtifact(
    artifact: WireLocalArtifact,
) ValidationError!package_origin.LocalArtifactEvidence {
    return .{
        .artifact_id = try parseId(artifact.artifact_id),
        .sha256 = try parseHex(32, artifact.sha256),
        .size = artifact.size,
        .package = artifact.package.name,
        .version = artifact.package.version,
        .architecture = artifact.package.architecture,
        .acquisition_url = artifact.acquisition_url,
        .trust_mode = artifact.trust_mode,
    };
}

fn dupeLocalArtifact(
    allocator: std.mem.Allocator,
    artifact: package_origin.LocalArtifactEvidence,
) !package_origin.LocalArtifactEvidence {
    var result = artifact;
    result.package = try allocator.dupe(u8, artifact.package);
    result.version = try allocator.dupe(u8, artifact.version);
    result.architecture = try allocator.dupe(u8, artifact.architecture);
    result.acquisition_url = try allocator.dupe(u8, artifact.acquisition_url);
    return result;
}

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
    try writer.writeAll("],\"local_artifacts\":[");
    for (lock.local_artifacts, 0..) |artifact, index| {
        if (index != 0) try writer.writeByte(',');
        try writeLocalArtifact(writer, artifact);
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
        try writer.writeAll(",\"origin\":");
        try writeOrigin(writer, package.origin);
        try writer.writeAll(",\"sha256\":");
        try writeHexString(writer, &package.sha256);
        try writer.print(",\"declared_size\":{},\"retention\":", .{package.declared_size});
        try writeJsonString(writer, @tagName(package.retention));
        try writer.print(",\"dpkg_selection_hold\":{}}}", .{package.dpkg_selection_hold});
    }
    try writer.writeAll("]}");
}

fn writeOrigin(writer: *std.Io.Writer, origin: PackageOrigin) !void {
    switch (origin) {
        .authenticated_repository => |repository| {
            try writer.writeAll("{\"type\":\"authenticated_repository\",\"repository_id\":");
            try writeJsonString(writer, &repository.repository_id);
            try writer.writeAll(",\"repository_snapshot_sha256\":");
            try writeHexString(writer, &repository.repository_snapshot_sha256);
            try writer.writeByte('}');
        },
        .local_artifact => |artifact| {
            try writer.writeAll("{\"type\":\"local_artifact\",\"artifact_id\":");
            try writeJsonString(writer, &artifact.artifact_id);
            try writer.writeAll(",\"sha256\":");
            try writeHexString(writer, &artifact.sha256);
            try writer.print(",\"size\":{},\"package\":", .{artifact.size});
            try writeIdentity(writer, artifact);
            try writer.writeAll(",\"acquisition_url\":");
            try writeJsonString(writer, artifact.acquisition_url);
            try writer.writeAll(",\"trust_mode\":");
            try writeJsonString(writer, @tagName(artifact.trust_mode));
            try writer.writeByte('}');
        },
    }
}

fn writeLocalArtifact(
    writer: *std.Io.Writer,
    artifact: package_origin.LocalArtifactEvidence,
) !void {
    try writer.writeAll("{\"artifact_id\":");
    try writeJsonString(writer, &artifact.artifact_id);
    try writer.writeAll(",\"sha256\":");
    try writeHexString(writer, &artifact.sha256);
    try writer.print(",\"size\":{},\"package\":", .{artifact.size});
    try writeIdentity(writer, artifact);
    try writer.writeAll(",\"acquisition_url\":");
    try writeJsonString(writer, artifact.acquisition_url);
    try writer.writeAll(",\"trust_mode\":");
    try writeJsonString(writer, @tagName(artifact.trust_mode));
    try writer.writeByte('}');
}

fn writeIdentity(
    writer: *std.Io.Writer,
    artifact: package_origin.LocalArtifactEvidence,
) !void {
    try writer.writeAll("{\"name\":");
    try writeJsonString(writer, artifact.package);
    try writer.writeAll(",\"version\":");
    try writeJsonString(writer, artifact.version);
    try writer.writeAll(",\"architecture\":");
    try writeJsonString(writer, artifact.architecture);
    try writer.writeByte('}');
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

fn parseId(value: []const u8) ValidationError![64]u8 {
    if (value.len != 64 or !validLowerHex(value)) return error.InvalidIdentity;
    var result: [64]u8 = undefined;
    @memcpy(&result, value);
    return result;
}

fn validLowerHex(value: []const u8) bool {
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return false;
    }
    return true;
}

fn validIdentity(value: []const u8) bool {
    if (value.len == 0) return false;
    for (value) |byte| if (byte <= 0x1f or byte == 0x7f) return false;
    return true;
}

fn findRepositoryIndex(repositories: []const Repository, id: [64]u8) ?usize {
    var low: usize = 0;
    var high = repositories.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        switch (std.mem.order(u8, &repositories[middle].id, &id)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return middle,
        }
    }
    return null;
}

fn findLocalArtifactIndex(
    artifacts: []const package_origin.LocalArtifactEvidence,
    id: [64]u8,
) ?usize {
    var low: usize = 0;
    var high = artifacts.len;
    while (low < high) {
        const middle = low + (high - low) / 2;
        switch (std.mem.order(u8, &artifacts[middle].artifact_id, &id)) {
            .lt => low = middle + 1,
            .gt => high = middle,
            .eq => return middle,
        }
    }
    return null;
}

fn comparePackageKey(
    package: Package,
    name: []const u8,
    architecture: []const u8,
    version: []const u8,
) std.math.Order {
    const name_order = std.mem.order(u8, package.name, name);
    if (name_order != .eq) return name_order;
    const architecture_order = std.mem.order(u8, package.architecture, architecture);
    if (architecture_order != .eq) return architecture_order;
    return std.mem.order(u8, package.version, version);
}

fn lessRepository(_: void, left: Repository, right: Repository) bool {
    return std.mem.order(u8, &left.id, &right.id) == .lt;
}

fn lessLocalArtifact(
    _: void,
    left: package_origin.LocalArtifactEvidence,
    right: package_origin.LocalArtifactEvidence,
) bool {
    return std.mem.order(u8, &left.artifact_id, &right.artifact_id) == .lt;
}

fn lessPackage(_: void, left: Package, right: Package) bool {
    const name = std.mem.order(u8, left.name, right.name);
    if (name != .eq) return name == .lt;
    const arch = std.mem.order(u8, left.architecture, right.architecture);
    if (arch != .eq) return arch == .lt;
    const version = std.mem.order(u8, left.version, right.version);
    if (version != .eq) return version == .lt;
    return originOrder(left.origin, right.origin) == .lt;
}

fn originOrder(left: PackageOrigin, right: PackageOrigin) std.math.Order {
    return switch (left) {
        .authenticated_repository => |left_repository| switch (right) {
            .authenticated_repository => |right_repository| std.mem.order(
                u8,
                &left_repository.repository_id,
                &right_repository.repository_id,
            ),
            .local_artifact => .lt,
        },
        .local_artifact => |left_artifact| switch (right) {
            .authenticated_repository => .gt,
            .local_artifact => |right_artifact| std.mem.order(u8, &left_artifact.artifact_id, &right_artifact.artifact_id),
        },
    };
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

test "exact_lock_v2.test.mixed origins canonical roundtrip and tamper rejection" {
    const repository_id: [64]u8 = @splat('a');
    const snapshot: [32]u8 = @splat(1);
    const artifact_digest: [32]u8 = @splat(2);
    const artifact: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(artifact_digest),
        .sha256 = artifact_digest,
        .size = 42,
        .package = "vendor-repo",
        .version = "1.0",
        .architecture = "all",
        .acquisition_url = "https://example.test/vendor.deb?REDACTED",
        .trust_mode = .verified_https,
    };
    const repositories = [_]Repository{.{
        .id = repository_id,
        .snapshot_sha256 = snapshot,
        .release_sha256 = @splat(3),
        .index_sha256 = @splat(4),
        .signer_fingerprints = &.{@splat(5)},
    }};
    const packages = [_]Package{
        .{
            .name = "dependency",
            .version = "2",
            .architecture = "amd64",
            .origin = .{ .authenticated_repository = .{
                .repository_id = repository_id,
                .repository_snapshot_sha256 = snapshot,
            } },
            .sha256 = @splat(6),
            .declared_size = 12,
            .retention = .dependency,
            .dpkg_selection_hold = false,
        },
        .{
            .name = artifact.package,
            .version = artifact.version,
            .architecture = artifact.architecture,
            .origin = .{ .local_artifact = artifact },
            .sha256 = artifact.sha256,
            .declared_size = artifact.size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        },
    };
    var owned = try create(std.testing.allocator, .{
        .target_architecture = "amd64",
        .request_sha256 = @splat(7),
        .policy_sha256 = @splat(8),
        .repositories = &repositories,
        .local_artifacts = &.{artifact},
        .packages = &packages,
        .verified_origins = true,
    });
    defer owned.deinit();
    const json = try owned.lock.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(json);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"local_artifact\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"signer_fingerprints\"") != null);
    var decoded = try decode(std.testing.allocator, json, maximum_document_bytes);
    defer decoded.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &owned.lock.digest_sha256,
        &decoded.lock.digest_sha256,
    );

    var tampered = try std.testing.allocator.dupe(u8, json);
    defer std.testing.allocator.free(tampered);
    const url = std.mem.indexOf(u8, tampered, "example.test").?;
    tampered[url] = 'E';
    try std.testing.expectError(
        error.ArtifactEvidenceMismatch,
        decode(std.testing.allocator, tampered, maximum_document_bytes),
    );
    const noncanonical = try std.fmt.allocPrint(
        std.testing.allocator,
        "{{ {s}",
        .{json[1..]},
    );
    defer std.testing.allocator.free(noncanonical);
    try std.testing.expectError(
        error.NonCanonicalDocument,
        decode(std.testing.allocator, noncanonical, maximum_document_bytes),
    );
}

test "exact_lock_v2.test.rejects origin substitution mismatch and unused evidence" {
    const digest: [32]u8 = @splat(9);
    const artifact: package_origin.LocalArtifactEvidence = .{
        .artifact_id = package_origin.artifactIdFromSha256(digest),
        .sha256 = digest,
        .size = 9,
        .package = "demo",
        .version = "1",
        .architecture = "amd64",
        .acquisition_url = "file:///demo.deb",
        .trust_mode = .pinned_sha256,
    };
    var mismatched = artifact;
    mismatched.size += 1;
    const package: Package = .{
        .name = artifact.package,
        .version = artifact.version,
        .architecture = artifact.architecture,
        .origin = .{ .local_artifact = mismatched },
        .sha256 = artifact.sha256,
        .declared_size = artifact.size,
        .retention = .requested,
        .dpkg_selection_hold = false,
    };
    try std.testing.expectError(error.ArtifactEvidenceMismatch, create(
        std.testing.allocator,
        .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(0),
            .policy_sha256 = @splat(0),
            .repositories = &.{},
            .local_artifacts = &.{artifact},
            .packages = &.{package},
            .verified_origins = true,
        },
    ));

    const repository: Repository = .{
        .id = @splat('b'),
        .snapshot_sha256 = @splat(1),
        .release_sha256 = @splat(2),
        .index_sha256 = @splat(3),
        .signer_fingerprints = &.{@splat(4)},
    };
    const local_package: Package = .{
        .name = artifact.package,
        .version = artifact.version,
        .architecture = artifact.architecture,
        .origin = .{ .local_artifact = artifact },
        .sha256 = artifact.sha256,
        .declared_size = artifact.size,
        .retention = .requested,
        .dpkg_selection_hold = false,
    };
    try std.testing.expectError(error.UnusedRepository, create(
        std.testing.allocator,
        .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(0),
            .policy_sha256 = @splat(0),
            .repositories = &.{repository},
            .local_artifacts = &.{artifact},
            .packages = &.{local_package},
            .verified_origins = true,
        },
    ));

    const MismatchKind = enum { digest, size, identity, url, trust };
    inline for ([_]MismatchKind{
        .digest,
        .size,
        .identity,
        .url,
        .trust,
    }) |mismatch_kind| {
        var changed = artifact;
        switch (mismatch_kind) {
            .digest => changed.sha256 = @splat(0xaa),
            .size => changed.size += 1,
            .identity => changed.version = "2",
            .url => changed.acquisition_url = "file:///other.deb",
            .trust => changed.trust_mode = .verified_https,
        }
        const changed_package: Package = .{
            .name = artifact.package,
            .version = artifact.version,
            .architecture = artifact.architecture,
            .origin = .{ .local_artifact = changed },
            .sha256 = artifact.sha256,
            .declared_size = artifact.size,
            .retention = .requested,
            .dpkg_selection_hold = false,
        };
        const expected_error: anyerror = if (mismatch_kind == .trust)
            error.TrustModeMismatch
        else
            error.ArtifactEvidenceMismatch;
        try std.testing.expectError(expected_error, create(
            std.testing.allocator,
            .{
                .target_architecture = "amd64",
                .request_sha256 = @splat(0),
                .policy_sha256 = @splat(0),
                .repositories = &.{},
                .local_artifacts = &.{artifact},
                .packages = &.{changed_package},
                .verified_origins = true,
            },
        ));
    }

    {
        const count = 4096;
        var input_arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer input_arena.deinit();
        const allocator = input_arena.allocator();
        const artifacts = try allocator.alloc(package_origin.LocalArtifactEvidence, count);
        const packages = try allocator.alloc(Package, count);
        for (0..count) |offset| {
            const value: u64 = @intCast(count - offset);
            var package_digest: [32]u8 = @splat(0);
            std.mem.writeInt(u64, package_digest[0..8], value, .big);
            const name = try std.fmt.allocPrint(allocator, "package-{d:0>5}", .{value});
            const url = try std.fmt.allocPrint(allocator, "file:///{s}.deb", .{name});
            const large_artifact: package_origin.LocalArtifactEvidence = .{
                .artifact_id = package_origin.artifactIdFromSha256(package_digest),
                .sha256 = package_digest,
                .size = value + 1,
                .package = name,
                .version = "1",
                .architecture = "amd64",
                .acquisition_url = url,
                .trust_mode = .pinned_sha256,
            };
            artifacts[offset] = large_artifact;
            packages[offset] = .{
                .name = large_artifact.package,
                .version = large_artifact.version,
                .architecture = large_artifact.architecture,
                .origin = .{ .local_artifact = large_artifact },
                .sha256 = large_artifact.sha256,
                .declared_size = large_artifact.size,
                .retention = .dependency,
                .dpkg_selection_hold = false,
            };
        }
        var lock = try create(std.testing.allocator, .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(1),
            .policy_sha256 = @splat(2),
            .repositories = &.{},
            .local_artifacts = artifacts,
            .packages = packages,
            .verified_origins = true,
        });
        defer lock.deinit();
        try std.testing.expectEqual(count, lock.lock.packages.len);
        try std.testing.expect(lock.lock.findPackage("package-02048", "1", "amd64") != null);
        const canonical = try lock.lock.canonicalJson(std.testing.allocator);
        defer std.testing.allocator.free(canonical);
        try std.testing.expect(canonical.len < maximum_document_bytes);
        var decoded = try decode(std.testing.allocator, canonical, maximum_document_bytes);
        defer decoded.deinit();
        try std.testing.expectEqual(count, decoded.lock.local_artifacts.len);

        const too_many = try std.testing.allocator.alloc(
            Repository,
            maximum_repositories + 1,
        );
        defer std.testing.allocator.free(too_many);
        try std.testing.expectError(error.TooManyRepositories, create(
            std.testing.allocator,
            .{
                .target_architecture = "amd64",
                .request_sha256 = @splat(1),
                .policy_sha256 = @splat(2),
                .repositories = too_many,
                .local_artifacts = artifacts[0..1],
                .packages = packages[0..1],
                .verified_origins = true,
            },
        ));
    }

    try std.testing.expectError(error.DuplicateArtifact, create(
        std.testing.allocator,
        .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(0),
            .policy_sha256 = @splat(0),
            .repositories = &.{},
            .local_artifacts = &.{ artifact, artifact },
            .packages = &.{local_package},
            .verified_origins = true,
        },
    ));

    var unused = artifact;
    unused.artifact_id = @splat('c');
    try std.testing.expectError(error.UnusedArtifact, create(
        std.testing.allocator,
        .{
            .target_architecture = "amd64",
            .request_sha256 = @splat(0),
            .policy_sha256 = @splat(0),
            .repositories = &.{},
            .local_artifacts = &.{ artifact, unused },
            .packages = &.{local_package},
            .verified_origins = true,
        },
    ));
}
