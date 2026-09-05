const std = @import("std");
const absolute_path = @import("absolute_path.zig");
const dpkg_status = @import("dpkg_status.zig");
const openpgp = @import("openpgp_verifier.zig");
const repository_policy = @import("repository_policy.zig");
const repository_refresh = @import("repository_refresh.zig");
const source = @import("source.zig");

pub const schema_id = "https://debz.dev/schema/apt-config-snapshot-v2";
pub const schema_version: u32 = 2;
pub const maximum_document_bytes: usize = 16 * 1024 * 1024;

const sources_list_path = "/etc/apt/sources.list";
const sources_directory_path = "/etc/apt/sources.list.d";
const global_keyring_path = "/etc/apt/trusted.gpg";
const global_keyring_directory_path = "/etc/apt/trusted.gpg.d";
const status_path = "/var/lib/dpkg/status";
const foreign_architectures_path = "/var/lib/dpkg/arch";

pub const Limits = struct {
    source: source.Limits = .{},
    repository: repository_policy.Limits = .{},
    keyring: openpgp.Limits = .{},
    max_directory_entries: usize = 4096,
    max_sources: usize = 1024,
    max_source_material_bytes: usize = 16 * 1024 * 1024,
    max_keyrings: usize = 1024,
    max_keyring_material_bytes: usize = 64 * 1024 * 1024,
    max_exclusions: usize = 8192,
    max_status_bytes: usize = 32 * 1024 * 1024,
    max_architecture_state_bytes: usize = 64 * 1024,
};

pub const EntryKind = enum {
    regular,
    directory,
    symlink,
    other,
};

pub const DirectoryEntry = struct {
    name: []const u8,
    kind: EntryKind,
};

pub const DirectoryListing = struct {
    entries: []DirectoryEntry,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *DirectoryListing) void {
        for (self.entries) |entry| self.allocator.free(entry.name);
        self.allocator.free(self.entries);
        self.* = undefined;
    }
};

/// Filesystem errors intentionally distinguish missing files, symlinks, and
/// non-regular objects so eligible APT inputs never disappear silently.
pub const FileSystemError = error{
    FileNotFound,
    Symlink,
    NotRegular,
    UnsafePath,
    DirectoryLimitExceeded,
};

pub const FileSystem = struct {
    context: *anyopaque,
    host_root: bool,
    readFileFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
        usize,
    ) anyerror![]u8,
    listDirectoryFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const u8,
        usize,
    ) anyerror!DirectoryListing,

    pub fn readFile(
        self: FileSystem,
        allocator: std.mem.Allocator,
        logical_path: []const u8,
        maximum: usize,
    ) ![]u8 {
        return self.readFileFn(self.context, allocator, logical_path, maximum);
    }

    pub fn listDirectory(
        self: FileSystem,
        allocator: std.mem.Allocator,
        logical_path: []const u8,
        maximum_entries: usize,
    ) !DirectoryListing {
        return self.listDirectoryFn(self.context, allocator, logical_path, maximum_entries);
    }
};

pub const EnvironmentEntry = struct {
    key: []const u8,
    value: []const u8,
};

pub const ProcessOutput = struct {
    stdout: []u8,
    stderr: []u8,
    exit_code: u8,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *ProcessOutput) void {
        self.allocator.free(self.stdout);
        self.allocator.free(self.stderr);
        self.* = undefined;
    }
};

pub const ProcessRunner = struct {
    context: *anyopaque,
    runFn: *const fn (
        *anyopaque,
        std.mem.Allocator,
        []const []const u8,
        []const EnvironmentEntry,
    ) anyerror!ProcessOutput,

    pub fn run(
        self: ProcessRunner,
        allocator: std.mem.Allocator,
        argv: []const []const u8,
        environment: []const EnvironmentEntry,
    ) !ProcessOutput {
        return self.runFn(self.context, allocator, argv, environment);
    }
};

pub const Dependencies = struct {
    filesystem: FileSystem,
    process: ?ProcessRunner = null,
};

pub const Request = struct {
    /// Used only to decide whether the fixed dpkg fallback is permitted. The
    /// filesystem adapter owns logical-to-physical root mapping.
    root_path: []const u8,
    architecture_override: ?[]const u8 = null,
    source_policies: []const SourcePolicy = &.{},
    limits: Limits = .{},
    dependencies: Dependencies,
};

pub const RecordedRequest = struct {
    root_path: []const u8,
    manifest: Manifest,
    limits: Limits = .{},
    dependencies: Dependencies,
};

pub const ArchitectureRequest = struct {
    root_path: []const u8,
    architecture_override: ?[]const u8 = null,
    limits: Limits = .{},
    dependencies: Dependencies,
};

pub fn discoverNativeArchitecture(
    allocator: std.mem.Allocator,
    request: ArchitectureRequest,
) ![]u8 {
    if (!validRootPath(request.root_path) or
        request.dependencies.filesystem.host_root !=
            std.mem.eql(u8, request.root_path, "/"))
        return error.InvalidRootPath;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const architecture = try discoverArchitecture(arena.allocator(), allocator, .{
        .root_path = request.root_path,
        .architecture_override = request.architecture_override,
        .limits = request.limits,
        .dependencies = request.dependencies,
    });
    return allocator.dupe(u8, architecture.native);
}

pub const SourcePolicy = struct {
    logical_path: []const u8,
    freshness: repository_refresh.ExpiryPolicy,
};

pub const SourceRecord = struct {
    logical_path: []const u8,
    sha256: [32]u8,
    format: source.Format,
    freshness: repository_refresh.ExpiryPolicy = .require_valid_until,
};

pub const RepositoryPolicyRecord = struct {
    repository_id: [64]u8,
    freshness: repository_refresh.ExpiryPolicy,
};

pub const KeyringUse = enum {
    declared,
    global,
    declared_and_global,
};

pub const KeyringRecord = struct {
    logical_path: []const u8,
    sha256: [32]u8,
    primary_fingerprints: []const [20]u8,
    use: KeyringUse,
};

pub const ExclusionReason = enum {
    unsupported_name,
    directory,
    symlink,
    special,
};

pub const Exclusion = struct {
    logical_path: []const u8,
    reason: ExclusionReason,
};

pub const Manifest = struct {
    native_architecture: []const u8,
    foreign_architectures: []const []const u8,
    sources: []const SourceRecord,
    configuration_id: [64]u8,
    repository_ids: []const [64]u8,
    repository_policies: []const RepositoryPolicyRecord = &.{},
    keyrings: []const KeyringRecord,
    global_trust_compatibility: bool,
    exclusions: []const Exclusion,
    digest_sha256: [32]u8,

    pub fn canonicalJson(self: Manifest, allocator: std.mem.Allocator) ![]u8 {
        try validateSerializableManifest(self);
        var output: std.Io.Writer.Allocating = .init(allocator);
        errdefer output.deinit();
        try writeDocument(self, &output.writer);
        return output.toOwnedSlice();
    }
};

fn validateSerializableManifest(manifest: Manifest) ValidationError!void {
    if (!validArchitecture(manifest.native_architecture))
        return error.InvalidArchitecture;
    for (manifest.foreign_architectures) |architecture| {
        if (!validArchitecture(architecture)) return error.InvalidArchitecture;
    }
    for (manifest.sources) |record| {
        if (!validLogicalPath(record.logical_path) or
            !repository_refresh.validExpiryPolicy(record.freshness))
            return error.InvalidPath;
    }
    if (!validLowerHex(&manifest.configuration_id)) return error.InvalidIdentity;
    for (manifest.repository_ids) |id| {
        if (!validLowerHex(&id)) return error.InvalidIdentity;
    }
    if (manifest.repository_policies.len != manifest.repository_ids.len)
        return error.InvalidIdentity;
    for (manifest.repository_policies, manifest.repository_ids) |policy, id| {
        if (!std.mem.eql(u8, &policy.repository_id, &id) or
            !repository_refresh.validExpiryPolicy(policy.freshness))
            return error.InvalidIdentity;
    }
    for (manifest.keyrings) |record| {
        if (!validLogicalPath(record.logical_path)) return error.InvalidPath;
    }
    for (manifest.exclusions) |exclusion| {
        if (!validLogicalPath(exclusion.logical_path)) return error.InvalidPath;
    }
}

pub const OwnedManifest = struct {
    manifest: Manifest,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *OwnedManifest) void {
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub const SourceMaterial = struct {
    logical_path: []const u8,
    bytes: []const u8,
    sha256: [32]u8,
    format: source.Format,
};

pub const KeyringMaterial = struct {
    logical_path: []const u8,
    bytes: []const u8,
    sha256: [32]u8,
    primary_fingerprints: []const [20]u8,
    use: KeyringUse,
};

pub const Snapshot = struct {
    configuration: repository_policy.Configuration,
    manifest: OwnedManifest,
    source_materials: []const SourceMaterial,
    keyring_materials: []const KeyringMaterial,
    verifier_limits: openpgp.Limits,
    arena: *std.heap.ArenaAllocator,
    backing_allocator: std.mem.Allocator,

    pub fn deinit(self: *Snapshot) void {
        self.configuration.deinit();
        self.manifest.deinit();
        self.arena.deinit();
        self.backing_allocator.destroy(self.arena);
        self.* = undefined;
    }

    /// Builds verifier input from imported bytes while returning the logical
    /// declarations separately for repository-policy runtime matching.
    pub fn runtimeTrust(
        self: *const Snapshot,
        allocator: std.mem.Allocator,
        repository: repository_policy.NormalizedRepository,
    ) !RuntimeTrust {
        var keyrings: std.ArrayList(openpgp.Keyring) = .empty;
        errdefer keyrings.deinit(allocator);
        var seen_paths = std.StringHashMap(void).init(allocator);
        defer seen_paths.deinit();
        if (repository.signed_by.len == 0) {
            for (self.keyring_materials) |material| {
                if (material.use != .global and material.use != .declared_and_global)
                    continue;
                if (seen_paths.contains(material.logical_path)) continue;
                try seen_paths.put(material.logical_path, {});
                try keyrings.append(allocator, .{ .bytes = material.bytes });
            }
        } else {
            for (repository.signed_by) |logical_path| {
                if (seen_paths.contains(logical_path)) continue;
                const material = self.findKeyring(logical_path) orelse
                    return error.MissingKeyring;
                try seen_paths.put(logical_path, {});
                try keyrings.append(allocator, .{ .bytes = material.bytes });
            }
        }
        if (keyrings.items.len == 0) return error.MissingKeyring;
        return .{
            .keyrings = try keyrings.toOwnedSlice(allocator),
            .declared_keyrings = repository.signed_by,
            .verifier_limits = self.verifier_limits,
            .allocator = allocator,
        };
    }

    fn findKeyring(self: *const Snapshot, logical_path: []const u8) ?KeyringMaterial {
        for (self.keyring_materials) |material| {
            if (std.mem.eql(u8, material.logical_path, logical_path)) return material;
        }
        return null;
    }
};

pub const RuntimeTrust = struct {
    keyrings: []openpgp.Keyring,
    declared_keyrings: []const []const u8,
    verifier_limits: openpgp.Limits,
    allocator: std.mem.Allocator,

    pub fn authentication(
        self: *const RuntimeTrust,
        verification_time: i64,
    ) repository_refresh.AuthenticationInput {
        return .{ .in_release = .{
            .keyrings = .{ .many = self.keyrings },
            .accepted_primary_fingerprints = &.{},
            .verification_time = verification_time,
            .verifier_limits = self.verifier_limits,
        } };
    }

    pub fn deinit(self: *RuntimeTrust) void {
        self.allocator.free(self.keyrings);
        self.* = undefined;
    }
};

pub const ManifestInput = struct {
    native_architecture: []const u8,
    foreign_architectures: []const []const u8,
    sources: []const SourceRecord,
    configuration_id: [64]u8,
    repository_ids: []const [64]u8,
    repository_policies: []const RepositoryPolicyRecord = &.{},
    keyrings: []const KeyringRecord,
    global_trust_compatibility: bool,
    exclusions: []const Exclusion,
};

pub const ValidationError = error{
    UnsupportedSchema,
    DocumentTooLarge,
    DigestMismatch,
    NonCanonicalDocument,
    InvalidPath,
    InvalidArchitecture,
    InvalidIdentity,
    InvalidDigest,
    DuplicateSource,
    DuplicateKeyring,
    DuplicateRepository,
    DuplicateSourcePolicy,
    DuplicateExclusion,
    MissingFingerprint,
    DuplicateFingerprint,
};

pub const ImportError = error{
    InvalidRootPath,
    TooManySources,
    SourceMaterialTooLarge,
    SourceDigestMismatch,
    TooManyKeyrings,
    KeyringMaterialTooLarge,
    KeyringDigestMismatch,
    KeyringFingerprintMismatch,
    TooManyKeyringPackets,
    TooManyKeyringKeys,
    TooManyExclusions,
    UnsafeDirectoryEntry,
    SymlinkedSource,
    SourceNotRegular,
    UnsafeSourcePath,
    MalformedSource,
    MissingKeyring,
    SymlinkedKeyring,
    KeyringNotRegular,
    UnsafeKeyringPath,
    MalformedKeyring,
    UnsupportedKeyringArmor,
    UnsupportedKeyMaterial,
    UnsupportedKeySize,
    NoSupportedPrimaryKeys,
    MalformedArchitectureState,
    NativeArchitectureUnavailable,
    ArchitectureProcessFailed,
    ArchitectureProcessOutputInvalid,
};

const Architecture = struct {
    native: []const u8,
    foreign: []const []const u8,
};

const KeyCandidate = struct {
    logical_path: []const u8,
    use: KeyringUse,
    optional: bool,
};

pub fn snapshot(
    allocator: std.mem.Allocator,
    request: Request,
) !Snapshot {
    if (!validRootPath(request.root_path)) return error.InvalidRootPath;
    if (request.dependencies.filesystem.host_root !=
        std.mem.eql(u8, request.root_path, "/"))
        return error.InvalidRootPath;
    for (request.source_policies, 0..) |policy, index| {
        if (!validLogicalPath(policy.logical_path) or
            !repository_refresh.validExpiryPolicy(policy.freshness))
            return error.InvalidRootPath;
        for (request.source_policies[0..index]) |prior| {
            if (std.mem.eql(u8, prior.logical_path, policy.logical_path))
                return error.DuplicateSourcePolicy;
        }
    }

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const architecture = try discoverArchitecture(owned, allocator, request);
    const source_materials = try discoverSources(owned, allocator, request);

    const documents = try allocator.alloc(repository_policy.SourceDocument, source_materials.len);
    defer allocator.free(documents);
    for (source_materials, 0..) |material, index| documents[index] = .{
        .bytes = material.bytes,
        .format = material.format,
        .policy = .{ .freshness = sourceFreshness(
            request.source_policies,
            material.logical_path,
        ) },
    };
    var repository_limits = request.limits.repository;
    repository_limits.source = request.limits.source;
    const normalized = try repository_policy.normalizeBinaryRefresh(
        allocator,
        documents,
        architecture.native,
        repository_limits,
    );
    var configuration = switch (normalized) {
        .diagnostic => return error.MalformedSource,
        .configuration => |value| value,
    };
    errdefer configuration.deinit();

    var exclusions: std.ArrayList(Exclusion) = .empty;
    defer {
        for (exclusions.items) |exclusion| allocator.free(exclusion.logical_path);
        exclusions.deinit(allocator);
    }
    try discoverExclusions(allocator, request, &exclusions);

    var candidates: std.ArrayList(KeyCandidate) = .empty;
    defer {
        for (candidates.items) |candidate| allocator.free(candidate.logical_path);
        candidates.deinit(allocator);
    }
    var candidate_indices = std.StringHashMap(usize).init(allocator);
    defer candidate_indices.deinit();
    var global_trust = false;
    for (configuration.repositories) |repository| {
        if (repository.signed_by.len == 0) {
            global_trust = true;
        } else for (repository.signed_by) |logical_path| {
            if (!validLogicalPath(logical_path)) return error.UnsafeKeyringPath;
            try addKeyCandidate(
                allocator,
                &candidates,
                &candidate_indices,
                request.limits.max_keyrings,
                logical_path,
                .declared,
                false,
            );
        }
    }
    if (global_trust) {
        try addKeyCandidate(
            allocator,
            &candidates,
            &candidate_indices,
            request.limits.max_keyrings,
            global_keyring_path,
            .global,
            true,
        );
        try discoverGlobalKeyringCandidates(
            allocator,
            request,
            &candidates,
            &candidate_indices,
            &exclusions,
        );
    }
    if (exclusions.items.len > request.limits.max_exclusions) return error.TooManyExclusions;
    std.mem.sort(KeyCandidate, candidates.items, {}, lessKeyCandidate);
    std.mem.sort(Exclusion, exclusions.items, {}, lessExclusion);

    var keyring_materials: std.ArrayList(KeyringMaterial) = .empty;
    defer keyring_materials.deinit(allocator);
    var total_keyring_bytes: usize = 0;
    var inspection_totals: openpgp.KeyringInspectionTotals = .{};
    for (candidates.items) |candidate| {
        const bytes = request.dependencies.filesystem.readFile(
            allocator,
            candidate.logical_path,
            request.limits.keyring.max_keyring_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => {
                if (candidate.optional) continue;
                return error.MissingKeyring;
            },
            error.Symlink => return error.SymlinkedKeyring,
            error.NotRegular => return error.KeyringNotRegular,
            error.UnsafePath => return error.UnsafeKeyringPath,
            else => return err,
        };
        defer allocator.free(bytes);
        total_keyring_bytes = std.math.add(
            usize,
            total_keyring_bytes,
            bytes.len,
        ) catch return error.KeyringMaterialTooLarge;
        if (total_keyring_bytes > request.limits.max_keyring_material_bytes)
            return error.KeyringMaterialTooLarge;
        var inspected = openpgp.inspectKeyringWithTotals(
            allocator,
            bytes,
            request.limits.keyring,
            &inspection_totals,
        ) catch |err| switch (err) {
            error.KeyringTooLarge => return error.KeyringMaterialTooLarge,
            error.TooManyPackets => return error.TooManyKeyringPackets,
            error.TooManyKeys => return error.TooManyKeyringKeys,
            error.UnsupportedKeyringArmor => return error.UnsupportedKeyringArmor,
            error.UnsupportedKeyMaterial => return error.UnsupportedKeyMaterial,
            error.UnsupportedKeySize => return error.UnsupportedKeySize,
            error.NoSupportedPrimaryKeys => return error.NoSupportedPrimaryKeys,
            error.MalformedKeyring => return error.MalformedKeyring,
            else => return err,
        };
        defer inspected.deinit(allocator);
        try keyring_materials.append(allocator, .{
            .logical_path = try owned.dupe(u8, candidate.logical_path),
            .bytes = try owned.dupe(u8, bytes),
            .sha256 = sha256(bytes),
            .primary_fingerprints = try owned.dupe([20]u8, inspected.primary_fingerprints),
            .use = candidate.use,
        });
    }
    if (global_trust) {
        var found_global = false;
        for (keyring_materials.items) |material| {
            if (material.use == .global or material.use == .declared_and_global) {
                found_global = true;
                break;
            }
        }
        if (!found_global) return error.MissingKeyring;
    }

    const source_records = try allocator.alloc(SourceRecord, source_materials.len);
    defer allocator.free(source_records);
    for (source_materials, 0..) |material, index| source_records[index] = .{
        .logical_path = material.logical_path,
        .sha256 = material.sha256,
        .format = material.format,
        .freshness = documents[index].policy.freshness,
    };
    const repository_ids = try allocator.alloc([64]u8, configuration.repositories.len);
    defer allocator.free(repository_ids);
    for (configuration.repositories, 0..) |repository, index|
        repository_ids[index] = repository.id.bytes;
    const repository_policies = try allocator.alloc(
        RepositoryPolicyRecord,
        configuration.repositories.len,
    );
    defer allocator.free(repository_policies);
    for (configuration.repositories, 0..) |repository, index| {
        repository_policies[index] = .{
            .repository_id = repository.id.bytes,
            .freshness = repository.freshness,
        };
    }
    const keyring_records = try allocator.alloc(KeyringRecord, keyring_materials.items.len);
    defer allocator.free(keyring_records);
    for (keyring_materials.items, 0..) |material, index| keyring_records[index] = .{
        .logical_path = material.logical_path,
        .sha256 = material.sha256,
        .primary_fingerprints = material.primary_fingerprints,
        .use = material.use,
    };

    var manifest = try createManifest(allocator, .{
        .native_architecture = architecture.native,
        .foreign_architectures = architecture.foreign,
        .sources = source_records,
        .configuration_id = configuration.identity.bytes,
        .repository_ids = repository_ids,
        .repository_policies = repository_policies,
        .keyrings = keyring_records,
        .global_trust_compatibility = global_trust,
        .exclusions = exclusions.items,
    });
    errdefer manifest.deinit();

    return .{
        .configuration = configuration,
        .manifest = manifest,
        .source_materials = source_materials,
        .keyring_materials = try owned.dupe(KeyringMaterial, keyring_materials.items),
        .verifier_limits = request.limits.keyring,
        .arena = arena,
        .backing_allocator = allocator,
    };
}

/// Re-opens only the source and keyring files named by a recorded manifest.
/// Every leaf is no-follow through the supplied root-scoped filesystem, and
/// every byte digest and normalized repository policy is revalidated.
pub fn loadRecordedSnapshot(
    allocator: std.mem.Allocator,
    request: RecordedRequest,
) !Snapshot {
    if (!validRootPath(request.root_path) or
        request.dependencies.filesystem.host_root !=
            std.mem.eql(u8, request.root_path, "/"))
        return error.InvalidRootPath;
    try validateSerializableManifest(request.manifest);

    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const architecture = try discoverArchitecture(owned, allocator, .{
        .root_path = request.root_path,
        .architecture_override = request.manifest.native_architecture,
        .limits = request.limits,
        .dependencies = request.dependencies,
    });
    if (!std.mem.eql(
        u8,
        architecture.native,
        request.manifest.native_architecture,
    )) return error.InvalidArchitecture;

    const source_materials = try owned.alloc(SourceMaterial, request.manifest.sources.len);
    var total_source_bytes: usize = 0;
    for (request.manifest.sources, 0..) |record, index| {
        const bytes = request.dependencies.filesystem.readFile(
            allocator,
            record.logical_path,
            request.limits.source.max_input_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => return error.MalformedSource,
            error.Symlink => return error.SymlinkedSource,
            error.NotRegular => return error.SourceNotRegular,
            error.UnsafePath => return error.UnsafeSourcePath,
            else => return err,
        };
        defer allocator.free(bytes);
        total_source_bytes = std.math.add(
            usize,
            total_source_bytes,
            bytes.len,
        ) catch return error.SourceMaterialTooLarge;
        if (total_source_bytes > request.limits.max_source_material_bytes)
            return error.SourceMaterialTooLarge;
        if (!std.mem.eql(u8, &sha256(bytes), &record.sha256))
            return error.SourceDigestMismatch;
        source_materials[index] = .{
            .logical_path = try owned.dupe(u8, record.logical_path),
            .bytes = try owned.dupe(u8, bytes),
            .sha256 = record.sha256,
            .format = record.format,
        };
    }

    const documents = try allocator.alloc(
        repository_policy.SourceDocument,
        source_materials.len,
    );
    defer allocator.free(documents);
    for (source_materials, request.manifest.sources, 0..) |material, record, index| {
        documents[index] = .{
            .bytes = material.bytes,
            .format = material.format,
            .policy = .{ .freshness = record.freshness },
        };
    }
    var repository_limits = request.limits.repository;
    repository_limits.source = request.limits.source;
    const normalized = try repository_policy.normalizeBinaryRefresh(
        allocator,
        documents,
        request.manifest.native_architecture,
        repository_limits,
    );
    var configuration = switch (normalized) {
        .diagnostic => return error.MalformedSource,
        .configuration => |value| value,
    };
    errdefer configuration.deinit();
    if (!std.mem.eql(
        u8,
        configuration.identity.slice(),
        &request.manifest.configuration_id,
    ) or configuration.repositories.len != request.manifest.repository_policies.len)
        return error.DigestMismatch;
    for (configuration.repositories, request.manifest.repository_policies) |repository, policy| {
        if (!std.mem.eql(u8, repository.id.slice(), &policy.repository_id) or
            !repository_refresh.expiryPoliciesEqual(
                repository.freshness,
                policy.freshness,
            ))
            return error.DigestMismatch;
    }

    const keyring_materials = try owned.alloc(
        KeyringMaterial,
        request.manifest.keyrings.len,
    );
    var total_keyring_bytes: usize = 0;
    var inspection_totals: openpgp.KeyringInspectionTotals = .{};
    for (request.manifest.keyrings, 0..) |record, index| {
        const bytes = request.dependencies.filesystem.readFile(
            allocator,
            record.logical_path,
            request.limits.keyring.max_keyring_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => return error.MissingKeyring,
            error.Symlink => return error.SymlinkedKeyring,
            error.NotRegular => return error.KeyringNotRegular,
            error.UnsafePath => return error.UnsafeKeyringPath,
            else => return err,
        };
        defer allocator.free(bytes);
        total_keyring_bytes = std.math.add(
            usize,
            total_keyring_bytes,
            bytes.len,
        ) catch return error.KeyringMaterialTooLarge;
        if (total_keyring_bytes > request.limits.max_keyring_material_bytes)
            return error.KeyringMaterialTooLarge;
        if (!std.mem.eql(u8, &sha256(bytes), &record.sha256))
            return error.KeyringDigestMismatch;
        var inspected = openpgp.inspectKeyringWithTotals(
            allocator,
            bytes,
            request.limits.keyring,
            &inspection_totals,
        ) catch |err| switch (err) {
            error.KeyringTooLarge => return error.KeyringMaterialTooLarge,
            error.TooManyPackets => return error.TooManyKeyringPackets,
            error.TooManyKeys => return error.TooManyKeyringKeys,
            error.UnsupportedKeyringArmor => return error.UnsupportedKeyringArmor,
            error.UnsupportedKeyMaterial => return error.UnsupportedKeyMaterial,
            error.UnsupportedKeySize => return error.UnsupportedKeySize,
            error.NoSupportedPrimaryKeys => return error.NoSupportedPrimaryKeys,
            error.MalformedKeyring => return error.MalformedKeyring,
            else => return err,
        };
        defer inspected.deinit(allocator);
        if (!equalFingerprints(
            inspected.primary_fingerprints,
            record.primary_fingerprints,
        )) return error.KeyringFingerprintMismatch;
        keyring_materials[index] = .{
            .logical_path = try owned.dupe(u8, record.logical_path),
            .bytes = try owned.dupe(u8, bytes),
            .sha256 = record.sha256,
            .primary_fingerprints = try owned.dupe(
                [20]u8,
                record.primary_fingerprints,
            ),
            .use = record.use,
        };
    }

    var manifest = try createManifest(allocator, .{
        .native_architecture = request.manifest.native_architecture,
        .foreign_architectures = request.manifest.foreign_architectures,
        .sources = request.manifest.sources,
        .configuration_id = request.manifest.configuration_id,
        .repository_ids = request.manifest.repository_ids,
        .repository_policies = request.manifest.repository_policies,
        .keyrings = request.manifest.keyrings,
        .global_trust_compatibility = request.manifest.global_trust_compatibility,
        .exclusions = request.manifest.exclusions,
    });
    errdefer manifest.deinit();
    if (!std.mem.eql(
        u8,
        &manifest.manifest.digest_sha256,
        &request.manifest.digest_sha256,
    )) return error.DigestMismatch;

    return .{
        .configuration = configuration,
        .manifest = manifest,
        .source_materials = source_materials,
        .keyring_materials = keyring_materials,
        .verifier_limits = request.limits.keyring,
        .arena = arena,
        .backing_allocator = allocator,
    };
}

fn discoverSources(
    owned: std.mem.Allocator,
    allocator: std.mem.Allocator,
    request: Request,
) ![]SourceMaterial {
    var materials: std.ArrayList(SourceMaterial) = .empty;
    defer materials.deinit(allocator);
    var total_bytes: usize = 0;

    try appendSourceIfPresent(
        owned,
        allocator,
        request,
        &materials,
        &total_bytes,
        sources_list_path,
        .legacy,
    );
    var listing = request.dependencies.filesystem.listDirectory(
        allocator,
        sources_directory_path,
        request.limits.max_directory_entries,
    ) catch |err| switch (err) {
        error.FileNotFound => return owned.dupe(SourceMaterial, materials.items),
        error.Symlink => return error.SymlinkedSource,
        error.NotRegular => return error.SourceNotRegular,
        error.UnsafePath => return error.UnsafeSourcePath,
        else => return err,
    };
    defer listing.deinit();
    std.mem.sort(DirectoryEntry, listing.entries, {}, lessDirectoryEntry);
    for (listing.entries) |entry| {
        if (!safeLeaf(entry.name)) return error.UnsafeDirectoryEntry;
        if (!validAptFragmentFilename(entry.name)) continue;
        const format: ?source.Format = if (std.mem.endsWith(u8, entry.name, ".sources"))
            .deb822
        else if (std.mem.endsWith(u8, entry.name, ".list"))
            .legacy
        else
            null;
        if (format == null) continue;
        switch (entry.kind) {
            .regular => {},
            .symlink => return error.SymlinkedSource,
            else => return error.SourceNotRegular,
        }

        const path = try joinLogical(allocator, sources_directory_path, entry.name);
        defer allocator.free(path);
        try appendSourceIfPresent(
            owned,
            allocator,
            request,
            &materials,
            &total_bytes,
            path,
            format.?,
        );
    }
    if (materials.items.len > request.limits.max_sources) return error.TooManySources;
    std.mem.sort(SourceMaterial, materials.items, {}, lessSourceMaterial);
    return owned.dupe(SourceMaterial, materials.items);
}

fn sourceFreshness(
    policies: []const SourcePolicy,
    logical_path: []const u8,
) repository_refresh.ExpiryPolicy {
    for (policies) |policy| {
        if (std.mem.eql(u8, policy.logical_path, logical_path))
            return policy.freshness;
    }
    return .require_valid_until;
}

fn appendSourceIfPresent(
    owned: std.mem.Allocator,
    allocator: std.mem.Allocator,
    request: Request,
    materials: *std.ArrayList(SourceMaterial),
    total_bytes: *usize,
    logical_path: []const u8,
    format: source.Format,
) !void {
    if (materials.items.len >= request.limits.max_sources) return error.TooManySources;
    const bytes = request.dependencies.filesystem.readFile(
        allocator,
        logical_path,
        request.limits.source.max_input_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        error.Symlink => return error.SymlinkedSource,
        error.NotRegular => return error.SourceNotRegular,
        error.UnsafePath => return error.UnsafeSourcePath,
        else => return err,
    };
    defer allocator.free(bytes);
    total_bytes.* = std.math.add(usize, total_bytes.*, bytes.len) catch
        return error.SourceMaterialTooLarge;
    if (total_bytes.* > request.limits.max_source_material_bytes)
        return error.SourceMaterialTooLarge;
    const parsed = try source.parse(allocator, bytes, format, request.limits.source);
    switch (parsed) {
        .diagnostic => return error.MalformedSource,
        .sources => |value| {
            var parsed_sources = value;
            parsed_sources.deinit();
        },
    }
    try materials.append(allocator, .{
        .logical_path = try owned.dupe(u8, logical_path),
        .bytes = try owned.dupe(u8, bytes),
        .sha256 = sha256(bytes),
        .format = format,
    });
}

fn discoverExclusions(
    allocator: std.mem.Allocator,
    request: Request,
    exclusions: *std.ArrayList(Exclusion),
) !void {
    try appendDirectoryExclusions(
        allocator,
        request,
        exclusions,
        sources_directory_path,
        .source,
    );
}

const DirectoryPurpose = enum { source, keyring };

fn appendDirectoryExclusions(
    allocator: std.mem.Allocator,
    request: Request,
    exclusions: *std.ArrayList(Exclusion),
    logical_directory: []const u8,
    purpose: DirectoryPurpose,
) !void {
    var listing = request.dependencies.filesystem.listDirectory(
        allocator,
        logical_directory,
        request.limits.max_directory_entries,
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        error.Symlink => return if (purpose == .source)
            error.SymlinkedSource
        else
            error.SymlinkedKeyring,
        error.NotRegular => return if (purpose == .source)
            error.SourceNotRegular
        else
            error.KeyringNotRegular,
        error.UnsafePath => return if (purpose == .source)
            error.UnsafeSourcePath
        else
            error.UnsafeKeyringPath,
        else => return err,
    };
    defer listing.deinit();
    std.mem.sort(DirectoryEntry, listing.entries, {}, lessDirectoryEntry);
    for (listing.entries) |entry| {
        if (!safeLeaf(entry.name)) return error.UnsafeDirectoryEntry;
        const apt_filename = purpose != .source or validAptFragmentFilename(entry.name);
        const eligible = switch (purpose) {
            .source => apt_filename and
                (std.mem.endsWith(u8, entry.name, ".list") or
                    std.mem.endsWith(u8, entry.name, ".sources")),
            .keyring => std.mem.endsWith(u8, entry.name, ".gpg") or
                std.mem.endsWith(u8, entry.name, ".asc"),
        };
        if (eligible) {
            switch (entry.kind) {
                .regular => continue,
                .symlink => return if (purpose == .source)
                    error.SymlinkedSource
                else
                    error.SymlinkedKeyring,
                else => return if (purpose == .source)
                    error.SourceNotRegular
                else
                    error.KeyringNotRegular,
            }
        }
        if (exclusions.items.len >= request.limits.max_exclusions)
            return error.TooManyExclusions;
        try exclusions.append(allocator, .{
            .logical_path = try joinLogical(allocator, logical_directory, entry.name),
            .reason = if (!apt_filename)
                .unsupported_name
            else switch (entry.kind) {
                .regular => .unsupported_name,
                .directory => .directory,
                .symlink => .symlink,
                .other => .special,
            },
        });
    }
}

fn discoverGlobalKeyringCandidates(
    allocator: std.mem.Allocator,
    request: Request,
    candidates: *std.ArrayList(KeyCandidate),
    candidate_indices: *std.StringHashMap(usize),
    exclusions: *std.ArrayList(Exclusion),
) !void {
    var listing = request.dependencies.filesystem.listDirectory(
        allocator,
        global_keyring_directory_path,
        request.limits.max_directory_entries,
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        error.Symlink => return error.SymlinkedKeyring,
        error.NotRegular => return error.KeyringNotRegular,
        error.UnsafePath => return error.UnsafeKeyringPath,
        else => return err,
    };
    defer listing.deinit();
    std.mem.sort(DirectoryEntry, listing.entries, {}, lessDirectoryEntry);
    for (listing.entries) |entry| {
        if (!safeLeaf(entry.name)) return error.UnsafeDirectoryEntry;
        const eligible = std.mem.endsWith(u8, entry.name, ".gpg") or
            std.mem.endsWith(u8, entry.name, ".asc");
        if (eligible) {
            switch (entry.kind) {
                .regular => {},
                .symlink => return error.SymlinkedKeyring,
                else => return error.KeyringNotRegular,
            }
            const path = try joinLogical(
                allocator,
                global_keyring_directory_path,
                entry.name,
            );
            defer allocator.free(path);
            try addKeyCandidate(
                allocator,
                candidates,
                candidate_indices,
                request.limits.max_keyrings,
                path,
                .global,
                false,
            );
        } else {
            if (exclusions.items.len >= request.limits.max_exclusions)
                return error.TooManyExclusions;
            try exclusions.append(allocator, .{
                .logical_path = try joinLogical(
                    allocator,
                    global_keyring_directory_path,
                    entry.name,
                ),
                .reason = switch (entry.kind) {
                    .regular => .unsupported_name,
                    .directory => .directory,
                    .symlink => .symlink,
                    .other => .special,
                },
            });
        }
    }
}

fn addKeyCandidate(
    allocator: std.mem.Allocator,
    candidates: *std.ArrayList(KeyCandidate),
    candidate_indices: *std.StringHashMap(usize),
    maximum: usize,
    path: []const u8,
    usage: KeyringUse,
    optional: bool,
) !void {
    if (candidate_indices.get(path)) |index| {
        const candidate = &candidates.items[index];
        candidate.use = mergeUse(candidate.use, usage);
        candidate.optional = candidate.optional and optional;
        return;
    }
    if (candidates.items.len >= maximum) return error.TooManyKeyrings;
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    try candidates.append(allocator, .{
        .logical_path = owned_path,
        .use = usage,
        .optional = optional,
    });
    errdefer _ = candidates.pop();
    try candidate_indices.put(owned_path, candidates.items.len - 1);
}

fn mergeUse(left: KeyringUse, right: KeyringUse) KeyringUse {
    if (left == right) return left;
    return .declared_and_global;
}

fn discoverArchitecture(
    owned: std.mem.Allocator,
    allocator: std.mem.Allocator,
    request: Request,
) !Architecture {
    var native: ?[]const u8 = null;
    if (request.architecture_override) |value| {
        if (!validArchitecture(value)) return error.InvalidArchitecture;
        native = try owned.dupe(u8, value);
    } else {
        const status_bytes = request.dependencies.filesystem.readFile(
            allocator,
            status_path,
            request.limits.max_status_bytes,
        ) catch |err| switch (err) {
            error.FileNotFound => null,
            error.Symlink, error.NotRegular, error.UnsafePath => return error.MalformedArchitectureState,
            else => return err,
        };
        if (status_bytes) |bytes| {
            defer allocator.free(bytes);
            const parsed = try dpkg_status.parseBorrowed(allocator, bytes, .{});
            var database = switch (parsed) {
                .diagnostic => return error.MalformedArchitectureState,
                .database => |value| value,
            };
            defer database.deinit();
            for (database.packages) |package| {
                if (!std.mem.eql(u8, package.name.value, "dpkg") or
                    !package.status.isFullyInstalled()) continue;
                if (native != null and
                    !std.mem.eql(u8, native.?, package.architecture.value))
                    return error.MalformedArchitectureState;
                native = try owned.dupe(u8, package.architecture.value);
            }
        }
        if (native == null and std.mem.eql(u8, request.root_path, "/")) {
            const process = request.dependencies.process orelse
                return error.NativeArchitectureUnavailable;
            const argv = [_][]const u8{ "/usr/bin/dpkg", "--print-architecture" };
            var output = try process.run(allocator, &argv, &.{});
            defer output.deinit();
            if (output.exit_code != 0) return error.ArchitectureProcessFailed;
            const value = std.mem.trim(u8, output.stdout, " \t\r\n");
            if (!validArchitecture(value) or std.mem.indexOfAny(u8, value, "\r\n") != null)
                return error.ArchitectureProcessOutputInvalid;
            native = try owned.dupe(u8, value);
        }
    }
    const native_value = native orelse return error.NativeArchitectureUnavailable;

    var foreign: std.ArrayList([]const u8) = .empty;
    defer foreign.deinit(allocator);
    const architecture_bytes = request.dependencies.filesystem.readFile(
        allocator,
        foreign_architectures_path,
        request.limits.max_architecture_state_bytes,
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        error.Symlink, error.NotRegular, error.UnsafePath => return error.MalformedArchitectureState,
        else => return err,
    };
    if (architecture_bytes) |bytes| {
        defer allocator.free(bytes);
        var lines = std.mem.splitScalar(u8, bytes, '\n');
        while (lines.next()) |raw| {
            const value = std.mem.trim(u8, raw, " \t\r");
            if (value.len == 0) continue;
            if (!validArchitecture(value)) return error.MalformedArchitectureState;
            if (std.mem.eql(u8, value, native_value)) continue;
            var duplicate = false;
            for (foreign.items) |existing| {
                if (std.mem.eql(u8, existing, value)) {
                    duplicate = true;
                    break;
                }
            }
            if (!duplicate) try foreign.append(allocator, try owned.dupe(u8, value));
        }
    }
    std.mem.sort([]const u8, foreign.items, {}, lessString);
    return .{
        .native = native_value,
        .foreign = try owned.dupe([]const u8, foreign.items),
    };
}

pub fn createManifest(
    allocator: std.mem.Allocator,
    input: ManifestInput,
) (std.mem.Allocator.Error || ValidationError)!OwnedManifest {
    if (!validArchitecture(input.native_architecture)) return error.InvalidArchitecture;
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const foreign = try owned.alloc([]const u8, input.foreign_architectures.len);
    for (input.foreign_architectures, 0..) |architecture, index| {
        if (!validArchitecture(architecture) or
            std.mem.eql(u8, architecture, input.native_architecture))
            return error.InvalidArchitecture;
        foreign[index] = try owned.dupe(u8, architecture);
    }
    std.mem.sort([]const u8, foreign, {}, lessString);
    for (foreign, 0..) |architecture, index| {
        if (index != 0 and std.mem.eql(u8, architecture, foreign[index - 1]))
            return error.InvalidArchitecture;
    }

    const sources = try owned.alloc(SourceRecord, input.sources.len);
    for (input.sources, 0..) |record, index| {
        if (!validLogicalPath(record.logical_path) or
            !repository_refresh.validExpiryPolicy(record.freshness))
            return error.InvalidPath;
        sources[index] = record;
        sources[index].logical_path = try owned.dupe(u8, record.logical_path);
    }
    std.mem.sort(SourceRecord, sources, {}, lessSourceRecord);
    for (sources, 0..) |record, index| {
        if (index != 0 and std.mem.eql(u8, record.logical_path, sources[index - 1].logical_path))
            return error.DuplicateSource;
    }

    if (!validLowerHex(&input.configuration_id)) return error.InvalidIdentity;
    const repository_ids = try owned.dupe([64]u8, input.repository_ids);
    std.mem.sort([64]u8, repository_ids, {}, lessId);
    for (repository_ids, 0..) |id, index| {
        if (!validLowerHex(&id)) return error.InvalidIdentity;
        if (index != 0 and std.mem.eql(u8, &id, &repository_ids[index - 1]))
            return error.DuplicateRepository;
    }
    const repository_policies = try owned.alloc(
        RepositoryPolicyRecord,
        repository_ids.len,
    );
    if (input.repository_policies.len == 0) {
        for (repository_ids, 0..) |id, index| repository_policies[index] = .{
            .repository_id = id,
            .freshness = .require_valid_until,
        };
    } else {
        if (input.repository_policies.len != repository_ids.len)
            return error.InvalidIdentity;
        @memcpy(repository_policies, input.repository_policies);
        std.mem.sort(
            RepositoryPolicyRecord,
            repository_policies,
            {},
            lessRepositoryPolicy,
        );
        for (repository_policies, repository_ids) |policy, id| {
            if (!std.mem.eql(u8, &policy.repository_id, &id) or
                !repository_refresh.validExpiryPolicy(policy.freshness))
                return error.InvalidIdentity;
        }
    }

    const keyrings = try owned.alloc(KeyringRecord, input.keyrings.len);
    for (input.keyrings, 0..) |record, index| {
        if (!validLogicalPath(record.logical_path)) return error.InvalidPath;
        if (record.primary_fingerprints.len == 0) return error.MissingFingerprint;
        const fingerprints = try owned.dupe([20]u8, record.primary_fingerprints);
        std.mem.sort([20]u8, fingerprints, {}, lessFingerprint);
        for (fingerprints, 0..) |fingerprint, fingerprint_index| {
            if (fingerprint_index != 0 and std.mem.eql(
                u8,
                &fingerprint,
                &fingerprints[fingerprint_index - 1],
            )) return error.DuplicateFingerprint;
        }
        keyrings[index] = record;
        keyrings[index].logical_path = try owned.dupe(u8, record.logical_path);
        keyrings[index].primary_fingerprints = fingerprints;
    }
    std.mem.sort(KeyringRecord, keyrings, {}, lessKeyringRecord);
    for (keyrings, 0..) |record, index| {
        if (index != 0 and std.mem.eql(u8, record.logical_path, keyrings[index - 1].logical_path))
            return error.DuplicateKeyring;
    }

    const exclusions = try owned.alloc(Exclusion, input.exclusions.len);
    for (input.exclusions, 0..) |exclusion, index| {
        if (!validLogicalPath(exclusion.logical_path)) return error.InvalidPath;
        exclusions[index] = .{
            .logical_path = try owned.dupe(u8, exclusion.logical_path),
            .reason = exclusion.reason,
        };
    }
    std.mem.sort(Exclusion, exclusions, {}, lessExclusion);
    for (exclusions, 0..) |exclusion, index| {
        if (index != 0 and
            std.mem.eql(u8, exclusion.logical_path, exclusions[index - 1].logical_path))
            return error.DuplicateExclusion;
    }

    var manifest: Manifest = .{
        .native_architecture = try owned.dupe(u8, input.native_architecture),
        .foreign_architectures = foreign,
        .sources = sources,
        .configuration_id = input.configuration_id,
        .repository_ids = repository_ids,
        .repository_policies = repository_policies,
        .keyrings = keyrings,
        .global_trust_compatibility = input.global_trust_compatibility,
        .exclusions = exclusions,
        .digest_sha256 = undefined,
    };
    manifest.digest_sha256 = digestPayload(manifest);
    return .{ .manifest = manifest, .arena = arena, .backing_allocator = allocator };
}

const FreshnessMode = enum {
    require_valid_until,
    allow_missing_valid_until_with_max_age_seconds,
};

const WireFreshness = struct {
    mode: FreshnessMode,
    maximum_release_age_seconds: ?u64,
};

const WireSource = struct {
    logical_path: []const u8,
    sha256: []const u8,
    format: source.Format,
    freshness: WireFreshness,
};

const WireRepositoryPolicy = struct {
    repository_id: []const u8,
    freshness: WireFreshness,
};

const WireKeyring = struct {
    logical_path: []const u8,
    sha256: []const u8,
    primary_fingerprints: []const []const u8,
    use: KeyringUse,
};

const WireExclusion = struct {
    logical_path: []const u8,
    reason: ExclusionReason,
};

const WireManifest = struct {
    schema: []const u8,
    version: u32,
    native_architecture: []const u8,
    foreign_architectures: []const []const u8,
    sources: []const WireSource,
    configuration_id: []const u8,
    repository_ids: []const []const u8,
    repository_policies: []const WireRepositoryPolicy,
    keyrings: []const WireKeyring,
    global_trust_compatibility: bool,
    exclusions: []const WireExclusion,
    digest_sha256: []const u8,
};

pub fn decodeManifest(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    maximum_bytes: usize,
) !OwnedManifest {
    if (bytes.len > maximum_bytes or bytes.len > maximum_document_bytes)
        return error.DocumentTooLarge;
    var parsed = try std.json.parseFromSlice(WireManifest, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
    });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.schema, schema_id) or
        parsed.value.version != schema_version)
        return error.UnsupportedSchema;

    const sources = try allocator.alloc(SourceRecord, parsed.value.sources.len);
    defer allocator.free(sources);
    for (parsed.value.sources, 0..) |record, index| sources[index] = .{
        .logical_path = record.logical_path,
        .sha256 = try parseHex(32, record.sha256),
        .format = record.format,
        .freshness = try parseFreshness(record.freshness),
    };
    const repository_ids = try allocator.alloc([64]u8, parsed.value.repository_ids.len);
    defer allocator.free(repository_ids);
    for (parsed.value.repository_ids, 0..) |id, index|
        repository_ids[index] = try parseId(id);
    const repository_policies = try allocator.alloc(
        RepositoryPolicyRecord,
        parsed.value.repository_policies.len,
    );
    defer allocator.free(repository_policies);
    for (parsed.value.repository_policies, 0..) |policy, index| {
        repository_policies[index] = .{
            .repository_id = try parseId(policy.repository_id),
            .freshness = try parseFreshness(policy.freshness),
        };
    }
    const keyrings = try allocator.alloc(KeyringRecord, parsed.value.keyrings.len);
    var keyrings_initialized: usize = 0;
    defer {
        for (keyrings[0..keyrings_initialized]) |record|
            allocator.free(record.primary_fingerprints);
        allocator.free(keyrings);
    }
    for (parsed.value.keyrings, 0..) |record, index| {
        const fingerprints = try allocator.alloc([20]u8, record.primary_fingerprints.len);
        errdefer allocator.free(fingerprints);
        for (record.primary_fingerprints, 0..) |fingerprint, fingerprint_index|
            fingerprints[fingerprint_index] = try parseHex(20, fingerprint);
        keyrings[index] = .{
            .logical_path = record.logical_path,
            .sha256 = try parseHex(32, record.sha256),
            .primary_fingerprints = fingerprints,
            .use = record.use,
        };
        keyrings_initialized += 1;
    }
    const exclusions = try allocator.alloc(Exclusion, parsed.value.exclusions.len);
    defer allocator.free(exclusions);
    for (parsed.value.exclusions, 0..) |exclusion, index| exclusions[index] = .{
        .logical_path = exclusion.logical_path,
        .reason = exclusion.reason,
    };

    var result = try createManifest(allocator, .{
        .native_architecture = parsed.value.native_architecture,
        .foreign_architectures = parsed.value.foreign_architectures,
        .sources = sources,
        .configuration_id = try parseId(parsed.value.configuration_id),
        .repository_ids = repository_ids,
        .repository_policies = repository_policies,
        .keyrings = keyrings,
        .global_trust_compatibility = parsed.value.global_trust_compatibility,
        .exclusions = exclusions,
    });
    errdefer result.deinit();
    const expected = try parseHex(32, parsed.value.digest_sha256);
    if (!std.mem.eql(u8, &expected, &result.manifest.digest_sha256))
        return error.DigestMismatch;
    const canonical = try result.manifest.canonicalJson(allocator);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, canonical, bytes)) return error.NonCanonicalDocument;
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

    pub fn read(
        self: Store,
        allocator: std.mem.Allocator,
        maximum_bytes: usize,
    ) !OwnedManifest {
        var file = try self.dir.openFile(self.io, self.name, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        var reader = file.reader(self.io, &.{});
        const bytes = try reader.interface.allocRemaining(
            allocator,
            .limited(maximum_bytes),
        );
        defer allocator.free(bytes);
        return decodeManifest(allocator, bytes, maximum_bytes);
    }

    pub fn writeAtomic(
        self: Store,
        allocator: std.mem.Allocator,
        manifest: Manifest,
    ) !void {
        const bytes = try manifest.canonicalJson(allocator);
        defer allocator.free(bytes);
        if (bytes.len > maximum_document_bytes) return error.DocumentTooLarge;
        const stage = ".apt-config-snapshot.new";
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

/// Production logical-root adapter. The selected root and every traversed
/// parent are opened without following symlinks; leaf reads are resolve-beneath
/// and no-follow.
pub const ProductionFileSystem = struct {
    io: std.Io,
    root: std.Io.Dir,
    host_root: bool,

    pub fn init(io: std.Io, root_path: []const u8) !ProductionFileSystem {
        if (!validRootPath(root_path)) return error.InvalidRootPath;
        return .{
            .io = io,
            .root = try openAbsoluteRoot(io, root_path),
            .host_root = std.mem.eql(u8, root_path, "/"),
        };
    }

    pub fn deinit(self: *ProductionFileSystem) void {
        self.root.close(self.io);
        self.* = undefined;
    }

    pub fn interface(self: *ProductionFileSystem) FileSystem {
        return .{
            .context = self,
            .host_root = self.host_root,
            .readFileFn = readFile,
            .listDirectoryFn = listDirectory,
        };
    }

    fn readFile(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        logical_path: []const u8,
        maximum: usize,
    ) ![]u8 {
        const self: *ProductionFileSystem = @ptrCast(@alignCast(context));
        if (!validLogicalPath(logical_path)) return error.UnsafePath;
        const parent_path = std.fs.path.dirname(logical_path) orelse return error.UnsafePath;
        const leaf = std.fs.path.basename(logical_path);
        var parent = openLogicalDirectory(self, parent_path) catch |err|
            return mapDirectoryOpenError(err);
        defer parent.close(self.io);
        const kind = try statEntryKind(self.io, parent, leaf);
        switch (kind) {
            .regular => {},
            .symlink => return error.Symlink,
            else => return error.NotRegular,
        }
        var file = parent.openFile(self.io, leaf, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
            .resolve_beneath = true,
        }) catch |err| switch (err) {
            error.FileNotFound => return error.FileNotFound,
            error.SymLinkLoop => return error.Symlink,
            else => return err,
        };
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.kind != .file) return error.NotRegular;
        var reader_buffer: [8192]u8 = undefined;
        var reader = file.reader(self.io, &reader_buffer);
        const probe_limit = std.math.add(usize, maximum, 1) catch maximum;
        const bytes = try reader.interface.allocRemaining(
            allocator,
            .limited(probe_limit),
        );
        if (bytes.len > maximum) {
            allocator.free(bytes);
            return error.StreamTooLong;
        }
        return bytes;
    }

    fn listDirectory(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        logical_path: []const u8,
        maximum_entries: usize,
    ) !DirectoryListing {
        const self: *ProductionFileSystem = @ptrCast(@alignCast(context));
        if (!validLogicalPath(logical_path)) return error.UnsafePath;
        const parent_path = std.fs.path.dirname(logical_path) orelse return error.UnsafePath;
        const leaf = std.fs.path.basename(logical_path);
        var parent = openLogicalDirectory(self, parent_path) catch |err|
            return mapDirectoryOpenError(err);
        defer parent.close(self.io);
        const kind = try statEntryKind(self.io, parent, leaf);
        switch (kind) {
            .directory => {},
            .symlink => return error.Symlink,
            else => return error.NotRegular,
        }
        var directory = parent.openDir(self.io, leaf, .{
            .iterate = true,
            .follow_symlinks = false,
        }) catch |err| switch (err) {
            error.FileNotFound => return error.FileNotFound,
            error.SymLinkLoop => return error.Symlink,
            else => return err,
        };
        defer directory.close(self.io);
        var entries: std.ArrayList(DirectoryEntry) = .empty;
        errdefer {
            for (entries.items) |entry| allocator.free(entry.name);
            entries.deinit(allocator);
        }
        var iterator = directory.iterate();
        while (try iterator.next(self.io)) |entry| {
            if (entries.items.len >= maximum_entries)
                return error.DirectoryLimitExceeded;
            try entries.append(allocator, .{
                .name = try allocator.dupe(u8, entry.name),
                .kind = switch (entry.kind) {
                    .file => .regular,
                    .directory => .directory,
                    .sym_link => .symlink,
                    else => .other,
                },
            });
        }
        return .{
            .entries = try entries.toOwnedSlice(allocator),
            .allocator = allocator,
        };
    }

    fn openLogicalDirectory(
        self: *ProductionFileSystem,
        logical_path: []const u8,
    ) !std.Io.Dir {
        if (!validLogicalDirectoryPath(logical_path)) return error.UnsafePath;
        var current = try self.root.openDir(self.io, ".", .{
            .iterate = true,
            .follow_symlinks = false,
        });
        errdefer current.close(self.io);
        if (std.mem.eql(u8, logical_path, "/")) return current;
        var components = std.mem.splitScalar(u8, logical_path[1..], '/');
        while (components.next()) |component| {
            const next = try current.openDir(self.io, component, .{
                .iterate = true,
                .follow_symlinks = false,
            });
            current.close(self.io);
            current = next;
        }
        return current;
    }

    fn statEntryKind(io: std.Io, directory: std.Io.Dir, leaf: []const u8) !EntryKind {
        var entry = directory.openFile(io, leaf, .{
            .mode = .read_only,
            .allow_directory = true,
            .path_only = true,
            .follow_symlinks = false,
            .resolve_beneath = true,
        }) catch |err| switch (err) {
            error.FileNotFound => return error.FileNotFound,
            error.SymLinkLoop => return .symlink,
            else => return err,
        };
        defer entry.close(io);
        const stat = try entry.stat(io);
        return switch (stat.kind) {
            .file => .regular,
            .directory => .directory,
            .sym_link => .symlink,
            else => .other,
        };
    }

    fn mapDirectoryOpenError(err: anyerror) anyerror {
        return switch (err) {
            error.FileNotFound => error.FileNotFound,
            error.SymLinkLoop, error.NotDir => error.UnsafePath,
            else => err,
        };
    }
};

pub const SystemProcessRunner = struct {
    io: std.Io,
    stdout_limit: usize = 256,
    stderr_limit: usize = 4096,

    pub fn interface(self: *SystemProcessRunner) ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        argv: []const []const u8,
        environment: []const EnvironmentEntry,
    ) !ProcessOutput {
        const self: *SystemProcessRunner = @ptrCast(@alignCast(context));
        var environ = std.process.Environ.Map.init(allocator);
        defer environ.deinit();
        for (environment) |entry| try environ.put(entry.key, entry.value);
        const result = try std.process.run(allocator, self.io, .{
            .argv = argv,
            .environ_map = &environ,
            .stdout_limit = .limited(self.stdout_limit),
            .stderr_limit = .limited(self.stderr_limit),
            .timeout = .{ .duration = .{
                .raw = .fromSeconds(10),
                .clock = .awake,
            } },
        });
        const exit_code: u8 = switch (result.term) {
            .exited => |code| code,
            else => 255,
        };
        return .{
            .stdout = result.stdout,
            .stderr = result.stderr,
            .exit_code = exit_code,
            .allocator = allocator,
        };
    }
};

fn openAbsoluteRoot(io: std.Io, path: []const u8) !std.Io.Dir {
    var current = try std.Io.Dir.openDirAbsolute(io, "/", .{
        .iterate = true,
        .follow_symlinks = false,
    });
    errdefer current.close(io);
    if (std.mem.eql(u8, path, "/")) return current;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        const next = try current.openDir(io, component, .{
            .iterate = true,
            .follow_symlinks = false,
        });
        current.close(io);
        current = next;
    }
    return current;
}

fn digestPayload(manifest: Manifest) [32]u8 {
    var buffer: [1024]u8 = undefined;
    var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha256) = .init(&buffer);
    writePayload(manifest, &sink.writer) catch unreachable;
    sink.writer.flush() catch unreachable;
    return sink.hasher.finalResult();
}

fn writeDocument(manifest: Manifest, writer: *std.Io.Writer) !void {
    try writePayload(manifest, writer);
    writer.undo(1);
    try writer.writeAll(",\"digest_sha256\":");
    try writeHexString(writer, &manifest.digest_sha256);
    try writer.writeByte('}');
}

fn writePayload(manifest: Manifest, writer: *std.Io.Writer) !void {
    try writer.writeAll("{\"schema\":");
    try writeJsonString(writer, schema_id);
    try writer.print(",\"version\":{},\"native_architecture\":", .{schema_version});
    try writeJsonString(writer, manifest.native_architecture);
    try writer.writeAll(",\"foreign_architectures\":[");
    for (manifest.foreign_architectures, 0..) |architecture, index| {
        if (index != 0) try writer.writeByte(',');
        try writeJsonString(writer, architecture);
    }
    try writer.writeAll("],\"sources\":[");
    for (manifest.sources, 0..) |record, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"logical_path\":");
        try writeJsonString(writer, record.logical_path);
        try writer.writeAll(",\"sha256\":");
        try writeHexString(writer, &record.sha256);
        try writer.writeAll(",\"format\":");
        try writeJsonString(writer, @tagName(record.format));
        try writer.writeAll(",\"freshness\":");
        try writeFreshness(writer, record.freshness);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"configuration_id\":");
    try writeJsonString(writer, &manifest.configuration_id);
    try writer.writeAll(",\"repository_ids\":[");
    for (manifest.repository_ids, 0..) |id, index| {
        if (index != 0) try writer.writeByte(',');
        try writeJsonString(writer, &id);
    }
    try writer.writeAll("],\"repository_policies\":[");
    for (manifest.repository_policies, 0..) |policy, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"repository_id\":");
        try writeJsonString(writer, &policy.repository_id);
        try writer.writeAll(",\"freshness\":");
        try writeFreshness(writer, policy.freshness);
        try writer.writeByte('}');
    }
    try writer.writeAll("],\"keyrings\":[");
    for (manifest.keyrings, 0..) |record, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"logical_path\":");
        try writeJsonString(writer, record.logical_path);
        try writer.writeAll(",\"sha256\":");
        try writeHexString(writer, &record.sha256);
        try writer.writeAll(",\"primary_fingerprints\":[");
        for (record.primary_fingerprints, 0..) |fingerprint, fingerprint_index| {
            if (fingerprint_index != 0) try writer.writeByte(',');
            try writeHexString(writer, &fingerprint);
        }
        try writer.writeAll("],\"use\":");
        try writeJsonString(writer, @tagName(record.use));
        try writer.writeByte('}');
    }
    try writer.print(
        "],\"global_trust_compatibility\":{},\"exclusions\":[",
        .{manifest.global_trust_compatibility},
    );
    for (manifest.exclusions, 0..) |exclusion, index| {
        if (index != 0) try writer.writeByte(',');
        try writer.writeAll("{\"logical_path\":");
        try writeJsonString(writer, exclusion.logical_path);
        try writer.writeAll(",\"reason\":");
        try writeJsonString(writer, @tagName(exclusion.reason));
        try writer.writeByte('}');
    }
    try writer.writeAll("]}");
}

fn writeFreshness(
    writer: *std.Io.Writer,
    freshness: repository_refresh.ExpiryPolicy,
) !void {
    try writer.writeAll("{\"mode\":");
    try writeJsonString(writer, @tagName(freshness));
    try writer.writeAll(",\"maximum_release_age_seconds\":");
    if (repository_refresh.expiryPolicyMaxAge(freshness)) |seconds|
        try writer.print("{d}", .{seconds})
    else
        try writer.writeAll("null");
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

fn parseFreshness(
    wire: WireFreshness,
) ValidationError!repository_refresh.ExpiryPolicy {
    const policy: repository_refresh.ExpiryPolicy = switch (wire.mode) {
        .require_valid_until => blk: {
            if (wire.maximum_release_age_seconds != null)
                return error.InvalidIdentity;
            break :blk .require_valid_until;
        },
        .allow_missing_valid_until_with_max_age_seconds => .{
            .allow_missing_valid_until_with_max_age_seconds = wire.maximum_release_age_seconds orelse return error.InvalidIdentity,
        },
    };
    if (!repository_refresh.validExpiryPolicy(policy))
        return error.InvalidIdentity;
    return policy;
}

fn validLowerHex(value: []const u8) bool {
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
            return false;
    }
    return true;
}

fn validRootPath(path: []const u8) bool {
    return absolute_path.root(path);
}

fn validLogicalPath(path: []const u8) bool {
    return absolute_path.nonRoot(path);
}

fn validLogicalDirectoryPath(path: []const u8) bool {
    return absolute_path.logical(path);
}

fn safeLeaf(name: []const u8) bool {
    if (!std.unicode.utf8ValidateSlice(name) or
        name.len == 0 or
        std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, "..") or
        std.mem.indexOfScalar(u8, name, '/') != null or
        std.mem.indexOfScalar(u8, name, '\\') != null)
        return false;
    for (name) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    return true;
}

fn validAptFragmentFilename(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or
            byte == '_' or
            byte == '-' or
            byte == '.'))
            return false;
    }
    return true;
}

fn validArchitecture(value: []const u8) bool {
    if (value.len == 0 or value.len > 64) return false;
    for (value) |byte| {
        if (!(std.ascii.isAlphanumeric(byte) or byte == '-')) return false;
    }
    return true;
}

fn joinLogical(
    allocator: std.mem.Allocator,
    directory: []const u8,
    leaf: []const u8,
) ![]u8 {
    if (!validLogicalPath(directory) or !safeLeaf(leaf)) return error.UnsafeDirectoryEntry;
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ directory, leaf });
}

fn sha256(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn lessDirectoryEntry(_: void, left: DirectoryEntry, right: DirectoryEntry) bool {
    return std.mem.order(u8, left.name, right.name) == .lt;
}

fn lessSourceMaterial(_: void, left: SourceMaterial, right: SourceMaterial) bool {
    return std.mem.order(u8, left.logical_path, right.logical_path) == .lt;
}

fn lessSourceRecord(_: void, left: SourceRecord, right: SourceRecord) bool {
    return std.mem.order(u8, left.logical_path, right.logical_path) == .lt;
}

fn lessKeyCandidate(_: void, left: KeyCandidate, right: KeyCandidate) bool {
    return std.mem.order(u8, left.logical_path, right.logical_path) == .lt;
}

fn lessKeyringRecord(_: void, left: KeyringRecord, right: KeyringRecord) bool {
    return std.mem.order(u8, left.logical_path, right.logical_path) == .lt;
}

fn lessExclusion(_: void, left: Exclusion, right: Exclusion) bool {
    const path_order = std.mem.order(u8, left.logical_path, right.logical_path);
    if (path_order != .eq) return path_order == .lt;
    return std.mem.order(u8, @tagName(left.reason), @tagName(right.reason)) == .lt;
}

fn lessString(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.order(u8, left, right) == .lt;
}

fn lessId(_: void, left: [64]u8, right: [64]u8) bool {
    return std.mem.order(u8, &left, &right) == .lt;
}

fn lessRepositoryPolicy(
    _: void,
    left: RepositoryPolicyRecord,
    right: RepositoryPolicyRecord,
) bool {
    return std.mem.order(
        u8,
        &left.repository_id,
        &right.repository_id,
    ) == .lt;
}

fn lessFingerprint(_: void, left: [20]u8, right: [20]u8) bool {
    return std.mem.order(u8, &left, &right) == .lt;
}

fn equalFingerprints(left: []const [20]u8, right: []const [20]u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!std.mem.eql(u8, &a, &b)) return false;
    }
    return true;
}

fn equalStrings(left: []const []const u8, right: []const []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!std.mem.eql(u8, a, b)) return false;
    }
    return true;
}

const test_fixture = @import("fixtures/openpgp.zig");

fn testRootPath(
    allocator: std.mem.Allocator,
    directory: std.Io.Dir,
) ![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try directory.realPath(std.testing.io, &buffer);
    return std.fmt.allocPrint(allocator, "{s}/root", .{buffer[0..length]});
}

fn stageSignedRoot(directory: std.Io.Dir, reverse_order: bool) !void {
    try directory.createDirPath(std.testing.io, "root/etc/apt/sources.list.d");
    try directory.createDirPath(std.testing.io, "root/usr/share/keyrings");
    try directory.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "Package: dpkg\n" ++
            "Status: install ok installed\n" ++
            "Architecture: amd64\n" ++
            "Version: 1.0\n\n",
    });
    try directory.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/arch",
        .data = "arm64\namd64\narm64\n",
    });
    try directory.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/keyrings/vendor.gpg",
        .data = &test_fixture.keyring,
    });
    const legacy =
        "deb [signed-by=/usr/share/keyrings/vendor.gpg] " ++
        "https://a.invalid/debian stable main\n";
    const deb822 =
        "Types: deb\n" ++
        "URIs: https://b.invalid/debian\n" ++
        "Suites: stable\n" ++
        "Components: main\n" ++
        "Signed-By: /usr/share/keyrings/vendor.gpg\n";
    if (reverse_order) {
        try directory.writeFile(std.testing.io, .{
            .sub_path = "root/etc/apt/sources.list.d/z.sources",
            .data = deb822,
        });
        try directory.writeFile(std.testing.io, .{
            .sub_path = "root/etc/apt/sources.list.d/a.list",
            .data = legacy,
        });
    } else {
        try directory.writeFile(std.testing.io, .{
            .sub_path = "root/etc/apt/sources.list.d/a.list",
            .data = legacy,
        });
        try directory.writeFile(std.testing.io, .{
            .sub_path = "root/etc/apt/sources.list.d/z.sources",
            .data = deb822,
        });
    }
    try directory.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/README",
        .data = "ignored",
    });
    try directory.createDirPath(std.testing.io, "root/etc/apt/sources.list.d/disabled");
    try directory.symLink(
        std.testing.io,
        "missing",
        "root/etc/apt/sources.list.d/backup.save",
        .{},
    );
}

test "target_apt_config deterministic alternate-root import preserves logical identities" {
    var first = std.testing.tmpDir(.{});
    defer first.cleanup();
    var second = std.testing.tmpDir(.{});
    defer second.cleanup();
    try stageSignedRoot(first.dir, false);
    try stageSignedRoot(second.dir, true);

    const first_path = try testRootPath(std.testing.allocator, first.dir);
    defer std.testing.allocator.free(first_path);
    const second_path = try testRootPath(std.testing.allocator, second.dir);
    defer std.testing.allocator.free(second_path);
    var first_files = try ProductionFileSystem.init(std.testing.io, first_path);
    defer first_files.deinit();
    var second_files = try ProductionFileSystem.init(std.testing.io, second_path);
    defer second_files.deinit();

    var first_snapshot = try snapshot(std.testing.allocator, .{
        .root_path = first_path,
        .dependencies = .{ .filesystem = first_files.interface() },
    });
    defer first_snapshot.deinit();
    var second_snapshot = try snapshot(std.testing.allocator, .{
        .root_path = second_path,
        .dependencies = .{ .filesystem = second_files.interface() },
    });
    defer second_snapshot.deinit();

    try std.testing.expectEqualStrings(
        "/etc/apt/sources.list.d/a.list",
        first_snapshot.source_materials[0].logical_path,
    );
    try std.testing.expectEqualStrings(
        "/etc/apt/sources.list.d/z.sources",
        first_snapshot.source_materials[1].logical_path,
    );
    try std.testing.expectEqualStrings(
        "/usr/share/keyrings/vendor.gpg",
        first_snapshot.keyring_materials[0].logical_path,
    );
    try std.testing.expectEqualStrings(
        "amd64",
        first_snapshot.manifest.manifest.native_architecture,
    );
    try std.testing.expectEqual(@as(usize, 1), first_snapshot.manifest.manifest.foreign_architectures.len);
    try std.testing.expectEqualStrings(
        "arm64",
        first_snapshot.manifest.manifest.foreign_architectures[0],
    );
    try std.testing.expectEqual(@as(usize, 3), first_snapshot.manifest.manifest.exclusions.len);
    try std.testing.expectEqualStrings(
        "/etc/apt/sources.list.d/README",
        first_snapshot.manifest.manifest.exclusions[0].logical_path,
    );
    try std.testing.expectEqualStrings(
        "/etc/apt/sources.list.d/backup.save",
        first_snapshot.manifest.manifest.exclusions[1].logical_path,
    );
    try std.testing.expectEqual(
        ExclusionReason.unsupported_name,
        first_snapshot.manifest.manifest.exclusions[0].reason,
    );
    try std.testing.expectEqual(
        ExclusionReason.symlink,
        first_snapshot.manifest.manifest.exclusions[1].reason,
    );
    try std.testing.expectEqual(
        ExclusionReason.directory,
        first_snapshot.manifest.manifest.exclusions[2].reason,
    );

    const first_json = try first_snapshot.manifest.manifest.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(first_json);
    const second_json = try second_snapshot.manifest.manifest.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(second_json);
    try std.testing.expectEqualStrings(first_json, second_json);
    try std.testing.expectEqualSlices(
        u8,
        first_snapshot.configuration.identity.slice(),
        second_snapshot.configuration.identity.slice(),
    );

    var trust = try first_snapshot.runtimeTrust(
        std.testing.allocator,
        first_snapshot.configuration.repositories[0],
    );
    defer trust.deinit();
    try std.testing.expectEqualStrings(
        "/usr/share/keyrings/vendor.gpg",
        trust.declared_keyrings[0],
    );
    try std.testing.expect(trust.keyrings[0] == .bytes);
    try std.testing.expectEqualSlices(
        u8,
        &test_fixture.keyring,
        trust.keyrings[0].bytes,
    );
    const authentication = trust.authentication(test_fixture.created + 30);
    const policy = authentication.in_release;
    var verified = try openpgp.verify(std.testing.allocator, .{
        .io = std.testing.io,
        .signed_bytes = &test_fixture.message,
        .signatures = &.{&test_fixture.signature},
        .keyrings = policy.keyrings,
        .policy = .{ .verification_time = policy.verification_time },
    });
    defer verified.deinit(std.testing.allocator);
    try std.testing.expect(verified == .accepted);

    var recorded = try loadRecordedSnapshot(std.testing.allocator, .{
        .root_path = first_path,
        .manifest = first_snapshot.manifest.manifest,
        .dependencies = .{ .filesystem = first_files.interface() },
    });
    defer recorded.deinit();
    try std.testing.expectEqualStrings(
        first_snapshot.configuration.identity.slice(),
        recorded.configuration.identity.slice(),
    );

    try first.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/a.list",
        .data = "deb [signed-by=/usr/share/keyrings/vendor.gpg] https://changed.invalid stable main\n",
    });
    try std.testing.expectError(error.SourceDigestMismatch, loadRecordedSnapshot(
        std.testing.allocator,
        .{
            .root_path = first_path,
            .manifest = first_snapshot.manifest.manifest,
            .dependencies = .{ .filesystem = first_files.interface() },
        },
    ));
}

test "target_apt_config retains source-only evidence but excludes it from binary refresh" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt/sources.list.d");
    try directory.dir.createDirPath(std.testing.io, "root/keyrings");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list",
        .data = "deb-src [signed-by=/missing-active.gpg] https://source.invalid stable main\n" ++
            "# deb-src [signed-by=/missing-disabled.gpg] https://disabled.invalid stable main\n" ++
            "deb [signed-by=/keyrings/binary.gpg] https://binary.invalid stable main\n",
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/source-only.sources",
        .data = "Types: deb-src\n" ++
            "URIs: https://deb822-source.invalid\n" ++
            "Suites: stable\n" ++
            "Components: main\n",
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/keyrings/binary.gpg",
        .data = &test_fixture.keyring,
    });
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var files = try ProductionFileSystem.init(std.testing.io, root_path);
    defer files.deinit();
    var imported = try snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
    });
    defer imported.deinit();

    try std.testing.expectEqual(@as(usize, 2), imported.source_materials.len);
    try std.testing.expectEqual(@as(usize, 2), imported.manifest.manifest.sources.len);
    try std.testing.expectEqual(@as(usize, 1), imported.configuration.repositories.len);
    try std.testing.expectEqualStrings(
        "https://binary.invalid",
        imported.configuration.repositories[0].uri,
    );
    try std.testing.expectEqual(@as(usize, 1), imported.keyring_materials.len);
    try std.testing.expectEqualStrings(
        "/keyrings/binary.gpg",
        imported.keyring_materials[0].logical_path,
    );
}

test "target_apt_config enforces aggregate source material bounds" {
    const primary = "deb-src https://one.invalid stable main\n";
    const secondary = "deb-src https://two.invalid stable main\n";
    const total = primary.len + secondary.len;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt/sources.list.d");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list",
        .data = primary,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/secondary.list",
        .data = secondary,
    });
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var files = try ProductionFileSystem.init(std.testing.io, root_path);
    defer files.deinit();

    var imported = try snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
        .limits = .{ .max_source_material_bytes = total },
    });
    imported.deinit();
    try std.testing.expectError(error.SourceMaterialTooLarge, snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
        .limits = .{ .max_source_material_bytes = total - 1 },
    }));
}

test "target_apt_config enforces aggregate keyring material bounds" {
    const total = test_fixture.keyring.len * 2;
    var single_totals: openpgp.KeyringInspectionTotals = .{};
    var single = try openpgp.inspectKeyringWithTotals(
        std.testing.allocator,
        &test_fixture.keyring,
        .{},
        &single_totals,
    );
    single.deinit(std.testing.allocator);
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt/sources.list.d");
    try directory.dir.createDirPath(std.testing.io, "root/keyrings");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/multiple.sources",
        .data = "Types: deb\n" ++
            "URIs: https://a.invalid\n" ++
            "Suites: stable\n" ++
            "Components: main\n" ++
            "Signed-By: /keyrings/a.gpg /keyrings/b.gpg\n",
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/keyrings/a.gpg",
        .data = &test_fixture.keyring,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/keyrings/b.gpg",
        .data = &test_fixture.keyring,
    });
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var files = try ProductionFileSystem.init(std.testing.io, root_path);
    defer files.deinit();

    var imported = try snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
        .limits = .{
            .max_keyring_material_bytes = total,
            .keyring = .{
                .max_keyring_bytes = total,
                .max_packets = single_totals.packets * 2,
                .max_keys = single_totals.keys * 2,
            },
        },
    });
    var trust = try imported.runtimeTrust(
        std.testing.allocator,
        imported.configuration.repositories[0],
    );
    defer trust.deinit();
    const authentication = trust.authentication(test_fixture.created + 30);
    try std.testing.expectEqual(@as(usize, 2), authentication.in_release.keyrings.many.len);
    try std.testing.expectEqual(
        total,
        authentication.in_release.verifier_limits.max_keyring_bytes,
    );
    try std.testing.expectEqual(
        single_totals.packets * 2,
        authentication.in_release.verifier_limits.max_packets,
    );
    try std.testing.expectEqual(
        single_totals.keys * 2,
        authentication.in_release.verifier_limits.max_keys,
    );
    var verified = try openpgp.verify(std.testing.allocator, .{
        .io = std.testing.io,
        .signed_bytes = &test_fixture.message,
        .signatures = &.{&test_fixture.signature},
        .keyrings = authentication.in_release.keyrings,
        .policy = .{ .verification_time = authentication.in_release.verification_time },
        .limits = authentication.in_release.verifier_limits,
    });
    defer verified.deinit(std.testing.allocator);
    try std.testing.expect(verified == .accepted);
    imported.deinit();
    try std.testing.expectError(error.KeyringMaterialTooLarge, snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
        .limits = .{ .max_keyring_material_bytes = total - 1 },
    }));
    try std.testing.expectError(error.KeyringMaterialTooLarge, snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
        .limits = .{
            .max_keyring_material_bytes = total,
            .keyring = .{ .max_keyring_bytes = total - 1 },
        },
    }));
    try std.testing.expectError(error.TooManyKeyringPackets, snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
        .limits = .{
            .max_keyring_material_bytes = total,
            .keyring = .{ .max_packets = single_totals.packets * 2 - 1 },
        },
    }));
    try std.testing.expectError(error.TooManyKeyringKeys, snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
        .limits = .{
            .max_keyring_material_bytes = total,
            .keyring = .{ .max_keys = single_totals.keys * 2 - 1 },
        },
    }));
}

test "target_apt_config runtime trust deduplicates repeated declared keyrings" {
    var single_totals: openpgp.KeyringInspectionTotals = .{};
    var single = try openpgp.inspectKeyringWithTotals(
        std.testing.allocator,
        &test_fixture.keyring,
        .{},
        &single_totals,
    );
    single.deinit(std.testing.allocator);

    var source_bytes: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer source_bytes.deinit();
    try source_bytes.writer.writeAll(
        "Types: deb\n" ++
            "URIs: https://repeated.invalid\n" ++
            "Suites: stable\n" ++
            "Components: main\n" ++
            "Signed-By:",
    );
    for (0..32) |_| try source_bytes.writer.writeAll(" /keyrings/shared.gpg");
    try source_bytes.writer.writeByte('\n');
    const source_document = try source_bytes.toOwnedSlice();
    defer std.testing.allocator.free(source_document);

    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt/sources.list.d");
    try directory.dir.createDirPath(std.testing.io, "root/keyrings");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/repeated.sources",
        .data = source_document,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/keyrings/shared.gpg",
        .data = &test_fixture.keyring,
    });
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var files = try ProductionFileSystem.init(std.testing.io, root_path);
    defer files.deinit();
    var imported = try snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
        .limits = .{
            .max_keyrings = 1,
            .max_keyring_material_bytes = test_fixture.keyring.len,
            .keyring = .{
                .max_keyring_bytes = test_fixture.keyring.len,
                .max_packets = single_totals.packets,
                .max_keys = single_totals.keys,
            },
        },
    });
    defer imported.deinit();
    const repository = imported.configuration.repositories[0];
    try std.testing.expectEqual(@as(usize, 32), repository.signed_by.len);
    var trust = try imported.runtimeTrust(std.testing.allocator, repository);
    defer trust.deinit();
    try std.testing.expectEqual(@as(usize, 32), trust.declared_keyrings.len);
    try std.testing.expectEqual(@as(usize, 1), trust.keyrings.len);

    const authentication = trust.authentication(test_fixture.created + 30).in_release;
    var verified = try openpgp.verify(std.testing.allocator, .{
        .io = std.testing.io,
        .signed_bytes = &test_fixture.message,
        .signatures = &.{&test_fixture.signature},
        .keyrings = authentication.keyrings,
        .policy = .{ .verification_time = authentication.verification_time },
        .limits = authentication.verifier_limits,
    });
    defer verified.deinit(std.testing.allocator);
    try std.testing.expect(verified == .accepted);
}

test "target_apt_config specific reads do not scan oversized parent directories" {
    var source_bytes: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer source_bytes.deinit();
    try source_bytes.writer.writeAll(
        "Types: deb\n" ++
            "URIs: https://specific.invalid\n" ++
            "Suites: stable\n" ++
            "Components: main\n" ++
            "Signed-By:",
    );
    for (0..8) |index| {
        try source_bytes.writer.print(" /keyrings/key{}.gpg", .{index});
    }
    try source_bytes.writer.writeByte('\n');
    const source_document = try source_bytes.toOwnedSlice();
    defer std.testing.allocator.free(source_document);

    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt/sources.list.d");
    try directory.dir.createDirPath(std.testing.io, "root/keyrings");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/specific.sources",
        .data = source_document,
    });
    for (0..64) |index| {
        const path = try std.fmt.allocPrint(
            std.testing.allocator,
            "root/keyrings/unrelated-{}",
            .{index},
        );
        defer std.testing.allocator.free(path);
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = path,
            .data = "",
        });
    }
    for (0..8) |index| {
        const path = try std.fmt.allocPrint(
            std.testing.allocator,
            "root/keyrings/key{}.gpg",
            .{index},
        );
        defer std.testing.allocator.free(path);
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = path,
            .data = &test_fixture.keyring,
        });
    }
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var files = try ProductionFileSystem.init(std.testing.io, root_path);
    defer files.deinit();
    var imported = try snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
        .limits = .{ .max_directory_entries = 2 },
    });
    defer imported.deinit();
    try std.testing.expectEqual(@as(usize, 8), imported.keyring_materials.len);
}

test "target_apt_config bounds unique keyring candidates while deduplicating repeats" {
    var repeated_root = std.testing.tmpDir(.{});
    defer repeated_root.cleanup();
    try repeated_root.dir.createDirPath(std.testing.io, "root/etc/apt");
    try repeated_root.dir.createDirPath(std.testing.io, "root/keyrings");
    var repeated_source: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer repeated_source.deinit();
    for (0..128) |index| {
        try repeated_source.writer.print(
            "deb [signed-by=/keyrings/shared.gpg] https://repeat{}.invalid stable main\n",
            .{index},
        );
    }
    const repeated_bytes = try repeated_source.toOwnedSlice();
    defer std.testing.allocator.free(repeated_bytes);
    try repeated_root.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list",
        .data = repeated_bytes,
    });
    try repeated_root.dir.writeFile(std.testing.io, .{
        .sub_path = "root/keyrings/shared.gpg",
        .data = &test_fixture.keyring,
    });
    const repeated_path = try testRootPath(std.testing.allocator, repeated_root.dir);
    defer std.testing.allocator.free(repeated_path);
    var repeated_files = try ProductionFileSystem.init(std.testing.io, repeated_path);
    defer repeated_files.deinit();
    var repeated = try snapshot(std.testing.allocator, .{
        .root_path = repeated_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = repeated_files.interface() },
        .limits = .{ .max_keyrings = 1 },
    });
    defer repeated.deinit();
    try std.testing.expectEqual(@as(usize, 1), repeated.keyring_materials.len);

    var unique_root = std.testing.tmpDir(.{});
    defer unique_root.cleanup();
    try unique_root.dir.createDirPath(std.testing.io, "root/etc/apt");
    var unique_source: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer unique_source.deinit();
    for (0..128) |index| {
        try unique_source.writer.print(
            "deb [signed-by=/keyrings/key{}.gpg] https://unique{}.invalid stable main\n",
            .{ index, index },
        );
    }
    const unique_bytes = try unique_source.toOwnedSlice();
    defer std.testing.allocator.free(unique_bytes);
    try unique_root.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list",
        .data = unique_bytes,
    });
    const unique_path = try testRootPath(std.testing.allocator, unique_root.dir);
    defer std.testing.allocator.free(unique_path);
    var unique_files = try ProductionFileSystem.init(std.testing.io, unique_path);
    defer unique_files.deinit();
    try std.testing.expectError(error.TooManyKeyrings, snapshot(std.testing.allocator, .{
        .root_path = unique_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = unique_files.interface() },
        .limits = .{ .max_keyrings = 64 },
    }));
}

test "target_apt_config applies APT source fragment filename grammar" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt/sources.list.d");
    const valid_source = "deb-src https://source.invalid stable main\n";
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/valid-name_1.list",
        .data = valid_source,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/valid.sources",
        .data = "Types: deb-src\nURIs: https://deb822.invalid\nSuites: stable\nComponents: main\n",
    });
    const invalid_names = [_][]const u8{
        "bad name.list",
        "bad@name.sources",
        "unicodé.list",
    };
    for (invalid_names) |name| {
        const path = try std.fmt.allocPrint(
            std.testing.allocator,
            "root/etc/apt/sources.list.d/{s}",
            .{name},
        );
        defer std.testing.allocator.free(path);
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = path,
            .data = "not a valid source",
        });
    }
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var files = try ProductionFileSystem.init(std.testing.io, root_path);
    defer files.deinit();
    var imported = try snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
    });
    defer imported.deinit();

    try std.testing.expectEqual(@as(usize, 2), imported.source_materials.len);
    try std.testing.expectEqual(@as(usize, 3), imported.manifest.manifest.exclusions.len);
    for (imported.manifest.manifest.exclusions) |exclusion| {
        try std.testing.expectEqual(ExclusionReason.unsupported_name, exclusion.reason);
    }
    try std.testing.expectEqualStrings(
        "/etc/apt/sources.list.d/bad name.list",
        imported.manifest.manifest.exclusions[0].logical_path,
    );
    try std.testing.expectEqualStrings(
        "/etc/apt/sources.list.d/bad@name.sources",
        imported.manifest.manifest.exclusions[1].logical_path,
    );
    try std.testing.expectEqualStrings(
        "/etc/apt/sources.list.d/unicodé.list",
        imported.manifest.manifest.exclusions[2].logical_path,
    );
}

test "target_apt_config production adapter rejects eligible source and keyring symlinks" {
    var source_root = std.testing.tmpDir(.{});
    defer source_root.cleanup();
    try source_root.dir.createDirPath(std.testing.io, "root/etc/apt/sources.list.d");
    try source_root.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list.d/real.list",
        .data = "deb [signed-by=/key.gpg] https://example.invalid stable main\n",
    });
    try source_root.dir.symLink(
        std.testing.io,
        "real.list",
        "root/etc/apt/sources.list.d/linked.list",
        .{},
    );
    const source_path = try testRootPath(std.testing.allocator, source_root.dir);
    defer std.testing.allocator.free(source_path);
    var source_files = try ProductionFileSystem.init(std.testing.io, source_path);
    defer source_files.deinit();
    try std.testing.expectError(error.SymlinkedSource, snapshot(std.testing.allocator, .{
        .root_path = source_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = source_files.interface() },
    }));

    var key_root = std.testing.tmpDir(.{});
    defer key_root.cleanup();
    try key_root.dir.createDirPath(std.testing.io, "root/etc/apt");
    try key_root.dir.createDirPath(std.testing.io, "root/usr/share/keyrings");
    try key_root.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list",
        .data = "deb [signed-by=/usr/share/keyrings/vendor.gpg] https://example.invalid stable main\n",
    });
    try key_root.dir.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/keyrings/real.gpg",
        .data = &test_fixture.keyring,
    });
    try key_root.dir.symLink(
        std.testing.io,
        "real.gpg",
        "root/usr/share/keyrings/vendor.gpg",
        .{},
    );
    const key_path = try testRootPath(std.testing.allocator, key_root.dir);
    defer std.testing.allocator.free(key_path);
    var key_files = try ProductionFileSystem.init(std.testing.io, key_path);
    defer key_files.deinit();
    try std.testing.expectError(error.SymlinkedKeyring, snapshot(std.testing.allocator, .{
        .root_path = key_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = key_files.interface() },
    }));
}

test "target_apt_config global trust compatibility is explicit and uses imported bytes" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt/sources.list.d");
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt/trusted.gpg.d");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list",
        .data = "deb https://example.invalid stable main\n",
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/trusted.gpg.d/archive.gpg",
        .data = &test_fixture.keyring,
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/trusted.gpg.d/README",
        .data = "not a keyring",
    });
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var files = try ProductionFileSystem.init(std.testing.io, root_path);
    defer files.deinit();
    var imported = try snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
    });
    defer imported.deinit();

    try std.testing.expect(imported.manifest.manifest.global_trust_compatibility);
    try std.testing.expectEqual(KeyringUse.global, imported.keyring_materials[0].use);
    try std.testing.expectEqualStrings(
        "/etc/apt/trusted.gpg.d/archive.gpg",
        imported.keyring_materials[0].logical_path,
    );
    var trust = try imported.runtimeTrust(
        std.testing.allocator,
        imported.configuration.repositories[0],
    );
    defer trust.deinit();
    try std.testing.expectEqual(@as(usize, 0), trust.declared_keyrings.len);
    try std.testing.expectEqual(@as(usize, 1), trust.keyrings.len);
    try std.testing.expect(trust.authentication(1) == .in_release);
}

test "target_apt_config rejects malformed unsupported and armored keyrings" {
    const cases = [_]struct { bytes: []const u8, expected: anyerror }{
        .{ .bytes = "not-openpgp", .expected = error.MalformedKeyring },
        .{
            .bytes = "-----BEGIN PGP PUBLIC KEY BLOCK-----\n",
            .expected = error.UnsupportedKeyringArmor,
        },
    };
    for (cases) |case| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try directory.dir.createDirPath(std.testing.io, "root/etc/apt");
        try directory.dir.createDirPath(std.testing.io, "root/keyrings");
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "root/etc/apt/sources.list",
            .data = "deb [signed-by=/keyrings/vendor.gpg] https://example.invalid stable main\n",
        });
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "root/keyrings/vendor.gpg",
            .data = case.bytes,
        });
        const root_path = try testRootPath(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root_path);
        var files = try ProductionFileSystem.init(std.testing.io, root_path);
        defer files.deinit();
        try std.testing.expectError(case.expected, snapshot(std.testing.allocator, .{
            .root_path = root_path,
            .architecture_override = "amd64",
            .dependencies = .{ .filesystem = files.interface() },
        }));
    }

    var unsupported = test_fixture.ed25519_keyring;
    const packet_header_bytes: usize = 2;
    unsupported[packet_header_bytes + 5] = 19;
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt");
    try directory.dir.createDirPath(std.testing.io, "root/keyrings");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list",
        .data = "deb [signed-by=/keyrings/vendor.gpg] https://example.invalid stable main\n",
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/keyrings/vendor.gpg",
        .data = &unsupported,
    });
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var files = try ProductionFileSystem.init(std.testing.io, root_path);
    defer files.deinit();
    try std.testing.expectError(error.UnsupportedKeyMaterial, snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
    }));
}

test "target_apt_config rejects malformed sources and traversing Signed-By paths" {
    const cases = [_]struct { source_bytes: []const u8, expected: anyerror }{
        .{
            .source_bytes = "this is not a source\n",
            .expected = error.MalformedSource,
        },
        .{
            .source_bytes = "deb [signed-by=/../outside.gpg] https://example.invalid stable main\n",
            .expected = error.UnsafeKeyringPath,
        },
        .{
            .source_bytes = "deb [trusted=yes] https://example.invalid stable main\n",
            .expected = error.MalformedSource,
        },
        .{
            .source_bytes = "Types: deb\nURIs: https://example.invalid\n" ++
                "Suites: stable\nComponents: main\nTrusted: yes\n",
            .expected = error.MalformedSource,
        },
    };
    for (cases) |case| {
        var directory = std.testing.tmpDir(.{});
        defer directory.cleanup();
        try directory.dir.createDirPath(std.testing.io, "root/etc/apt");
        try directory.dir.writeFile(std.testing.io, .{
            .sub_path = "root/etc/apt/sources.list",
            .data = case.source_bytes,
        });
        const root_path = try testRootPath(std.testing.allocator, directory.dir);
        defer std.testing.allocator.free(root_path);
        var files = try ProductionFileSystem.init(std.testing.io, root_path);
        defer files.deinit();
        try std.testing.expectError(case.expected, snapshot(std.testing.allocator, .{
            .root_path = root_path,
            .architecture_override = "amd64",
            .dependencies = .{ .filesystem = files.interface() },
        }));
    }
}

test "target_apt_config accepts explicit trusted false without weakening authentication" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/etc/apt");
    try directory.dir.createDirPath(std.testing.io, "root/usr/share/keyrings");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/etc/apt/sources.list",
        .data = "deb [trusted=no signed-by=/usr/share/keyrings/vendor.gpg] " ++
            "https://example.invalid stable main\n",
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/usr/share/keyrings/vendor.gpg",
        .data = &test_fixture.keyring,
    });
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var files = try ProductionFileSystem.init(std.testing.io, root_path);
    defer files.deinit();
    var imported = try snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .architecture_override = "amd64",
        .dependencies = .{ .filesystem = files.interface() },
    });
    defer imported.deinit();
    try std.testing.expectEqual(@as(usize, 1), imported.configuration.repositories.len);
    try std.testing.expectEqual(
        @as(usize, 1),
        imported.configuration.repositories[0].signed_by.len,
    );
}

const MissingFileSystem = struct {
    calls: usize = 0,
    unexpected: bool = false,

    fn interface(self: *MissingFileSystem, host_root: bool) FileSystem {
        return .{
            .context = self,
            .host_root = host_root,
            .readFileFn = readFile,
            .listDirectoryFn = listDirectory,
        };
    }

    fn readFile(
        context: *anyopaque,
        _: std.mem.Allocator,
        path: []const u8,
        _: usize,
    ) ![]u8 {
        const self: *MissingFileSystem = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (!std.mem.eql(u8, path, status_path) and
            !std.mem.eql(u8, path, foreign_architectures_path) and
            !std.mem.eql(u8, path, sources_list_path))
            self.unexpected = true;
        return error.FileNotFound;
    }

    fn listDirectory(
        context: *anyopaque,
        _: std.mem.Allocator,
        path: []const u8,
        _: usize,
    ) !DirectoryListing {
        const self: *MissingFileSystem = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (!std.mem.eql(u8, path, sources_directory_path))
            self.unexpected = true;
        return error.FileNotFound;
    }
};

const ArchitectureProcess = struct {
    calls: usize = 0,
    invalid_invocation: bool = false,

    fn interface(self: *ArchitectureProcess) ProcessRunner {
        return .{ .context = self, .runFn = run };
    }

    fn run(
        context: *anyopaque,
        allocator: std.mem.Allocator,
        argv: []const []const u8,
        environment: []const EnvironmentEntry,
    ) !ProcessOutput {
        const self: *ArchitectureProcess = @ptrCast(@alignCast(context));
        self.calls += 1;
        if (argv.len != 2 or
            !std.mem.eql(u8, argv[0], "/usr/bin/dpkg") or
            !std.mem.eql(u8, argv[1], "--print-architecture") or
            environment.len != 0)
            self.invalid_invocation = true;
        return .{
            .stdout = try allocator.dupe(u8, "arm64\n"),
            .stderr = try allocator.dupe(u8, ""),
            .exit_code = 0,
            .allocator = allocator,
        };
    }
};

test "target_apt_config architecture discovery uses target state and root-only fixed fallback" {
    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    try directory.dir.createDirPath(std.testing.io, "root/var/lib/dpkg");
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/status",
        .data = "Package: dpkg\n" ++
            "Status: install ok installed\n" ++
            "Architecture: amd64\n" ++
            "Version: 1\n\n",
    });
    try directory.dir.writeFile(std.testing.io, .{
        .sub_path = "root/var/lib/dpkg/arch",
        .data = "arm64\namd64\n",
    });
    const root_path = try testRootPath(std.testing.allocator, directory.dir);
    defer std.testing.allocator.free(root_path);
    var production = try ProductionFileSystem.init(std.testing.io, root_path);
    defer production.deinit();
    var imported = try snapshot(std.testing.allocator, .{
        .root_path = root_path,
        .dependencies = .{ .filesystem = production.interface() },
    });
    defer imported.deinit();
    try std.testing.expectEqualStrings("amd64", imported.manifest.manifest.native_architecture);
    try std.testing.expectEqualStrings("arm64", imported.manifest.manifest.foreign_architectures[0]);

    var files: MissingFileSystem = .{};
    var process: ArchitectureProcess = .{};
    var host = try snapshot(std.testing.allocator, .{
        .root_path = "/",
        .dependencies = .{
            .filesystem = files.interface(true),
            .process = process.interface(),
        },
    });
    defer host.deinit();
    try std.testing.expectEqualStrings("arm64", host.manifest.manifest.native_architecture);
    try std.testing.expectEqual(@as(usize, 1), process.calls);
    try std.testing.expect(!process.invalid_invocation);

    var alternate_files: MissingFileSystem = .{};
    var alternate_process: ArchitectureProcess = .{};
    try std.testing.expectError(error.NativeArchitectureUnavailable, snapshot(
        std.testing.allocator,
        .{
            .root_path = "/alternate",
            .dependencies = .{
                .filesystem = alternate_files.interface(false),
                .process = alternate_process.interface(),
            },
        },
    ));
    try std.testing.expectEqual(@as(usize, 0), alternate_process.calls);
}

test "target_apt_config explicit architecture reads no ambient configuration" {
    var files: MissingFileSystem = .{};
    var process: ArchitectureProcess = .{};
    var imported = try snapshot(std.testing.allocator, .{
        .root_path = "/alternate",
        .architecture_override = "amd64",
        .dependencies = .{
            .filesystem = files.interface(false),
            .process = process.interface(),
        },
    });
    defer imported.deinit();
    try std.testing.expectEqual(@as(usize, 4), files.calls);
    try std.testing.expect(!files.unexpected);
    try std.testing.expectEqual(@as(usize, 0), process.calls);

    try std.testing.expectError(error.InvalidRootPath, snapshot(std.testing.allocator, .{
        .root_path = "/",
        .architecture_override = "amd64",
        .dependencies = .{
            .filesystem = files.interface(false),
            .process = process.interface(),
        },
    }));
    try std.testing.expectEqual(@as(usize, 0), process.calls);
}

test "target_apt_config manifest canonical round trip detects tampering and stores atomically" {
    const sources = [_]SourceRecord{
        .{
            .logical_path = "/etc/apt/sources.list.d/z.sources",
            .sha256 = @splat(2),
            .format = .deb822,
        },
        .{
            .logical_path = "/etc/apt/sources.list",
            .sha256 = @splat(1),
            .format = .legacy,
        },
    };
    const keyrings = [_]KeyringRecord{.{
        .logical_path = "/usr/share/keyrings/vendor.gpg",
        .sha256 = @splat(3),
        .primary_fingerprints = &.{@splat(4)},
        .use = .declared,
    }};
    const repositories = [_][64]u8{ @splat('b'), @splat('a') };
    const exclusions = [_]Exclusion{.{
        .logical_path = "/etc/apt/sources.list.d/README",
        .reason = .unsupported_name,
    }};
    var created = try createManifest(std.testing.allocator, .{
        .native_architecture = "amd64",
        .foreign_architectures = &.{"arm64"},
        .sources = &sources,
        .configuration_id = @splat('c'),
        .repository_ids = &repositories,
        .keyrings = &keyrings,
        .global_trust_compatibility = false,
        .exclusions = &exclusions,
    });
    defer created.deinit();
    const canonical = try created.manifest.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);
    var decoded = try decodeManifest(
        std.testing.allocator,
        canonical,
        maximum_document_bytes,
    );
    defer decoded.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &created.manifest.digest_sha256,
        &decoded.manifest.digest_sha256,
    );
    try std.testing.expectEqualStrings(
        "/etc/apt/sources.list",
        decoded.manifest.sources[0].logical_path,
    );

    var tampered = try std.testing.allocator.dupe(u8, canonical);
    defer std.testing.allocator.free(tampered);
    tampered[std.mem.indexOf(u8, tampered, "amd64").?] = 'x';
    try std.testing.expectError(
        error.DigestMismatch,
        decodeManifest(std.testing.allocator, tampered, maximum_document_bytes),
    );

    var directory = std.testing.tmpDir(.{});
    defer directory.cleanup();
    const store = try Store.init(std.testing.io, directory.dir, "apt-snapshot.json");
    try store.writeAtomic(std.testing.allocator, created.manifest);
    var stored = try store.read(std.testing.allocator, maximum_document_bytes);
    defer stored.deinit();
    try std.testing.expectEqualSlices(
        u8,
        &created.manifest.digest_sha256,
        &stored.manifest.digest_sha256,
    );
}

test "target_apt_config logical path grammar is UTF-8 and traversal safe" {
    const valid_sources = [_]SourceRecord{.{
        .logical_path = "/etc/apt/sources.list.d/référence.sources",
        .sha256 = @splat(1),
        .format = .deb822,
    }};
    var valid = try createManifest(std.testing.allocator, .{
        .native_architecture = "amd64",
        .foreign_architectures = &.{},
        .sources = &valid_sources,
        .configuration_id = @splat('a'),
        .repository_ids = &.{},
        .keyrings = &.{},
        .global_trust_compatibility = false,
        .exclusions = &.{},
    });
    defer valid.deinit();
    const canonical = try valid.manifest.canonicalJson(std.testing.allocator);
    defer std.testing.allocator.free(canonical);
    var decoded = try decodeManifest(
        std.testing.allocator,
        canonical,
        maximum_document_bytes,
    );
    defer decoded.deinit();
    try std.testing.expectEqualStrings(
        valid_sources[0].logical_path,
        decoded.manifest.sources[0].logical_path,
    );

    const invalid_paths = [_][]const u8{
        "/",
        "/etc//apt",
        "/etc/./apt",
        "/etc/../apt",
        "/etc/apt/",
        "/etc\\apt",
        "/etc/\x1fapt",
        "/etc/\x7fapt",
        "/etc/\xffapt",
    };
    for (invalid_paths) |path| {
        const sources = [_]SourceRecord{.{
            .logical_path = path,
            .sha256 = @splat(1),
            .format = .legacy,
        }};
        try std.testing.expectError(error.InvalidPath, createManifest(std.testing.allocator, .{
            .native_architecture = "amd64",
            .foreign_architectures = &.{},
            .sources = &sources,
            .configuration_id = @splat('a'),
            .repository_ids = &.{},
            .keyrings = &.{},
            .global_trust_compatibility = false,
            .exclusions = &.{},
        }));
        const direct: Manifest = .{
            .native_architecture = "amd64",
            .foreign_architectures = &.{},
            .sources = &sources,
            .configuration_id = @splat('a'),
            .repository_ids = &.{},
            .keyrings = &.{},
            .global_trust_compatibility = false,
            .exclusions = &.{},
            .digest_sha256 = @splat(0),
        };
        try std.testing.expectError(
            error.InvalidPath,
            direct.canonicalJson(std.testing.allocator),
        );
    }
}
