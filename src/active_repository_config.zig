const std = @import("std");
const root_fs = @import("root_fs.zig");
const root_operation = @import("root_operation.zig");
const target = @import("target_apt_config.zig");
const recovery = @import("transaction_recovery.zig");

pub const schema_id = "https://debz.dev/schema/active-repository-config-v1";
pub const document_name = "active-config-v1.json";
pub const maximum_document_bytes: usize = 32 * 1024;

const Payload = struct {
    schema: []const u8,
    version: u32,
    root_identity_sha256: []const u8,
    root_device: u64,
    root_inode: u64,
    manifest_path: []const u8,
    manifest_sha256: []const u8,
};

const Wire = struct {
    payload: Payload,
    digest_sha256: []const u8,
};

pub fn logicalPath(allocator: std.mem.Allocator, state_path: []const u8) ![]u8 {
    _ = try root_fs.Path.fromAbsolute(state_path);
    return std.fmt.allocPrint(allocator, "{s}/repository/{s}", .{ state_path, document_name });
}

fn manifestPath(allocator: std.mem.Allocator, state_path: []const u8, path: []const u8) !root_fs.Path {
    const parsed = try root_fs.Path.fromAbsolute(path);
    const prefix = try std.fmt.allocPrint(allocator, "{s}/repository/operations/", .{state_path});
    defer allocator.free(prefix);
    const suffix = "/apt-config-snapshot-v1.json";
    if (!std.mem.startsWith(u8, path, prefix) or !std.mem.endsWith(u8, path, suffix) or
        path.len != prefix.len + 64 + suffix.len)
        return error.InvalidActiveManifestPath;
    _ = try parseDigest(path[prefix.len..][0..64]);
    return parsed;
}

fn parseDigest(text: []const u8) ![32]u8 {
    if (text.len != 64) return error.InvalidActiveConfig;
    for (text) |byte| {
        if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f'))
            return error.InvalidActiveConfig;
    }
    var result: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&result, text);
    return result;
}

fn digest(bytes: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &result, .{});
    return result;
}

fn encode(allocator: std.mem.Allocator, payload: Payload) ![]u8 {
    const bytes = try std.json.Stringify.valueAlloc(allocator, payload, .{});
    defer allocator.free(bytes);
    const hex = std.fmt.bytesToHex(digest(bytes), .lower);
    return std.json.Stringify.valueAlloc(allocator, Wire{
        .payload = payload,
        .digest_sha256 = &hex,
    }, .{});
}

fn validateRoot(root: root_fs.Root, root_path: []const u8, payload: Payload) !void {
    const identity = try parseDigest(payload.root_identity_sha256);
    const entry = try root.rootEntry();
    if (!entry.modeled) return error.ActiveRootIdentityUnavailable;
    if (!std.mem.eql(u8, &identity, &recovery.rootIdentity(root_path)) or
        entry.device != payload.root_device or entry.inode != payload.root_inode)
        return error.ForeignActiveRoot;
}

fn requireOwnedEntry(root: root_fs.Root, entry: root_fs.Entry) !void {
    const owner = try root.rootEntry();
    if (!entry.modeled or !entry.isRegularFile() or entry.uid != owner.uid or
        entry.mode & 0o022 != 0 or entry.link_count != 1)
        return error.UnsafeActiveConfigFile;
}

fn pinOwnedFile(root: root_fs.Root, path: root_fs.Path) !root_fs.PinnedRegularFile {
    try requireOwnedEntry(root, try root.entry(path));
    var pin = try root.pinRegularFile(path);
    errdefer pin.close();
    try requireOwnedEntry(root, (try pin.metadata()).entry);
    return pin;
}

fn verifyRecordedFile(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    logical_path: []const u8,
    expected: [32]u8,
    maximum: usize,
) !void {
    const path = try root_fs.Path.fromAbsolute(logical_path);
    var pin = try pinOwnedFile(root, path);
    defer pin.close();
    const observed = try pin.observeStableAlloc(allocator, maximum);
    defer allocator.free(observed.bytes);
    if (!std.mem.eql(u8, &digest(observed.bytes), &expected))
        return error.ActiveConfigurationChanged;
}

fn importMatching(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    root_path: []const u8,
    manifest: target.Manifest,
    architecture_override: ?[]const u8,
) !target.Snapshot {
    if (architecture_override) |architecture| {
        if (!std.mem.eql(u8, architecture, manifest.native_architecture))
            return error.ActiveArchitectureMismatch;
    }
    const policies = try allocator.alloc(target.SourcePolicy, manifest.sources.len);
    defer allocator.free(policies);
    const limits: target.Limits = .{};
    for (manifest.sources, policies) |record, *policy| {
        try verifyRecordedFile(allocator, root, record.logical_path, record.sha256, limits.max_source_material_bytes);
        policy.* = .{ .logical_path = record.logical_path, .freshness = record.freshness };
    }
    for (manifest.keyrings) |record|
        try verifyRecordedFile(allocator, root, record.logical_path, record.sha256, limits.max_keyring_material_bytes);
    var files: target.ProductionFileSystem = .{
        .io = root.io,
        .root = root.dir,
        .host_root = std.mem.eql(u8, root_path, "/"),
    };
    var snapshot = try target.snapshot(allocator, .{
        .root_path = root_path,
        .architecture_override = architecture_override,
        .source_policies = policies,
        .dependencies = .{ .filesystem = files.interface() },
    });
    errdefer snapshot.deinit();
    if (!std.mem.eql(u8, &snapshot.manifest.manifest.digest_sha256, &manifest.digest_sha256))
        return error.ActiveConfigurationChanged;
    return snapshot;
}

/// Called only while the successful repository caller still holds the shared
/// root lock. No active pointer is published from an unverified import.
pub fn publish(
    allocator: std.mem.Allocator,
    attempt: *root_operation.Attempt,
    state_path: []const u8,
    retained_manifest_path: []const u8,
    manifest: target.Manifest,
    observer: ?root_fs.PublishObserver,
) !void {
    if (!attempt.locked()) return error.RootOperationLockLost;
    switch (attempt.record().operation) {
        .repository_bootstrap => |operation| if (operation != .add) return error.InvalidActiveOwner,
        else => return error.InvalidActiveOwner,
    }
    try attempt.coordinator.validateProjection();
    const root = attempt.coordinator.root;
    const root_path = attempt.record().install_root;
    const configuration_root = if (attempt.coordinator.root_projection != null) "/" else root_path;
    var current = try attempt.coordinator.store().read(allocator) orelse {
        const record = attempt.record();
        if (!record.clearable() or
            (record.provenance != .published and record.outcome != .abandoned_before_mutation))
            return error.InvalidActiveOwner;
        // Completed native cleanup can replay after clearing the caller. It
        // may verify the exact prior publication, never create or replace it.
        var prior = try load(allocator, root, configuration_root, state_path, manifest.native_architecture);
        defer prior.deinit();
        const expected = try manifest.canonicalJson(allocator);
        defer allocator.free(expected);
        const retained = try parseDigest(prior.pointer.value.payload.manifest_sha256);
        if (!std.mem.eql(u8, prior.retainedManifestPath(), retained_manifest_path) or
            !std.mem.eql(u8, &retained, &digest(expected)))
            return error.ActiveManifestChanged;
        try attempt.coordinator.validateProjection();
        return;
    };
    defer current.deinit();
    if (!std.mem.eql(u8, &current.record.digest_sha256, &attempt.record().digest_sha256))
        return error.InvalidActiveOwner;
    const path = try manifestPath(allocator, state_path, retained_manifest_path);
    var pinned = try pinOwnedFile(root, path);
    defer pinned.close();
    const observed = try pinned.observeStableAlloc(allocator, target.maximum_document_bytes);
    defer allocator.free(observed.bytes);
    const expected = try manifest.canonicalJson(allocator);
    defer allocator.free(expected);
    if (!std.mem.eql(u8, observed.bytes, expected)) return error.ActiveManifestChanged;
    var imported = try importMatching(allocator, root, root_path, manifest, manifest.native_architecture);
    defer imported.deinit();
    const identity = try root.rootEntry();
    if (!identity.modeled) return error.ActiveRootIdentityUnavailable;
    // Configuration is backend-neutral. Only a genuine projection can name
    // this physical host as `/`; execution/recovery records keep their namespace.
    const root_hex = std.fmt.bytesToHex(recovery.rootIdentity(configuration_root), .lower);
    const manifest_hex = std.fmt.bytesToHex(digest(observed.bytes), .lower);
    const bytes = try encode(allocator, .{
        .schema = schema_id,
        .version = 1,
        .root_identity_sha256 = &root_hex,
        .root_device = identity.device,
        .root_inode = identity.inode,
        .manifest_path = retained_manifest_path,
        .manifest_sha256 = &manifest_hex,
    });
    defer allocator.free(bytes);
    const active_text = try logicalPath(allocator, state_path);
    defer allocator.free(active_text);
    const active = try root_fs.Path.fromAbsolute(active_text);
    try root.createDirectoryPath(active.parent().?, .fromMode(0o700));
    if (try root.entryIfExists(active) != null) {
        var prior = try readPointer(allocator, root, configuration_root, active);
        defer prior.deinit();
        _ = try manifestPath(allocator, state_path, prior.value.payload.manifest_path);
    }
    if (!attempt.locked()) return error.RootOperationLockLost;
    try attempt.coordinator.validateProjection();
    try root.publishFile(active, bytes, .{
        .permissions = .fromMode(0o600),
        .durable = true,
        .observer = observer,
    });
}

pub const Loaded = struct {
    snapshot: target.Snapshot,
    pointer: std.json.Parsed(Wire),

    pub fn deinit(self: *Loaded) void {
        self.snapshot.deinit();
        self.pointer.deinit();
        self.* = undefined;
    }

    pub fn retainedManifestPath(self: *const Loaded) []const u8 {
        return self.pointer.value.payload.manifest_path;
    }
};

fn readPointer(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    root_path: []const u8,
    path: root_fs.Path,
) !std.json.Parsed(Wire) {
    var pin = try pinOwnedFile(root, path);
    defer pin.close();
    const observed = try pin.observeStableAlloc(allocator, maximum_document_bytes);
    defer allocator.free(observed.bytes);
    return decodePointer(allocator, root, root_path, observed.bytes);
}

fn decodePointer(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    root_path: []const u8,
    bytes: []const u8,
) !std.json.Parsed(Wire) {
    var parsed = std.json.parseFromSlice(Wire, allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = false,
        .max_value_len = maximum_document_bytes,
    }) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return error.InvalidActiveConfig,
    };
    errdefer parsed.deinit();
    const payload = parsed.value.payload;
    if (payload.version != 1 or !std.mem.eql(u8, payload.schema, schema_id))
        return error.InvalidActiveConfig;
    _ = try parseDigest(parsed.value.digest_sha256);
    const canonical = try encode(allocator, payload);
    defer allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical)) return error.InvalidActiveConfig;
    try validateRoot(root, root_path, payload);
    return parsed;
}

/// The pointer is configuration evidence, not freshness or execution
/// authority. Consumers must still authenticate Release/index/archive bytes.
pub fn load(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    root_path: []const u8,
    state_path: []const u8,
    architecture_override: ?[]const u8,
) !Loaded {
    const active_text = try logicalPath(allocator, state_path);
    defer allocator.free(active_text);
    const active = try root_fs.Path.fromAbsolute(active_text);
    var pointer_pin = try pinOwnedFile(root, active);
    defer pointer_pin.close();
    const pointer_bytes = try pointer_pin.observeStableAlloc(allocator, maximum_document_bytes);
    defer allocator.free(pointer_bytes.bytes);
    var parsed = try decodePointer(allocator, root, root_path, pointer_bytes.bytes);
    errdefer parsed.deinit();
    const payload = parsed.value.payload;
    const path = try manifestPath(allocator, state_path, payload.manifest_path);
    var manifest_pin = try pinOwnedFile(root, path);
    defer manifest_pin.close();
    const observed = try manifest_pin.observeStableAlloc(allocator, target.maximum_document_bytes);
    defer allocator.free(observed.bytes);
    const expected = try parseDigest(payload.manifest_sha256);
    if (!std.mem.eql(u8, &digest(observed.bytes), &expected)) return error.ActiveManifestChanged;
    var manifest = try target.decodeManifest(allocator, observed.bytes, target.maximum_document_bytes);
    defer manifest.deinit();
    var snapshot = try importMatching(allocator, root, root_path, manifest.manifest, architecture_override);
    errdefer snapshot.deinit();
    _ = try pointer_pin.metadata();
    _ = try manifest_pin.metadata();
    return .{ .snapshot = snapshot, .pointer = parsed };
}
