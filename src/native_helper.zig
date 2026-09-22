//! Trusted helper deployment never creates or replaces its package-owned target.
//! Sources are immutable, content-addressed files in debz's private namespace.
const std = @import("std");
const content_digest = @import("content_digest.zig");
const maintainer_script = @import("maintainer_script.zig");
const root_fs = @import("root_fs.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const directory = "var/lib/debz/native-helper-cache-v1";
pub const bootstrap_directory = "var/lib/debz/native-recovery-v1";
pub const target_path = "usr/bin/dpkg-trigger";
pub const owner_package = "dpkg";
pub const exact_lock_schema = "https://debz.dev/schema/exact-closure-lock-v3";
pub const exact_lock_version: u32 = 3;
pub const legacy_exact_lock_schema = "https://debz.dev/schema/exact-closure-lock-v2";
pub const legacy_exact_lock_version: u32 = 2;
pub const maximum_bytes = 32 * 1024 * 1024;
const cleanup_prepared = "prepared\n";
const cleanup_completed = "completed\n";

pub const Source = struct {
    bytes: []const u8,
    sha256: [32]u8,

    pub fn validate(self: Source) !void {
        if (self.bytes.len == 0 or self.bytes.len > maximum_bytes)
            return error.InvalidNativeHelper;
        var observed: [32]u8 = undefined;
        Sha256.hash(self.bytes, &observed, .{});
        if (!std.mem.eql(u8, &observed, &self.sha256))
            return error.NativeHelperDigestMismatch;
    }
};

pub fn bundled() Source {
    const bytes = @embedFile("debz_native_trigger_helper");
    var sha256: [32]u8 = undefined;
    Sha256.hash(bytes, &sha256, .{});
    return .{ .bytes = bytes, .sha256 = sha256 };
}

pub const Binding = struct {
    source_path: []const u8,
    target_path: []const u8,
    sha256: [64]u8,
    size: u64,

    pub fn eql(self: Binding, other: Binding) bool {
        return self.size == other.size and
            std.mem.eql(u8, self.source_path, other.source_path) and
            std.mem.eql(u8, self.target_path, other.target_path) and
            std.mem.eql(u8, &self.sha256, &other.sha256);
    }

    pub fn validate(self: Binding) !void {
        try self.validateCommon();
        var buffer: [256]u8 = undefined;
        const expected = try std.fmt.bufPrint(&buffer, "{s}/{s}.bin", .{ directory, self.sha256 });
        if (!std.mem.eql(u8, self.source_path, expected)) return error.InvalidNativeHelper;
    }

    pub fn validateBootstrap(self: Binding, attempt_id: [64]u8) !void {
        try self.validateCommon();
        if (!validDigest(attempt_id)) return error.InvalidNativeHelperBootstrap;
        var buffer: [256]u8 = undefined;
        const expected = try std.fmt.bufPrint(
            &buffer,
            "{s}/helper-{s}.bin",
            .{ bootstrap_directory, attempt_id },
        );
        if (!std.mem.eql(u8, self.source_path, expected))
            return error.InvalidNativeHelperBootstrap;
    }

    pub fn validateAny(self: Binding) !void {
        self.validate() catch {
            if (!std.mem.startsWith(u8, self.source_path, bootstrap_directory ++ "/helper-") or
                !std.mem.endsWith(u8, self.source_path, ".bin"))
                return error.InvalidNativeHelper;
            const prefix = bootstrap_directory.len + "/helper-".len;
            const suffix = ".bin".len;
            if (self.source_path.len != prefix + 64 + suffix)
                return error.InvalidNativeHelper;
            const attempt_id: [64]u8 = self.source_path[prefix .. prefix + 64].*;
            try self.validateBootstrap(attempt_id);
        };
    }

    fn validateCommon(self: Binding) !void {
        if (self.size == 0 or self.size > maximum_bytes or
            !std.mem.eql(u8, self.target_path, nativeTarget()))
            return error.InvalidNativeHelper;
        if (!validDigest(self.sha256)) return error.InvalidNativeHelper;
    }

    pub fn matches(self: Binding, source: Source) !void {
        try self.validateAny();
        try source.validate();
        if (self.size != source.bytes.len or
            !std.mem.eql(u8, &self.sha256, &std.fmt.bytesToHex(source.sha256, .lower)))
            return error.NativeHelperDigestMismatch;
    }
};

fn validDigest(value: [64]u8) bool {
    for (value) |byte|
        if ((byte < '0' or byte > '9') and (byte < 'a' or byte > 'f'))
            return false;
    return true;
}

fn nativeTarget() []const u8 {
    return target_path;
}

pub const BootstrapTarget = struct {
    path: []const u8 = target_path,
    sha256: [64]u8,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,

    pub fn validate(self: BootstrapTarget) !void {
        if (!std.mem.eql(u8, self.path, target_path) or
            !validDigest(self.sha256) or self.size == 0 or
            self.size > maximum_bytes or self.mode > 0o7777)
            return error.InvalidNativeHelperBootstrap;
    }
};

pub const BootstrapOwner = struct {
    package: []const u8,
    version: []const u8,
    architecture: []const u8,
    final_state: []const u8,
    artifact: u32,
    archive_sha256: [64]u8 = @splat('0'),
    archive_identity: ?content_digest.JsonIdentity = null,
    archive_size: u64,
    application_sha256: [64]u8,
    program_step: u32,

    pub fn validate(self: BootstrapOwner) !void {
        if (!std.mem.eql(u8, self.package, owner_package) or
            self.version.len == 0 or
            self.architecture.len == 0 or self.final_state.len == 0 or
            !validDigest(self.application_sha256) or self.archive_size == 0)
            return error.InvalidNativeHelperBootstrap;
        if (self.archive_identity) |archive_identity| {
            _ = content_digest.Identity.init(
                archive_identity.value.digests,
                archive_identity.value.primary,
            ) catch return error.InvalidNativeHelperBootstrap;
        } else if (!validDigest(self.archive_sha256)) {
            return error.InvalidNativeHelperBootstrap;
        }
        if (!std.mem.eql(u8, self.final_state, "installed") and
            !std.mem.eql(u8, self.final_state, "triggers_pending") and
            !std.mem.eql(u8, self.final_state, "triggers_awaited"))
            return error.InvalidNativeHelperBootstrap;
    }

    pub fn jsonParse(
        allocator: std.mem.Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) !BootstrapOwner {
        const Wire = struct {
            package: []const u8,
            version: []const u8,
            architecture: []const u8,
            final_state: []const u8,
            artifact: u32,
            archive_sha256: ?[64]u8 = null,
            archive_identity: ?content_digest.JsonIdentity = null,
            archive_size: u64,
            application_sha256: [64]u8,
            program_step: u32,
        };
        const wire = try std.json.innerParse(Wire, allocator, source, options);
        if ((wire.archive_sha256 == null) == (wire.archive_identity == null))
            return error.UnexpectedToken;
        return .{
            .package = wire.package,
            .version = wire.version,
            .architecture = wire.architecture,
            .final_state = wire.final_state,
            .artifact = wire.artifact,
            .archive_sha256 = wire.archive_sha256 orelse @splat('0'),
            .archive_identity = wire.archive_identity,
            .archive_size = wire.archive_size,
            .application_sha256 = wire.application_sha256,
            .program_step = wire.program_step,
        };
    }

    pub fn jsonStringify(self: BootstrapOwner, writer: anytype) !void {
        if (self.archive_identity) |archive_identity| {
            try writer.write(.{
                .package = self.package,
                .version = self.version,
                .architecture = self.architecture,
                .final_state = self.final_state,
                .artifact = self.artifact,
                .archive_identity = archive_identity,
                .archive_size = self.archive_size,
                .application_sha256 = self.application_sha256,
                .program_step = self.program_step,
            });
        } else {
            try writer.write(.{
                .package = self.package,
                .version = self.version,
                .architecture = self.architecture,
                .final_state = self.final_state,
                .artifact = self.artifact,
                .archive_sha256 = self.archive_sha256,
                .archive_size = self.archive_size,
                .application_sha256 = self.application_sha256,
                .program_step = self.program_step,
            });
        }
    }

    pub fn identity(self: BootstrapOwner) ?content_digest.Identity {
        if (self.archive_identity) |archive_identity| return archive_identity.value;
        var digest: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&digest, &self.archive_sha256) catch return null;
        return content_digest.Identity.init(.{ .sha256 = digest }, .sha256) catch null;
    }
};

pub const Bootstrap = struct {
    attempt_id: [64]u8,
    root_identity_sha256: [64]u8,
    root_inode: u64,
    root_uid: u32,
    root_gid: u32,
    plan_sha256: [64]u8,
    authorization_sha256: [64]u8,
    program_sha256: [64]u8,
    exact_lock_schema: []const u8,
    exact_lock_version: u32,
    exact_lock_sha256: [64]u8,
    helper: Binding,
    owner: BootstrapOwner,
    target: BootstrapTarget,

    pub fn eql(self: Bootstrap, other: Bootstrap) bool {
        return std.mem.eql(u8, &self.attempt_id, &other.attempt_id) and
            std.mem.eql(u8, &self.root_identity_sha256, &other.root_identity_sha256) and
            self.root_inode == other.root_inode and self.root_uid == other.root_uid and
            self.root_gid == other.root_gid and
            std.mem.eql(u8, &self.plan_sha256, &other.plan_sha256) and
            std.mem.eql(u8, &self.authorization_sha256, &other.authorization_sha256) and
            std.mem.eql(u8, &self.program_sha256, &other.program_sha256) and
            std.mem.eql(u8, self.exact_lock_schema, other.exact_lock_schema) and
            self.exact_lock_version == other.exact_lock_version and
            std.mem.eql(u8, &self.exact_lock_sha256, &other.exact_lock_sha256) and
            self.helper.eql(other.helper) and
            std.mem.eql(u8, self.owner.package, other.owner.package) and
            std.mem.eql(u8, self.owner.version, other.owner.version) and
            std.mem.eql(u8, self.owner.architecture, other.owner.architecture) and
            std.mem.eql(u8, self.owner.final_state, other.owner.final_state) and
            self.owner.artifact == other.owner.artifact and
            self.owner.identity() != null and other.owner.identity() != null and
            self.owner.identity().?.eql(other.owner.identity().?) and
            self.owner.archive_size == other.owner.archive_size and
            std.mem.eql(u8, &self.owner.application_sha256, &other.owner.application_sha256) and
            self.owner.program_step == other.owner.program_step and
            std.mem.eql(u8, self.target.path, other.target.path) and
            std.mem.eql(u8, &self.target.sha256, &other.target.sha256) and
            self.target.size == other.target.size and self.target.mode == other.target.mode and
            self.target.uid == other.target.uid and self.target.gid == other.target.gid;
    }

    pub fn validate(self: Bootstrap) !void {
        inline for (.{
            self.attempt_id,
            self.root_identity_sha256,
            self.plan_sha256,
            self.authorization_sha256,
            self.program_sha256,
            self.exact_lock_sha256,
        }) |digest| if (!validDigest(digest))
            return error.InvalidNativeHelperBootstrap;
        if (self.root_inode == 0 or self.root_uid != 0 or self.root_gid != 0 or
            !supportedExactLock(self.exact_lock_schema, self.exact_lock_version))
            return error.InvalidNativeHelperBootstrap;
        try self.helper.validateBootstrap(self.attempt_id);
        try self.owner.validate();
        try self.target.validate();
        if (!std.mem.eql(u8, self.helper.target_path, self.target.path))
            return error.InvalidNativeHelperBootstrap;
    }
};

fn supportedExactLock(schema: []const u8, version: u32) bool {
    return (std.mem.eql(u8, schema, exact_lock_schema) and
        version == exact_lock_version) or
        (std.mem.eql(u8, schema, legacy_exact_lock_schema) and
            version == legacy_exact_lock_version);
}

pub fn bootstrapBinding(
    allocator: std.mem.Allocator,
    attempt_id: [64]u8,
    source: Source,
) !Binding {
    try source.validate();
    if (!validDigest(attempt_id)) return error.InvalidNativeHelperBootstrap;
    const path = try std.fmt.allocPrint(
        allocator,
        "{s}/helper-{s}.bin",
        .{ bootstrap_directory, attempt_id },
    );
    const binding: Binding = .{
        .source_path = path,
        .target_path = target_path,
        .sha256 = std.fmt.bytesToHex(source.sha256, .lower),
        .size = source.bytes.len,
    };
    try binding.validateBootstrap(attempt_id);
    return binding;
}

pub fn verifyBootstrapTarget(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    target: BootstrapTarget,
) !void {
    try target.validate();
    const entry = (try root.entryIfExists(try root_fs.Path.init(target.path))) orelse
        return error.NativeHelperTargetMissing;
    if (!entry.modeled or entry.kind != .file or entry.link_count != 1 or
        entry.size != target.size or
        entry.mode != target.mode or entry.uid != target.uid or entry.gid != target.gid)
        return error.NativeHelperTargetDrift;
    const bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(target.path),
        std.math.cast(usize, target.size) orelse return error.InvalidNativeHelperBootstrap,
    );
    defer allocator.free(bytes);
    var observed: [32]u8 = undefined;
    Sha256.hash(bytes, &observed, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(observed, .lower), &target.sha256))
        return error.NativeHelperTargetDrift;
}

pub fn verifyBootstrapPrivateState(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
    source_required: bool,
) !void {
    try bootstrap.validate();
    const root_entry = try root.rootEntry();
    if (!root_entry.modeled or root_entry.inode != bootstrap.root_inode)
        return error.NativeHelperRootDrift;
    const directory_entry = (try root.entryIfExists(
        try root_fs.Path.init(bootstrap_directory),
    )) orelse return error.NativeHelperEvidenceMissing;
    if (!directory_entry.modeled or directory_entry.kind != .directory or
        directory_entry.mode & 0o7777 != 0o700 or
        directory_entry.uid != bootstrap.root_uid or directory_entry.gid != bootstrap.root_gid)
        return error.InvalidNativeHelperBootstrapState;
    const source_entry = try root.entryIfExists(
        try root_fs.Path.init(bootstrap.helper.source_path),
    );
    if (source_entry == null) {
        if (source_required) return error.NativeHelperEvidenceMissing;
        return;
    }
    const entry = source_entry.?;
    if (!entry.modeled or entry.kind != .file or entry.link_count != 1 or
        entry.size != bootstrap.helper.size or
        entry.mode & 0o7777 != 0o500 or entry.uid != bootstrap.root_uid or
        entry.gid != bootstrap.root_gid)
        return error.NativeHelperEvidenceChanged;
    const bytes = try root.readFileAlloc(
        allocator,
        try root_fs.Path.init(bootstrap.helper.source_path),
        maximum_bytes,
    );
    defer allocator.free(bytes);
    var observed: [32]u8 = undefined;
    Sha256.hash(bytes, &observed, .{});
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(observed, .lower), &bootstrap.helper.sha256))
        return error.NativeHelperEvidenceChanged;
}

pub fn stageBootstrap(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
    source: Source,
) !void {
    try bootstrap.validate();
    try bootstrap.helper.matches(source);
    try verifyBootstrapTarget(allocator, root, bootstrap.target);
    try verifyBootstrapPrivateState(allocator, root, bootstrap, false);
    const path = try root_fs.Path.init(bootstrap.helper.source_path);
    if (try root.entryIfExists(path) != null) {
        try verifyBootstrapPrivateState(allocator, root, bootstrap, true);
        return;
    }
    try root.publishFile(path, source.bytes, .{
        .permissions = .fromMode(0o500),
        .overwrite = .fail_if_exists,
        .durable = true,
    });
    try root.applyMetadata(path, .{
        .mode = 0o500,
        .uid = bootstrap.root_uid,
        .gid = bootstrap.root_gid,
    });
    try root.syncRegularFile(path);
    try root.syncDirectory(try root_fs.Path.init(bootstrap_directory));
    try verifyBootstrapPrivateState(allocator, root, bootstrap, true);
}

pub fn cleanupBootstrap(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
) !void {
    try prepareBootstrapCleanup(allocator, root, bootstrap);
    try removeBootstrapSource(allocator, root, bootstrap);
    try completeBootstrapCleanup(allocator, root, bootstrap);
    try finishBootstrapCleanupJournal(allocator, root, bootstrap);
}

const CleanupStage = enum { prepared, completed };

fn cleanupPath(bootstrap: Bootstrap, buffer: []u8) !root_fs.Path {
    return root_fs.Path.init(try std.fmt.bufPrint(
        buffer,
        "{s}.cleanup",
        .{bootstrap.helper.source_path},
    ));
}

fn cleanupStage(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
) !?CleanupStage {
    var path_buffer: [256]u8 = undefined;
    const path = try cleanupPath(bootstrap, &path_buffer);
    const entry = root.entryIfExists(path) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    } orelse return null;
    if (!entry.modeled or entry.kind != .file or entry.link_count != 1 or
        entry.mode & 0o7777 != 0o600 or entry.uid != 0 or entry.gid != 0 or
        (entry.size != cleanup_prepared.len and entry.size != cleanup_completed.len))
        return error.NativeHelperEvidenceChanged;
    const bytes = try root.readFileAlloc(allocator, path, cleanup_completed.len);
    defer allocator.free(bytes);
    if (std.mem.eql(u8, bytes, cleanup_prepared)) return .prepared;
    if (std.mem.eql(u8, bytes, cleanup_completed)) return .completed;
    return error.NativeHelperEvidenceChanged;
}

fn bootstrapSourcePresent(root: root_fs.Root, bootstrap: Bootstrap) !bool {
    return (root.entryIfExists(
        try root_fs.Path.init(bootstrap.helper.source_path),
    ) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    }) != null;
}

pub fn verifyBootstrapCleanupAbsent(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
) !void {
    try bootstrap.validate();
    if (try cleanupStage(allocator, root, bootstrap) != null)
        return error.NativeHelperEvidenceChanged;
}

pub fn verifyBootstrapCompletionState(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
    active_evidence: bool,
) !void {
    try bootstrap.validate();
    try verifyBootstrapTarget(allocator, root, bootstrap.target);
    const cleanup_state = try cleanupStage(allocator, root, bootstrap);
    const source_present = try bootstrapSourcePresent(root, bootstrap);
    if (!active_evidence) {
        if (cleanup_state != null or source_present)
            return error.NativeHelperEvidenceChanged;
        return;
    }
    switch (cleanup_state orelse {
        if (!source_present) return error.NativeHelperEvidenceMissing;
        try verifyBootstrapPrivateState(
            allocator,
            root,
            bootstrap,
            true,
        );
        return;
    }) {
        .prepared => try verifyBootstrapPrivateState(
            allocator,
            root,
            bootstrap,
            source_present,
        ),
        .completed => {
            if (source_present) return error.NativeHelperEvidenceChanged;
            try verifyBootstrapPrivateState(allocator, root, bootstrap, false);
        },
    }
}

pub fn prepareBootstrapCleanup(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
) !void {
    try bootstrap.validate();
    try verifyBootstrapTarget(allocator, root, bootstrap.target);
    const cleanup_state = try cleanupStage(allocator, root, bootstrap);
    if (cleanup_state != null) return;
    try verifyBootstrapPrivateState(allocator, root, bootstrap, true);
    var path_buffer: [256]u8 = undefined;
    const path = try cleanupPath(bootstrap, &path_buffer);
    try root.publishFile(path, cleanup_prepared, .{
        .permissions = .fromMode(0o600),
        .overwrite = .fail_if_exists,
        .durable = true,
    });
    try root.applyMetadata(path, .{ .mode = 0o600, .uid = 0, .gid = 0 });
    try root.syncRegularFile(path);
    try root.syncDirectory(try root_fs.Path.init(bootstrap_directory));
    if (try cleanupStage(allocator, root, bootstrap) != .prepared)
        return error.NativeHelperEvidenceChanged;
}

pub fn removeBootstrapSource(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
) !void {
    try bootstrap.validate();
    try verifyBootstrapTarget(allocator, root, bootstrap.target);
    const cleanup_state = try cleanupStage(allocator, root, bootstrap) orelse
        return error.NativeHelperEvidenceMissing;
    if (cleanup_state == .completed) {
        if (try bootstrapSourcePresent(root, bootstrap))
            return error.NativeHelperEvidenceChanged;
        return;
    }
    const source_present = try bootstrapSourcePresent(root, bootstrap);
    try verifyBootstrapPrivateState(allocator, root, bootstrap, source_present);
    if (source_present) {
        try root.removeFile(try root_fs.Path.init(bootstrap.helper.source_path));
        try root.syncDirectory(try root_fs.Path.init(bootstrap_directory));
    }
}

pub fn completeBootstrapCleanup(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
) !void {
    try bootstrap.validate();
    try verifyBootstrapTarget(allocator, root, bootstrap.target);
    const cleanup_state = try cleanupStage(allocator, root, bootstrap) orelse
        return error.NativeHelperEvidenceMissing;
    if (try bootstrapSourcePresent(root, bootstrap))
        return error.NativeHelperEvidenceChanged;
    if (cleanup_state == .completed) return;
    try verifyBootstrapPrivateState(allocator, root, bootstrap, false);
    var path_buffer: [256]u8 = undefined;
    const path = try cleanupPath(bootstrap, &path_buffer);
    try root.publishFile(path, cleanup_completed, .{
        .permissions = .fromMode(0o600),
        .overwrite = .replace,
        .durable = true,
    });
    try root.applyMetadata(path, .{ .mode = 0o600, .uid = 0, .gid = 0 });
    try root.syncRegularFile(path);
    try root.syncDirectory(try root_fs.Path.init(bootstrap_directory));
    if (try cleanupStage(allocator, root, bootstrap) != .completed)
        return error.NativeHelperEvidenceChanged;
}

pub fn finishBootstrapCleanupJournal(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
) !void {
    try bootstrap.validate();
    try verifyBootstrapTarget(allocator, root, bootstrap.target);
    if (try bootstrapSourcePresent(root, bootstrap))
        return error.NativeHelperEvidenceChanged;
    const cleanup_state = try cleanupStage(allocator, root, bootstrap) orelse
        return;
    if (cleanup_state != .completed)
        return error.NativeHelperEvidenceChanged;
    var path_buffer: [256]u8 = undefined;
    try root.removeFile(try cleanupPath(bootstrap, &path_buffer));
    try root.syncDirectory(try root_fs.Path.init(bootstrap_directory));
}

pub const Deployment = struct {
    binding: Binding,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Deployment) void {
        self.allocator.free(self.binding.source_path);
        self.* = undefined;
    }
};

pub fn bind(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    binding: Binding,
) !maintainer_script.HelperMount {
    try binding.validateAny();
    var sha256: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&sha256, &binding.sha256) catch return error.InvalidNativeHelper;
    var mount = maintainer_script.HelperMount.init(
        allocator,
        root,
        binding.source_path,
        binding.target_path,
        sha256,
    ) catch |err| switch (err) {
        error.FileNotFound => return error.NativeHelperEvidenceMissing,
        else => return err,
    };
    errdefer mount.deinit();
    const metadata = try mount.source.metadata();
    if (metadata.entry.size != binding.size or metadata.entry.mode & 0o7777 != 0o500)
        return error.InvalidNativeHelper;
    return mount;
}

pub fn bindBootstrap(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
) !maintainer_script.HelperMount {
    try bootstrap.validate();
    try verifyBootstrapPrivateState(allocator, root, bootstrap, true);
    try verifyBootstrapTarget(allocator, root, bootstrap.target);
    var mount = try bind(allocator, root, bootstrap.helper);
    errdefer mount.deinit();
    const root_entry = try root.rootEntry();
    if (!root_entry.modeled or root_entry.inode != bootstrap.root_inode)
        return error.NativeHelperRootDrift;
    const source = try mount.source.observeAlloc(allocator, maximum_bytes);
    defer allocator.free(source.bytes);
    if (source.entry.size != bootstrap.helper.size or
        source.entry.mode & 0o7777 != 0o500 or
        source.entry.uid != bootstrap.root_uid or
        source.entry.gid != bootstrap.root_gid or source.entry.link_count != 1)
        return error.NativeHelperEvidenceChanged;
    const target_maximum = std.math.cast(usize, bootstrap.target.size) orelse
        return error.InvalidNativeHelperBootstrap;
    const target = try mount.target.observeAlloc(allocator, target_maximum);
    defer allocator.free(target.bytes);
    if (target.entry.size != bootstrap.target.size or
        target.entry.mode != bootstrap.target.mode or
        target.entry.uid != bootstrap.target.uid or
        target.entry.gid != bootstrap.target.gid or target.entry.link_count != 1)
        return error.NativeHelperTargetDrift;
    var observed: [32]u8 = undefined;
    Sha256.hash(target.bytes, &observed, .{});
    if (!std.mem.eql(
        u8,
        &std.fmt.bytesToHex(observed, .lower),
        &bootstrap.target.sha256,
    )) return error.NativeHelperTargetDrift;
    return mount;
}

pub fn stage(allocator: std.mem.Allocator, root: root_fs.Root, source: Source) !Deployment {
    if (@import("builtin").os.tag != .linux) return error.UnsupportedPlatform;
    try source.validate();
    var target = root.pinRegularFile(try root_fs.Path.init(target_path)) catch |err| switch (err) {
        error.FileNotFound => return error.NativeHelperTargetMissing,
        else => return err,
    };
    defer target.close();
    const digest = std.fmt.bytesToHex(source.sha256, .lower);
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}.bin", .{ directory, digest });
    errdefer allocator.free(path);
    try root.createDirectoryPath(try root_fs.Path.init(directory), .fromMode(0o700));
    root.publishFile(try root_fs.Path.init(path), source.bytes, .{
        .permissions = .fromMode(0o500),
        .overwrite = .fail_if_exists,
        .durable = true,
    }) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const binding: Binding = .{
        .source_path = path,
        .target_path = target_path,
        .sha256 = digest,
        .size = source.bytes.len,
    };
    var mount = try bind(allocator, root, binding);
    defer mount.deinit();
    return .{ .binding = binding, .allocator = allocator };
}

pub fn probe(allocator: std.mem.Allocator, root: root_fs.Root, binding: Binding) !void {
    return probeWithCancellation(allocator, root, binding, .never());
}

pub fn probeWithCancellation(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    binding: Binding,
    cancellation: maintainer_script.Cancellation,
) !void {
    var execution = try probeExecutionWithCancellation(
        allocator,
        root,
        binding,
        cancellation,
    );
    defer execution.deinit(allocator);
    switch (execution.outcome) {
        .exited => |code| if (code != 0) return error.NativeHelperNamespaceUnavailable,
        else => return error.NativeHelperNamespaceUnavailable,
    }
}

pub fn probeExecutionWithCancellation(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    binding: Binding,
    cancellation: maintainer_script.Cancellation,
) !maintainer_script.Execution {
    var mount = try bind(allocator, root, binding);
    defer mount.deinit();
    return maintainer_script.SystemLauncher.probeHelper(
        allocator,
        &mount,
        cancellation,
    );
}

pub fn probeBootstrapExecutionWithCancellation(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    bootstrap: Bootstrap,
    cancellation: maintainer_script.Cancellation,
) !maintainer_script.Execution {
    var mount = try bindBootstrap(allocator, root, bootstrap);
    defer mount.deinit();
    return maintainer_script.SystemLauncher.probeHelper(
        allocator,
        &mount,
        cancellation,
    );
}

test "native_helper.test.bundled helper keeps runtime evidence compact" {
    if (@import("debz_build_options").native_helper_debug_info)
        return error.SkipZigTest;
    try std.testing.expect(@embedFile("debz_native_trigger_helper").len <= 8 * 1024 * 1024);
}

test "native_helper.test.absent target refuses without creating a placeholder or cache" {
    const testing = std.testing;
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    const source = bundled();
    try testing.expectError(error.NativeHelperTargetMissing, stage(testing.allocator, root, source));
    try testing.expect(try root.entryIfExists(try root_fs.Path.init(target_path)) == null);
    try testing.expect(try root.entryIfExists(try root_fs.Path.init(directory)) == null);
}

test "native_helper.test.deployment is immutable and does not replace target bytes" {
    const testing = std.testing;
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    try root.createDirectoryPath(try root_fs.Path.init("usr/bin"), .fromMode(0o755));
    try root.publishFile(try root_fs.Path.init(target_path), "package-owned helper\n", .{});
    const original = (try root.entryIfExists(try root_fs.Path.init(target_path))).?;
    var deployment = try stage(testing.allocator, root, bundled());
    defer deployment.deinit();
    var again = try stage(testing.allocator, root, bundled());
    defer again.deinit();
    try testing.expectEqualStrings(deployment.binding.source_path, again.binding.source_path);
    const after = (try root.entryIfExists(try root_fs.Path.init(target_path))).?;
    try testing.expectEqual(original.inode, after.inode);
    const bytes = try root.readFileAlloc(testing.allocator, try root_fs.Path.init(target_path), 128);
    defer testing.allocator.free(bytes);
    try testing.expectEqualStrings("package-owned helper\n", bytes);
    probe(testing.allocator, root, deployment.binding) catch |err| {
        try testing.expectEqual(error.NativeHelperNamespaceUnavailable, err);
    };
    const after_probe = (try root.entryIfExists(try root_fs.Path.init(target_path))).?;
    try testing.expectEqual(original.inode, after_probe.inode);
    try testing.expectEqual(original.size, after_probe.size);
    try root.publishFile(try root_fs.Path.init(deployment.binding.source_path), "changed", .{
        .permissions = .fromMode(0o500),
    });
    try testing.expectError(error.HelperDigestMismatch, stage(testing.allocator, root, bundled()));
}

fn testBootstrap(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    target_bytes: []const u8,
) !Bootstrap {
    const attempt_id: [64]u8 = @splat('a');
    const source = bundled();
    const helper = try bootstrapBinding(allocator, attempt_id, source);
    var target_sha256: [32]u8 = undefined;
    Sha256.hash(target_bytes, &target_sha256, .{});
    const root_entry = try root.rootEntry();
    return .{
        .attempt_id = attempt_id,
        .root_identity_sha256 = @splat('b'),
        .root_inode = root_entry.inode,
        .root_uid = 0,
        .root_gid = 0,
        .plan_sha256 = @splat('c'),
        .authorization_sha256 = @splat('d'),
        .program_sha256 = @splat('e'),
        .exact_lock_schema = "https://debz.dev/schema/exact-closure-lock-v2",
        .exact_lock_version = 2,
        .exact_lock_sha256 = @splat('f'),
        .helper = helper,
        .owner = .{
            .package = "dpkg",
            .version = "1.0",
            .architecture = "amd64",
            .final_state = "installed",
            .artifact = 0,
            .archive_sha256 = @splat('1'),
            .archive_size = 4096,
            .application_sha256 = @splat('2'),
            .program_step = 3,
        },
        .target = .{
            .sha256 = std.fmt.bytesToHex(target_sha256, .lower),
            .size = target_bytes.len,
            .mode = 0o755,
            .uid = root_entry.uid,
            .gid = root_entry.gid,
        },
    };
}

test "native_helper.test.fresh-root source is attempt scoped and never replaces package target" {
    if (@import("builtin").os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
    const testing = std.testing;
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    const target_bytes = "package-owned dpkg-trigger\n";
    try root.createDirectoryPath(try root_fs.Path.init("usr/bin"), .fromMode(0o755));
    try root.publishFile(try root_fs.Path.init(target_path), target_bytes, .{});
    try root.applyMetadata(try root_fs.Path.init(target_path), .{ .mode = 0o755 });
    try root.createDirectoryPath(
        try root_fs.Path.init(bootstrap_directory),
        .fromMode(0o700),
    );
    try root.applyMetadata(
        try root_fs.Path.init(bootstrap_directory),
        .{ .mode = 0o700 },
    );
    const bootstrap = try testBootstrap(testing.allocator, root, target_bytes);
    defer testing.allocator.free(bootstrap.helper.source_path);
    const before = (try root.entryIfExists(try root_fs.Path.init(target_path))).?;
    try stageBootstrap(testing.allocator, root, bootstrap, bundled());
    try verifyBootstrapPrivateState(testing.allocator, root, bootstrap, true);
    const after = (try root.entryIfExists(try root_fs.Path.init(target_path))).?;
    try testing.expectEqual(before.inode, after.inode);
    try testing.expectEqual(before.size, after.size);
    try cleanupBootstrap(testing.allocator, root, bootstrap);
    try testing.expect(
        try root.entryIfExists(try root_fs.Path.init(bootstrap.helper.source_path)) == null,
    );
}

test "native_helper.test.fresh-root target drift blocks private source publication" {
    if (@import("builtin").os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
    const testing = std.testing;
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    const target_bytes = "package-owned dpkg-trigger\n";
    try root.createDirectoryPath(try root_fs.Path.init("usr/bin"), .fromMode(0o755));
    try root.publishFile(try root_fs.Path.init(target_path), target_bytes, .{});
    try root.createDirectoryPath(
        try root_fs.Path.init(bootstrap_directory),
        .fromMode(0o700),
    );
    try root.applyMetadata(
        try root_fs.Path.init(bootstrap_directory),
        .{ .mode = 0o700 },
    );
    const bootstrap = try testBootstrap(testing.allocator, root, target_bytes);
    defer testing.allocator.free(bootstrap.helper.source_path);
    try testing.expectError(
        error.NativeHelperTargetDrift,
        stageBootstrap(testing.allocator, root, bootstrap, bundled()),
    );
    try testing.expect(
        try root.entryIfExists(try root_fs.Path.init(bootstrap.helper.source_path)) == null,
    );
}

test "native_helper.test.fresh-root bootstrap requires root-owned private state" {
    const testing = std.testing;
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    const bootstrap = try testBootstrap(testing.allocator, root, "target\n");
    defer testing.allocator.free(bootstrap.helper.source_path);
    var changed = bootstrap;
    changed.root_uid = 1;
    try testing.expectError(error.InvalidNativeHelperBootstrap, changed.validate());
    changed = bootstrap;
    changed.root_gid = 1;
    try testing.expectError(error.InvalidNativeHelperBootstrap, changed.validate());
}

test "native_helper.test.fresh-root bootstrap rejects target source and identity links or drift" {
    if (@import("builtin").os.tag != .linux or std.os.linux.geteuid() != 0)
        return error.SkipZigTest;
    const testing = std.testing;
    var temporary = testing.tmpDir(.{});
    defer temporary.cleanup();
    const root = root_fs.Root.init(testing.io, temporary.dir);
    const target_bytes = "package-owned dpkg-trigger\n";
    const target = try root_fs.Path.init(target_path);
    try root.createDirectoryPath(try root_fs.Path.init("usr/bin"), .fromMode(0o755));
    try root.publishFile(target, target_bytes, .{ .permissions = .fromMode(0o755) });
    try root.applyMetadata(target, .{ .mode = 0o755, .uid = 0, .gid = 0 });
    try root.createDirectoryPath(
        try root_fs.Path.init(bootstrap_directory),
        .fromMode(0o700),
    );
    try root.applyMetadata(
        try root_fs.Path.init(bootstrap_directory),
        .{ .mode = 0o700, .uid = 0, .gid = 0 },
    );
    const bootstrap = try testBootstrap(testing.allocator, root, target_bytes);
    defer testing.allocator.free(bootstrap.helper.source_path);

    var changed = bootstrap;
    changed.root_inode +%= 1;
    try testing.expectError(
        error.NativeHelperRootDrift,
        verifyBootstrapPrivateState(testing.allocator, root, changed, false),
    );
    const target_link = try root_fs.Path.init("usr/bin/dpkg-trigger.link");
    try root.createHardLink(target, target_link);
    try testing.expectError(
        error.NativeHelperTargetDrift,
        verifyBootstrapTarget(testing.allocator, root, bootstrap.target),
    );
    try root.removeFile(target_link);
    try root.applyMetadata(target, .{ .mode = 0o700 });
    try testing.expectError(
        error.NativeHelperTargetDrift,
        verifyBootstrapTarget(testing.allocator, root, bootstrap.target),
    );
    try root.applyMetadata(target, .{ .mode = 0o755 });
    try root.applyMetadata(target, .{ .uid = 1, .gid = 1 });
    try testing.expectError(
        error.NativeHelperTargetDrift,
        verifyBootstrapTarget(testing.allocator, root, bootstrap.target),
    );
    try root.applyMetadata(target, .{ .uid = 0, .gid = 0 });
    try root.publishFile(target, "changed package target\n", .{ .overwrite = .replace });
    try root.applyMetadata(target, .{ .mode = 0o755, .uid = 0, .gid = 0 });
    try testing.expectError(
        error.NativeHelperTargetDrift,
        verifyBootstrapTarget(testing.allocator, root, bootstrap.target),
    );
    try root.publishFile(target, target_bytes, .{ .overwrite = .replace });
    try root.applyMetadata(target, .{ .mode = 0o755, .uid = 0, .gid = 0 });

    const cleanup_path = try std.fmt.allocPrint(
        testing.allocator,
        "{s}.cleanup",
        .{bootstrap.helper.source_path},
    );
    defer testing.allocator.free(cleanup_path);
    try root.publishFile(
        try root_fs.Path.init(cleanup_path),
        cleanup_prepared,
        .{ .permissions = .fromMode(0o600) },
    );
    try root.applyMetadata(
        try root_fs.Path.init(cleanup_path),
        .{ .mode = 0o600, .uid = 0, .gid = 0 },
    );
    try testing.expectError(
        error.NativeHelperEvidenceChanged,
        verifyBootstrapCleanupAbsent(testing.allocator, root, bootstrap),
    );
    try root.removeFile(try root_fs.Path.init(cleanup_path));

    const source_path = try root_fs.Path.init(bootstrap.helper.source_path);
    try root.createSymbolicLink(source_path, "/outside");
    try testing.expectError(
        error.NativeHelperEvidenceChanged,
        stageBootstrap(testing.allocator, root, bootstrap, bundled()),
    );
    try root.removeFile(source_path);
    try stageBootstrap(testing.allocator, root, bootstrap, bundled());
    const source_link = try root_fs.Path.init("var/lib/debz/native-recovery-v1/helper.link");
    try root.createHardLink(source_path, source_link);
    try testing.expectError(
        error.NativeHelperEvidenceChanged,
        verifyBootstrapPrivateState(testing.allocator, root, bootstrap, true),
    );
    try testing.expectError(
        error.NativeHelperEvidenceChanged,
        cleanupBootstrap(testing.allocator, root, bootstrap),
    );
    try root.removeFile(source_link);
    try root.removeFile(source_path);
    try testing.expectError(
        error.NativeHelperEvidenceMissing,
        verifyBootstrapCompletionState(
            testing.allocator,
            root,
            bootstrap,
            true,
        ),
    );
    try testing.expectError(
        error.NativeHelperEvidenceMissing,
        cleanupBootstrap(testing.allocator, root, bootstrap),
    );
    try stageBootstrap(testing.allocator, root, bootstrap, bundled());
    try cleanupBootstrap(testing.allocator, root, bootstrap);
}
