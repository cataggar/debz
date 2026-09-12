//! Trusted helper deployment never creates or replaces its package-owned target.
//! Sources are immutable, content-addressed files in debz's private namespace.
const std = @import("std");
const maintainer_script = @import("maintainer_script.zig");
const root_fs = @import("root_fs.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;
pub const directory = "var/lib/debz/native-helper-cache-v1";
pub const target_path = "usr/bin/dpkg-trigger";
pub const maximum_bytes = 32 * 1024 * 1024;

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

    pub fn validate(self: Binding) !void {
        if (self.size == 0 or self.size > maximum_bytes or
            !std.mem.eql(u8, self.target_path, nativeTarget()))
            return error.InvalidNativeHelper;
        for (self.sha256) |byte|
            if ((byte < '0' or byte > '9') and (byte < 'a' or byte > 'f'))
                return error.InvalidNativeHelper;
        var buffer: [256]u8 = undefined;
        const expected = try std.fmt.bufPrint(&buffer, "{s}/{s}.bin", .{ directory, self.sha256 });
        if (!std.mem.eql(u8, self.source_path, expected)) return error.InvalidNativeHelper;
    }

    pub fn matches(self: Binding, source: Source) !void {
        try self.validate();
        try source.validate();
        if (self.size != source.bytes.len or
            !std.mem.eql(u8, &self.sha256, &std.fmt.bytesToHex(source.sha256, .lower)))
            return error.NativeHelperDigestMismatch;
    }
};

fn nativeTarget() []const u8 {
    return target_path;
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
    try binding.validate();
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
    var mount = try bind(allocator, root, binding);
    defer mount.deinit();
    var execution = try maintainer_script.SystemLauncher.probeHelper(
        allocator,
        &mount,
        maintainer_script.Cancellation.never(),
    );
    defer execution.deinit(allocator);
    switch (execution.outcome) {
        .exited => |code| if (code != 0) return error.NativeHelperNamespaceUnavailable,
        else => return error.NativeHelperNamespaceUnavailable,
    }
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
