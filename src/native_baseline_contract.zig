//! Versioned composition of authenticated archive authority and retained local no-ops.
const std = @import("std");
const components = @import("installed_baseline_component.zig");
const exact_lock_v4 = @import("exact_lock_v4.zig");
const exact_lock_v3 = @import("exact_lock_v3.zig");
const installed = @import("installed_baseline.zig");
const root_fs = @import("root_fs.zig");

pub const schema_id = "https://debz.dev/schema/native-installed-baseline-noop-v1";
pub const Contract = struct {
    schema: []const u8 = schema_id,
    version: u32 = 1,
    planning_lock_json: []const u8,
    planning_lock_sha256: [32]u8,
    archive_lock_sha256: [32]u8,
    component: components.Manifest,

    pub fn digest(self: Contract) [128]u8 {
        var buffer: [4096]u8 = undefined;
        var sink: std.Io.Writer.Hashing(std.crypto.hash.sha2.Sha512) = .init(&buffer);
        sink.writer.writeAll("debz native installed baseline no-op v1\x00") catch unreachable;
        std.json.Stringify.value(self, .{}, &sink.writer) catch unreachable;
        sink.writer.flush() catch unreachable;
        return std.fmt.bytesToHex(sink.hasher.finalResult(), .lower);
    }

    pub fn validate(self: Contract, allocator: std.mem.Allocator, archive_lock: ?*const exact_lock_v3.Lock) !void {
        if (!std.mem.eql(u8, self.schema, schema_id) or self.version != 1)
            return error.InvalidNativeBaselineContract;
        var actual: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.planning_lock_json, &actual, .{});
        if (!std.mem.eql(u8, &actual, &self.planning_lock_sha256)) return error.InvalidNativeBaselineContract;
        var lock = try exact_lock_v4.decode(allocator, self.planning_lock_json);
        defer lock.deinit();
        if (lock.backend() != .native or !std.mem.eql(u8, &self.archive_lock_sha256, &lock.archive_lock.lock.digest_sha256))
            return error.InvalidNativeBaselineContract;
        if (archive_lock) |archive| {
            const bytes = try archive.canonicalJson(allocator);
            defer allocator.free(bytes);
            if (!std.mem.eql(u8, bytes, lock.parsed.value.payload.archive_lock_json))
                return error.InvalidNativeBaselineContract;
        }
        const baseline = lock.evidence();
        if (!std.mem.eql(u8, self.component.schema, components.schema_id) or self.component.version != 1 or
            !std.mem.eql(u8, self.component.architecture, baseline.native_architecture) or
            self.component.root.device != baseline.root_device or self.component.root.inode != baseline.root_inode or
            self.component.root.uid != baseline.root_uid or self.component.root.gid != baseline.root_gid or
            self.component.root.mode != baseline.root_mode or self.component.components.len != baseline.packages.len)
            return error.InvalidNativeBaselineContract;
        for (baseline.packages, self.component.components) |package, component| {
            if (!std.mem.eql(u8, package.name, component.package.name) or
                !std.mem.eql(u8, package.version, component.package.version) or
                !std.mem.eql(u8, package.architecture, component.package.architecture) or
                package.selection != component.package.selection)
                return error.InvalidNativeBaselineContract;
        }
    }

    pub fn verify(self: Contract, allocator: std.mem.Allocator, root: root_fs.Root) !void {
        try self.validate(allocator, null);
        try components.verify(allocator, root, self.component);
    }

    pub fn clone(self: Contract, allocator: std.mem.Allocator) std.mem.Allocator.Error!Contract {
        const bytes = try std.json.Stringify.valueAlloc(allocator, self, .{});
        defer allocator.free(bytes);
        const parsed = std.json.parseFromSlice(Contract, allocator, bytes, .{ .allocate = .alloc_always, .max_value_len = exact_lock_v4.maximum_document_bytes }) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => unreachable,
        };
        // Callers provide the prepared program's owning arena.
        return parsed.value;
    }
};

pub fn capture(
    allocator: std.mem.Allocator,
    io: std.Io,
    root: root_fs.Root,
    lock: *const exact_lock_v4.OwnedLock,
    status_bytes: []const u8,
) !Contract {
    if (lock.backend() != .native) return error.InstalledBaselineExecutionUnsupported;
    const evidence = lock.evidence();
    const verified = try installed.verify(allocator, io, evidence.root_path, evidence.native_architecture, status_bytes, evidence);
    defer verified.deinit();
    const component = try components.capture(allocator, root, evidence.native_architecture, evidence.packages);
    const bytes = try lock.canonicalJson(allocator);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const result: Contract = .{
        .planning_lock_json = bytes,
        .planning_lock_sha256 = digest,
        .archive_lock_sha256 = lock.archive_lock.lock.digest_sha256,
        .component = component,
    };
    try result.validate(allocator, &lock.archive_lock.lock);
    return result;
}
