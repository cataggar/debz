const std = @import("std");
const package_database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");
const root_mutation = @import("root_mutation.zig");

pub const database_path = package_database.database_directory ++ "/" ++ package_database.diversions_path;
pub const UpdateError = error{ UnsupportedInPlaceDiversionUpdate, UnsupportedMidUnpackDiversionUpdate };

pub const Observation = struct {
    device: u64,
    inode: u64,
    sha256: [32]u8,

    pub fn validateAtomicUpdate(previous: Observation, next: Observation) UpdateError!void {
        if (previous.device == next.device and previous.inode == next.inode and
            !std.mem.eql(u8, &previous.sha256, &next.sha256))
            return error.UnsupportedInPlaceDiversionUpdate;
    }
};

pub fn validateUpdate(previous: ?Observation, next: ?Observation, in_progress: bool) UpdateError!void {
    if (previous) |before| {
        if (next) |after| {
            try before.validateAtomicUpdate(after);
            if (in_progress and !std.mem.eql(u8, &before.sha256, &after.sha256))
                return error.UnsupportedMidUnpackDiversionUpdate;
        } else if (in_progress) return error.UnsupportedMidUnpackDiversionUpdate;
    } else if (next != null and in_progress) return error.UnsupportedMidUnpackDiversionUpdate;
}

pub fn observe(allocator: std.mem.Allocator, root: root_fs.Root) !?Observation {
    var pinned = root.pinRegularFile(try root_fs.Path.init(database_path)) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer pinned.close();
    const observed = try pinned.observeAlloc(allocator, (package_database.Limits{}).max_database_file_bytes);
    defer allocator.free(observed.bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(observed.bytes, &digest, .{});
    return .{ .device = observed.entry.device, .inode = observed.entry.inode, .sha256 = digest };
}

/// Paths and records borrow the imported database; only the indexes are owned.
pub const Index = struct {
    sources: std.StringHashMapUnmanaged(package_database.DiversionRecord) = .empty,
    targets: std.StringHashMapUnmanaged(void) = .empty,

    pub fn init(
        allocator: std.mem.Allocator,
        records: []const package_database.DiversionRecord,
    ) error{ OutOfMemory, InvalidDiversion }!Index {
        if (records.len > (package_database.Limits{}).max_diversions)
            return error.InvalidDiversion;
        var result: Index = .{};
        errdefer result.deinit(allocator);
        for (records) |record| {
            if (record.from.len < 2 or record.to.len < 2 or
                record.from.len > (package_database.Limits{}).max_path_bytes or
                record.to.len > (package_database.Limits{}).max_path_bytes or
                !package_database.validAbsolutePath(record.from) or
                !package_database.validAbsolutePath(record.to) or
                std.mem.eql(u8, record.from, record.to))
                return error.InvalidDiversion;
            const from = record.from[1..];
            const to = record.to[1..];
            _ = root_fs.Path.initPackage(from) catch return error.InvalidDiversion;
            _ = root_fs.Path.initPackage(to) catch return error.InvalidDiversion;
            if (package_database.reservedPayloadPath(from) or package_database.reservedPayloadPath(to) or
                root_mutation.withinNamespace(from) or root_mutation.withinNamespace(to))
                return error.InvalidDiversion;
            if (result.sources.contains(from) or result.targets.contains(from) or
                result.sources.contains(to) or result.targets.contains(to))
                return error.InvalidDiversion;
            try result.sources.put(allocator, from, record);
            try result.targets.put(allocator, to, {});
        }
        return result;
    }

    pub fn deinit(self: *Index, allocator: std.mem.Allocator) void {
        self.sources.deinit(allocator);
        self.targets.deinit(allocator);
        self.* = undefined;
    }

    pub fn redirected(self: Index, relative: []const u8, package: []const u8) ?[]const u8 {
        const record = self.sources.get(relative) orelse return null;
        if (record.package) |exempt| {
            if (std.mem.eql(u8, exempt, package)) return null;
        }
        return record.to[1..];
    }

    pub fn physical(self: Index, relative: []const u8, package: []const u8) []const u8 {
        return self.redirected(relative, package) orelse relative;
    }
};
