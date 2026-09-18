const std = @import("std");
const package_database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");
const root_mutation = @import("root_mutation.zig");

pub const database_path = package_database.database_directory ++ "/" ++ package_database.diversions_path;
pub const UpdateError = error{ UnsupportedInPlaceDiversionUpdate, UnsupportedMidUnpackDiversionUpdate, InvalidDiversionUpdate };

pub const Observation = struct {
    device: u64,
    inode: u64,
    sha256: [32]u8,

    pub fn sameFile(left: Observation, right: Observation) bool {
        return left.device == right.device and left.inode == right.inode;
    }

    pub fn validateAtomicUpdate(previous: Observation, next: Observation) UpdateError!void {
        if (previous.sameFile(next) and
            !std.mem.eql(u8, &previous.sha256, &next.sha256))
            return error.UnsupportedInPlaceDiversionUpdate;
    }
};

/// Owns effective records separately from the most recently observed live bytes.
/// The runtime must keep the loaded file pinned to prevent inode reuse.
pub const CachedRecords = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    loaded: ?Observation,
    observed: ?Observation,
    bytes: ?[]const u8,
    records: []const package_database.DiversionRecord,
    index: Index,

    pub fn init(
        allocator: std.mem.Allocator,
        bytes: ?[]const u8,
        observation: ?Observation,
    ) !CachedRecords {
        try validateObservedBytes(bytes, observation);
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = .init(allocator);
        errdefer arena.deinit();
        const owned = arena.allocator();
        const stored = if (bytes) |contents| try owned.dupe(u8, contents) else null;
        const records = if (stored) |contents| switch (try package_database.interpretDiversions(
            owned,
            allocator,
            contents,
            .{},
        )) {
            .records => |value| value,
            .diagnostic => return error.InvalidDiversion,
        } else &.{};
        return .{
            .allocator = allocator,
            .arena = arena,
            .loaded = observation,
            .observed = observation,
            .bytes = stored,
            .records = records,
            .index = try Index.init(owned, records),
        };
    }

    pub fn deinit(self: *CachedRecords) void {
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }

    pub fn clone(self: CachedRecords, allocator: std.mem.Allocator) !CachedRecords {
        var result = try CachedRecords.init(allocator, self.bytes, self.loaded);
        result.observed = self.observed;
        return result;
    }

    pub fn refresh(self: *CachedRecords, bytes: ?[]const u8, observation: ?Observation) !bool {
        try validateObservedBytes(bytes, observation);
        if (std.meta.eql(self.observed, observation)) return false;
        // Identical replacements must not invalidate records borrowed by an active phase.
        if (self.loaded != null and observation != null and
            !self.loaded.?.sameFile(observation.?) and self.bytes != null and bytes != null and
            std.mem.eql(u8, self.bytes.?, bytes.?))
        {
            self.loaded = observation;
            self.observed = observation;
            return true;
        }
        var candidate = try CachedRecords.init(self.allocator, bytes, observation);
        if (self.loaded != null and observation != null and
            self.loaded.?.sameFile(observation.?))
        {
            candidate.deinit();
            self.observed = observation;
            return false;
        }
        self.deinit();
        self.* = candidate;
        return true;
    }

    pub fn validateRefresh(self: CachedRecords, next: ?Observation, in_progress: bool) UpdateError!void {
        if (!in_progress) return;
        try validateUpdate(self.observed, next, true);
        if (self.loaded) |loaded| {
            if (next) |after| {
                if (!loaded.sameFile(after) and !std.mem.eql(u8, &loaded.sha256, &after.sha256))
                    return error.UnsupportedMidUnpackDiversionUpdate;
            }
        }
    }
};

fn validateObservedBytes(bytes: ?[]const u8, observation: ?Observation) !void {
    const contents = bytes orelse {
        if (observation != null) return error.InvalidDiversionObservation;
        return;
    };
    if (contents.len > (package_database.Limits{}).max_database_file_bytes)
        return error.InvalidDiversion;
    const expected = observation orelse return error.InvalidDiversionObservation;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(contents, &digest, .{});
    if (!std.mem.eql(u8, &digest, &expected.sha256))
        return error.InvalidDiversionObservation;
}

const Capture = struct {
    allocator: std.mem.Allocator,
    pinned: ?root_fs.PinnedRegularFile = null,
    bytes: ?[]const u8 = null,
    observation: ?Observation = null,

    fn read(allocator: std.mem.Allocator, root: root_fs.Root) !Capture {
        var pinned = root.pinRegularFile(try root_fs.Path.init(database_path)) catch |err| switch (err) {
            error.FileNotFound => return .{ .allocator = allocator },
            else => return err,
        };
        errdefer pinned.close();
        const captured = try pinned.observeStableAlloc(allocator, (package_database.Limits{}).max_database_file_bytes);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(captured.bytes, &digest, .{});
        return .{
            .allocator = allocator,
            .pinned = pinned,
            .bytes = captured.bytes,
            .observation = .{ .device = captured.entry.device, .inode = captured.entry.inode, .sha256 = digest },
        };
    }

    fn deinit(self: *Capture) void {
        if (self.pinned) |*pinned| pinned.close();
        if (self.bytes) |bytes| self.allocator.free(bytes);
        self.* = undefined;
    }
};

pub const Session = struct {
    cache: CachedRecords,
    pinned: ?root_fs.PinnedRegularFile,

    pub fn open(allocator: std.mem.Allocator, root: root_fs.Root) !Session {
        var captured = try Capture.read(allocator, root);
        defer captured.deinit();
        const cache = try CachedRecords.init(allocator, captured.bytes, captured.observation);
        const pinned = captured.pinned;
        captured.pinned = null;
        return .{ .cache = cache, .pinned = pinned };
    }

    pub fn restore(
        allocator: std.mem.Allocator,
        root: root_fs.Root,
        expected: CachedRecords,
    ) !Session {
        var live = try Session.open(allocator, root);
        errdefer live.deinit();
        if (!std.meta.eql(live.cache.observed, expected.observed) or
            (expected.loaded == null) != (expected.observed == null) or
            (expected.loaded != null and !expected.loaded.?.sameFile(expected.observed.?)))
            return error.InvalidDiversionObservation;
        const cached = try expected.clone(allocator);
        live.cache.deinit();
        live.cache = cached;
        return live;
    }

    pub fn deinit(self: *Session) void {
        if (self.pinned) |*pinned| pinned.close();
        self.cache.deinit();
        self.* = undefined;
    }

    pub fn refresh(self: *Session, root: root_fs.Root, in_progress: bool) !bool {
        var captured = try Capture.read(self.cache.allocator, root);
        defer captured.deinit();
        try self.cache.validateRefresh(captured.observation, in_progress);
        const previous = self.cache.observed;
        if (try self.cache.refresh(captured.bytes, captured.observation)) {
            if (self.pinned) |*pinned| pinned.close();
            self.pinned = captured.pinned;
            captured.pinned = null;
        }
        return !std.meta.eql(previous, self.cache.observed);
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
