const std = @import("std");
const status = @import("dpkg_status.zig");
const root_fs = @import("root_fs.zig");

pub const Package = @import("installed_baseline_component.zig").Package;

pub const Identity = struct {
    algorithm: enum { sha512 } = .sha512,
    value: []const u8,
};

pub const Evidence = struct {
    authority: enum { installed_database_noop_v1 } = .installed_database_noop_v1,
    root_path: []const u8,
    root_device: u64,
    root_inode: u64,
    root_uid: u32,
    root_gid: u32,
    root_mode: u32,
    native_architecture: []const u8,
    database_identity: Identity,
    packages: []const Package,
};

/// Root-validated no-op facts, never archive or execution authority.
pub const Verified = opaque {
    fn data(self: *const Verified) *const Data {
        return @ptrCast(@alignCast(self));
    }

    pub fn evidence(self: *const Verified) Evidence {
        return self.data().value;
    }

    pub fn find(self: *const Verified, name: []const u8, architecture: []const u8) ?Package {
        const packages = self.evidence().packages;
        var lower: usize = 0;
        var upper = packages.len;
        while (lower < upper) {
            const middle = lower + (upper - lower) / 2;
            const package = packages[middle];
            const order = std.mem.order(u8, package.name, name);
            const identity_order = if (order == .eq) std.mem.order(u8, package.architecture, architecture) else order;
            switch (identity_order) {
                .eq => return package,
                .lt => lower = middle + 1,
                .gt => upper = middle,
            }
        }
        return null;
    }

    pub fn deinit(self: *Verified) void {
        const value: *Data = @ptrCast(@alignCast(self));
        value.deinit();
    }

    pub fn requireOutputOutsideDatabase(self: *const Verified, directory: root_fs.Root) !void {
        try self.data().requireOutputOutsideDatabase(directory);
    }
};

/// Read-only drift observation with unavailable exclusion bytes, never no-op authority.
pub const UnavailableDownloadPrestate = opaque {
    fn data(self: *const UnavailableDownloadPrestate) *const Data {
        return @ptrCast(@alignCast(self));
    }

    pub fn refusal(self: *const UnavailableDownloadPrestate) anyerror {
        return self.data().read_refusal.?;
    }

    pub fn verify(self: *const UnavailableDownloadPrestate, allocator: std.mem.Allocator, root: root_fs.Root, status_bytes: []const u8) !void {
        const evidence = self.data().value;
        const entry = try root.rootEntry();
        if (entry.device != evidence.root_device or entry.inode != evidence.root_inode or
            entry.uid != evidence.root_uid or entry.gid != evidence.root_gid or entry.mode != evidence.root_mode)
            return error.InstalledBaselineChanged;
        const actual = try make(allocator, root.io, evidence.root_path, evidence.native_architecture, status_bytes, evidence.packages, true);
        defer actual.deinit();
        try requireSamePrestate(actual.value, evidence);
    }

    pub fn requireOutputOutsideDatabase(self: *const UnavailableDownloadPrestate, directory: root_fs.Root) !void {
        try self.data().requireOutputOutsideDatabase(directory);
    }

    pub fn deinit(self: *UnavailableDownloadPrestate) void {
        const value: *Data = @ptrCast(@alignCast(self));
        value.deinit();
    }
};

pub const DownloadPrestate = union(enum) {
    verified: *Verified,
    unavailable: *UnavailableDownloadPrestate,
};

const DirectoryIdentity = struct { device: u64, inode: u64 };

const Data = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    value: Evidence,
    directories: []const DirectoryIdentity,
    read_refusal: ?anyerror,

    fn deinit(self: *Data) void {
        const allocator = self.allocator;
        self.arena.deinit();
        allocator.destroy(self);
    }

    fn requireOutputOutsideDatabase(self: *const Data, directory: root_fs.Root) !void {
        const actual = try directory.rootEntry();
        if (!actual.modeled or !actual.isDirectory()) return error.UnsafeInstalledBaseline;
        for (self.directories) |bound| {
            if (bound.device == actual.device and bound.inode == actual.inode)
                return error.InstalledBaselineOutputOverlapsDatabase;
        }
    }
};

const Tree = struct {
    allocator: std.mem.Allocator,
    hash: std.crypto.hash.sha2.Sha512 = .init(.{}),
    files: usize = 0,
    entries: usize = 0,
    bytes: usize = 0,
    metadata_bytes: usize = 0,
    status_bytes: ?[]const u8 = null,
    directories: std.ArrayList(DirectoryIdentity) = .empty,
    allow_unreadable_exclusions: bool = false,
    read_refusal: ?anyerror = null,

    fn charge(self: *Tree, bytes: usize) !void {
        self.metadata_bytes = std.math.add(usize, self.metadata_bytes, bytes) catch
            return error.InstalledBaselineLimitExceeded;
        if (self.metadata_bytes > 64 * 1024 * 1024) return error.InstalledBaselineLimitExceeded;
    }
};

fn requireOwned(root: root_fs.Root, entry: root_fs.Entry) !void {
    const owner = try root.rootEntry();
    if (!entry.modeled or entry.uid != owner.uid or entry.mode & 0o022 != 0 or
        (!entry.isDirectory() and (!entry.isRegularFile() or entry.link_count != 1)))
        return error.UnsafeInstalledBaseline;
}

fn hashEntry(tree: *Tree, path: []const u8, entry: root_fs.Entry, changed: i128, bytes: ?[]const u8) !void {
    const metadata = try std.json.Stringify.valueAlloc(tree.allocator, .{
        .path = path,
        .entry = entry,
        .change_nanoseconds = changed,
    }, .{});
    try tree.charge(metadata.len);
    tree.hash.update(metadata);
    tree.hash.update("\x00");
    if (bytes) |content| tree.hash.update(content);
    tree.hash.update("\x00");
}

fn captureTree(tree: *Tree, root: root_fs.Root, path: []const u8, depth: usize) !void {
    if (depth > 32 or path.len > 4096) return error.InstalledBaselineLimitExceeded;
    tree.entries += 1;
    if (tree.entries > 200_000) return error.InstalledBaselineLimitExceeded;
    const resolved = try root_fs.Path.init(path);
    const entry = try root.entry(resolved);
    try requireOwned(root, entry);
    if (entry.isRegularFile()) {
        tree.files += 1;
        if (tree.files > 100_000) return error.InstalledBaselineLimitExceeded;
        var pin = root.pinRegularFile(resolved) catch |err| switch (err) {
            error.AccessDenied, error.PermissionDenied => {
                if (!tree.allow_unreadable_exclusions or
                    (!std.mem.eql(u8, path, "var/lib/dpkg/lock") and
                        !std.mem.eql(u8, path, "var/lib/dpkg/lock-frontend")))
                    return err;
                const observed = try root.observeEntry(resolved);
                try requireOwned(root, observed.entry);
                if (!observed.entry.isRegularFile()) return error.UnsafeInstalledBaseline;
                if (observed.entry.size > 64 * 1024 * 1024) return error.InstalledBaselineLimitExceeded;
                tree.bytes = std.math.add(usize, tree.bytes, @intCast(observed.entry.size)) catch
                    return error.InstalledBaselineLimitExceeded;
                if (tree.bytes > 256 * 1024 * 1024) return error.InstalledBaselineLimitExceeded;
                tree.read_refusal = tree.read_refusal orelse err;
                tree.hash.update("unreadable publication exclusion\x00");
                try hashEntry(tree, path, observed.entry, observed.change_nanoseconds, null);
                return;
            },
            else => return err,
        };
        defer pin.close();
        try requireOwned(root, (try pin.metadata()).entry);
        const observed = try pin.observeStableAlloc(tree.allocator, 64 * 1024 * 1024);
        tree.bytes = std.math.add(usize, tree.bytes, observed.bytes.len) catch
            return error.InstalledBaselineLimitExceeded;
        if (tree.bytes > 256 * 1024 * 1024) return error.InstalledBaselineLimitExceeded;
        if (std.mem.eql(u8, path, "var/lib/dpkg/status")) tree.status_bytes = observed.bytes;
        try hashEntry(tree, path, observed.entry, observed.change_nanoseconds, observed.bytes);
        return;
    }
    var pin = try root.pinDirectory(resolved);
    defer pin.close();
    const observed = try pin.observeAlloc(tree.allocator, 100_000, 4 * 1024 * 1024);
    try tree.charge(observed.members.len * @sizeOf(root_fs.DirectoryMember));
    for (observed.members) |member| try tree.charge(member.name.len);
    try requireOwned(root, observed.entry);
    try tree.charge(@sizeOf(DirectoryIdentity));
    try tree.directories.append(tree.allocator, .{ .device = observed.entry.device, .inode = observed.entry.inode });
    try hashEntry(tree, path, observed.entry, observed.change_nanoseconds, null);
    if (std.mem.eql(u8, path, "var/lib/dpkg/updates") and observed.members.len != 0)
        return error.InstalledBaselineRecoveryRequired;
    const Member = std.meta.Elem(@TypeOf(observed.members));
    std.mem.sort(Member, observed.members, {}, struct {
        fn less(_: void, left: Member, right: Member) bool {
            return std.mem.lessThan(u8, left.name, right.name);
        }
    }.less);
    for (observed.members) |member| {
        const child = try std.fmt.allocPrint(tree.allocator, "{s}/{s}", .{ path, member.name });
        try tree.charge(child.len);
        try captureTree(tree, root, child, depth + 1);
    }
    _ = try pin.metadata();
}

fn captureIdentity(allocator: std.mem.Allocator, root: root_fs.Root, allow_unreadable_exclusions: bool) !struct { bytes: []const u8, digest: [64]u8, directories: []const DirectoryIdentity, read_refusal: ?anyerror } {
    var tree: Tree = .{ .allocator = allocator, .allow_unreadable_exclusions = allow_unreadable_exclusions };
    tree.hash.update("debz installed database no-op prestate v1\x00");
    try captureTree(&tree, root, "var/lib/dpkg", 0);
    const bytes = tree.status_bytes orelse return error.InstalledBaselineStatusMissing;
    return .{ .bytes = bytes, .digest = tree.hash.finalResult(), .directories = try tree.directories.toOwnedSlice(allocator), .read_refusal = tree.read_refusal };
}

fn make(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_path: []const u8,
    architecture: []const u8,
    expected_status: ?[]const u8,
    packages: []const Package,
    allow_unreadable_exclusions: bool,
) !*Data {
    if (packages.len == 0 or packages.len > 100_000) return error.InvalidInstalledBaseline;
    var root = try root_fs.openAbsoluteRoot(io, root_path);
    defer root.close();
    const root_entry = try root.root.rootEntry();
    try requireOwned(root.root, root_entry);
    var arena: std.heap.ArenaAllocator = .init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    const first = try captureIdentity(owned, root.root, allow_unreadable_exclusions);
    if (expected_status) |expected| {
        if (!std.mem.eql(u8, first.bytes, expected)) return error.InstalledBaselineChanged;
    }
    var check_arena: std.heap.ArenaAllocator = .init(allocator);
    defer check_arena.deinit();
    const second = try captureIdentity(check_arena.allocator(), root.root, allow_unreadable_exclusions);
    if (!std.mem.eql(u8, &first.digest, &second.digest)) return error.InstalledBaselineChanged;
    var database = switch (try status.parseBorrowed(owned, first.bytes, .{})) {
        .database => |value| value,
        .diagnostic => return error.InvalidInstalledBaseline,
    };
    defer database.deinit();
    if (database.packages.len > 100_000) return error.InstalledBaselineLimitExceeded;
    var installed_index: std.StringHashMap(*const status.Package) = .init(owned);
    defer installed_index.deinit();
    for (database.packages) |*package| {
        const key = try std.fmt.allocPrint(owned, "{s}\x00{s}", .{ package.name.value, package.architecture.value });
        const slot = try installed_index.getOrPut(key);
        if (slot.found_existing) return error.InvalidInstalledBaseline;
        slot.value_ptr.* = package;
    }
    const saved = try owned.dupe(Package, packages);
    std.mem.sort(Package, saved, {}, lessThan);
    for (saved, 0..) |*destination, index| {
        const package = destination.*;
        if (index != 0 and !lessThan({}, saved[index - 1], package))
            return error.InvalidInstalledBaseline;
        const key = try std.fmt.allocPrint(owned, "{s}\x00{s}", .{ package.name, package.architecture });
        const installed = installed_index.get(key) orelse
            return error.InstalledBaselineChanged;
        if (!installed.status.isFullyInstalled() or
            (installed.status.want != .install and installed.status.want != .hold) or
            installed.status.want != package.selection or
            !std.mem.eql(u8, installed.version.spelling.value, package.version))
            return error.InstalledBaselineChanged;
        destination.* = .{
            .name = try owned.dupe(u8, package.name),
            .version = try owned.dupe(u8, package.version),
            .architecture = try owned.dupe(u8, package.architecture),
            .selection = package.selection,
        };
    }
    const value: Evidence = .{
        .root_path = try owned.dupe(u8, root_path),
        .root_device = root_entry.device,
        .root_inode = root_entry.inode,
        .root_uid = root_entry.uid,
        .root_gid = root_entry.gid,
        .root_mode = root_entry.mode,
        .native_architecture = try owned.dupe(u8, architecture),
        .database_identity = .{ .value = try owned.dupe(u8, &std.fmt.bytesToHex(first.digest, .lower)) },
        .packages = saved,
    };
    const data = try allocator.create(Data);
    data.* = .{ .allocator = allocator, .arena = arena, .value = value, .directories = first.directories, .read_refusal = first.read_refusal };
    return data;
}

pub fn lessThan(_: void, left: Package, right: Package) bool {
    const order = std.mem.order(u8, left.name, right.name);
    return if (order == .eq) std.mem.lessThan(u8, left.architecture, right.architecture) else order == .lt;
}

pub fn capture(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_path: []const u8,
    architecture: []const u8,
    expected_status: []const u8,
    packages: []const Package,
) !*Verified {
    return @ptrCast(try make(allocator, io, root_path, architecture, expected_status, packages, false));
}

pub fn captureDownloadPrestate(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_path: []const u8,
    architecture: []const u8,
    expected_status: []const u8,
    packages: []const Package,
) !DownloadPrestate {
    const data = try make(allocator, io, root_path, architecture, expected_status, packages, true);
    if (data.read_refusal != null) return .{ .unavailable = @ptrCast(data) };
    return .{ .verified = @ptrCast(data) };
}

fn requireSamePrestate(actual: Evidence, evidence: Evidence) !void {
    if (actual.root_device != evidence.root_device or actual.root_inode != evidence.root_inode or
        actual.root_uid != evidence.root_uid or actual.root_gid != evidence.root_gid or actual.root_mode != evidence.root_mode or
        !std.mem.eql(u8, actual.database_identity.value, evidence.database_identity.value))
        return error.InstalledBaselineChanged;
}

pub fn verify(
    allocator: std.mem.Allocator,
    io: std.Io,
    root_path: []const u8,
    architecture: []const u8,
    expected_status: []const u8,
    evidence: Evidence,
) !*Verified {
    if (!std.mem.eql(u8, root_path, evidence.root_path) or
        !std.mem.eql(u8, architecture, evidence.native_architecture))
        return error.InstalledBaselineRootMismatch;
    const result: *Verified = @ptrCast(try make(allocator, io, root_path, architecture, expected_status, evidence.packages, false));
    errdefer result.deinit();
    const actual = result.evidence();
    try requireSamePrestate(actual, evidence);
    return result;
}
