const std = @import("std");
const package_database = @import("package_database.zig");
const root_fs = @import("root_fs.zig");

pub const maximum_identity_bytes = 4 * 1024 * 1024;
pub const passwd_path = "etc/passwd";
pub const group_path = "etc/group";
pub const database_path = package_database.database_directory ++ "/" ++ package_database.statoverride_path;
pub const passwd_key = "statoverride-passwd";
pub const group_key = "statoverride-group";

pub const IdentityFile = struct {
    path: []const u8,
    bytes: []const u8,
    mode: u32,
};

pub const Metadata = struct {
    mode: u32,
    uid: u32,
    gid: u32,
};

/// Storage belongs to the caller's arena; no host account lookup is permitted.
pub const Resolved = struct {
    paths: std.StringHashMapUnmanaged(Metadata) = .empty,
    observed_paths: []const []const u8 = &.{},
    identity_files: []const IdentityFile = &.{},

    pub fn get(self: Resolved, archive_path: []const u8) ?Metadata {
        return self.paths.get(archive_path);
    }
};

const Accounts = std.StringHashMapUnmanaged(u32);

fn numericId(value: []const u8) !u32 {
    if (value.len == 0) return error.InvalidStatOverrideIdentity;
    for (value) |byte|
        if (!std.ascii.isDigit(byte)) return error.InvalidStatOverrideIdentity;
    const result = std.fmt.parseUnsigned(u32, value, 10) catch
        return error.InvalidStatOverrideIdentity;
    if (result == std.math.maxInt(u32)) return error.InvalidStatOverrideIdentity;
    return result;
}

fn accounts(allocator: std.mem.Allocator, bytes: ?[]const u8) !Accounts {
    var result: Accounts = .empty;
    const source = bytes orelse return result;
    if (source.len > maximum_identity_bytes) return error.StatOverrideIdentityLimit;
    var lines = std.mem.splitScalar(u8, source, '\n');
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        if (std.mem.indexOfScalar(u8, line, 0) != null or
            std.mem.indexOfScalar(u8, line, '\r') != null)
            return error.InvalidStatOverrideIdentity;
        var fields = std.mem.splitScalar(u8, line, ':');
        const name = fields.next().?;
        _ = fields.next() orelse return error.InvalidStatOverrideIdentity;
        const id_text = fields.next() orelse return error.InvalidStatOverrideIdentity;
        if (name.len == 0 or name.len > 255) return error.InvalidStatOverrideIdentity;
        const id = try numericId(id_text);
        const entry = try result.getOrPut(allocator, name);
        if (entry.found_existing) return error.AmbiguousStatOverrideIdentity;
        entry.value_ptr.* = id;
    }
    return result;
}

fn identity(value: []const u8, names: Accounts) !u32 {
    if (std.mem.startsWith(u8, value, "#")) return numericId(value[1..]);
    return names.get(value) orelse error.UnknownStatOverrideIdentity;
}

pub fn resolve(
    allocator: std.mem.Allocator,
    records: []const package_database.StatOverrideRecord,
    passwd: ?[]const u8,
    group: ?[]const u8,
) !Resolved {
    if (records.len > (package_database.Limits{}).max_stat_overrides)
        return error.StatOverrideIdentityLimit;
    var needs_users = false;
    var needs_groups = false;
    for (records) |record| {
        needs_users = needs_users or !std.mem.startsWith(u8, record.user, "#");
        needs_groups = needs_groups or !std.mem.startsWith(u8, record.group, "#");
    }
    const users = try accounts(allocator, if (needs_users) passwd else null);
    const groups = try accounts(allocator, if (needs_groups) group else null);
    var result: Resolved = .{};
    const observed = try allocator.alloc(
        []const u8,
        @as(usize, @intFromBool(records.len != 0)) + @intFromBool(needs_users) + @intFromBool(needs_groups),
    );
    var index: usize = 0;
    if (records.len != 0) {
        observed[index] = database_path;
        index += 1;
    }
    if (needs_users) {
        observed[index] = passwd_path;
        index += 1;
    }
    if (needs_groups) observed[index] = group_path;
    result.observed_paths = observed;
    for (records) |record| {
        if (record.path.len < 2 or record.path[0] != '/' or record.mode > 0o7777)
            return error.InvalidStatOverrideIdentity;
        _ = try root_fs.Path.initPackage(record.path[1..]);
        const entry = try result.paths.getOrPut(allocator, record.path[1..]);
        if (entry.found_existing) return error.InvalidStatOverrideIdentity;
        entry.value_ptr.* = .{
            .mode = record.mode,
            .uid = try identity(record.user, users),
            .gid = try identity(record.group, groups),
        };
    }
    return result;
}

pub fn read(
    allocator: std.mem.Allocator,
    root: root_fs.Root,
    records: []const package_database.StatOverrideRecord,
) !Resolved {
    var needs_users = false;
    var needs_groups = false;
    for (records) |record| {
        needs_users = needs_users or !std.mem.startsWith(u8, record.user, "#");
        needs_groups = needs_groups or !std.mem.startsWith(u8, record.group, "#");
    }
    const passwd = if (needs_users)
        try root.readFileAlloc(allocator, try root_fs.Path.init(passwd_path), maximum_identity_bytes)
    else
        null;
    const group = if (needs_groups)
        try root.readFileAlloc(allocator, try root_fs.Path.init(group_path), maximum_identity_bytes)
    else
        null;
    var result = try resolve(allocator, records, passwd, group);
    const files = try allocator.alloc(IdentityFile, @as(usize, @intFromBool(needs_users)) + @intFromBool(needs_groups));
    var index: usize = 0;
    if (passwd) |bytes| {
        files[index] = .{
            .path = passwd_path,
            .bytes = bytes,
            .mode = (try root.entry(try root_fs.Path.init(passwd_path))).mode,
        };
        index += 1;
    }
    if (group) |bytes| {
        files[index] = .{
            .path = group_path,
            .bytes = bytes,
            .mode = (try root.entry(try root_fs.Path.init(group_path))).mode,
        };
    }
    result.identity_files = files;
    return result;
}
