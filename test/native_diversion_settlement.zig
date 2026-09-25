const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const lifecycle = @import("native_lifecycle_support.zig");
const root_fs = @import("debz").root_fs;
const options = @import("native_test_options");
const builtin = @import("builtin");

const package = "diversion-lifecycle";
const watcher = "diversion-watcher";
const base = "usr/share/" ++ package;
const config = "etc/debz-native.conf";
const literal = "etc/diversion\\literal";
const epoch_ns = foundation.epoch * std.time.ns_per_s;

const Case = struct { update: []const u8, member: []const u8 };
const cases = [_]Case{
    .{ .update = "atomic", .member = "regular" },
    .{ .update = "unchanged", .member = "regular" },
    .{ .update = "inplace", .member = "regular" },
    .{ .update = "create", .member = "regular" },
    .{ .update = "empty", .member = "regular" },
    .{ .update = "remove", .member = "regular" },
    .{ .update = "cached-activation", .member = "regular" },
    .{ .update = "exempt", .member = "regular" },
    .{ .update = "atomic", .member = "symlink" },
    .{ .update = "atomic", .member = "hardlink-source" },
    .{ .update = "atomic", .member = "hardlink-member" },
    .{ .update = "atomic", .member = "conffile" },
    .{ .update = "atomic", .member = "directory" },
    .{ .update = "unwind-success", .member = "regular" },
    .{ .update = "rollback", .member = "regular" },
    .{ .update = "rollback", .member = "symlink" },
    .{ .update = "rollback", .member = "hardlink-source" },
    .{ .update = "postinst-failure", .member = "regular" },
    .{ .update = "atomic", .member = "obsolete" },
    .{ .update = "rollback", .member = "obsolete" },
    .{ .update = "atomic", .member = "introduced" },
    .{ .update = "rollback", .member = "introduced" },
    .{ .update = "rollback", .member = "conffile" },
    .{ .update = "postinst-failure", .member = "conffile" },
};

fn eq(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, left, right);
}

fn fail(label: []const u8) error{SettlementMismatch} {
    last_failure = label;
    if (!builtin.is_test) std.debug.print("diversion settlement: {s}\n", .{label});
    return error.SettlementMismatch;
}

var last_failure: []const u8 = "";

fn check(ok: bool, label: []const u8) !void {
    if (!ok) return fail(label);
}

fn memberPath(member: []const u8) []const u8 {
    if (eq(member, "regular")) return base ++ "/mode";
    if (eq(member, "symlink")) return base ++ "/current";
    if (eq(member, "hardlink-source")) return base ++ "/data";
    if (eq(member, "hardlink-member")) return base ++ "/data.link";
    if (eq(member, "conffile")) return config;
    if (eq(member, "directory")) return base;
    if (eq(member, "obsolete")) return base ++ "/obsolete";
    if (eq(member, "introduced")) return base ++ "/introduced";
    unreachable;
}

fn succeeds(c: Case) bool {
    return !eq(c.update, "rollback") and !eq(c.update, "postinst-failure");
}

fn route(allocator: std.mem.Allocator, update: []const u8, source: []const u8) ![]const u8 {
    if (eq(update, "unchanged")) return std.fmt.allocPrint(allocator, "{s}.original", .{source});
    if (eq(update, "empty") or eq(update, "remove") or eq(update, "exempt"))
        return allocator.dupe(u8, source);
    return std.fmt.allocPrint(allocator, "{s}.changed", .{source});
}

const Entry = struct {
    path: []const u8,
    kind: []const u8,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime_ns: ?i128 = null,
    size: ?u64 = null,
    sha256: ?[]const u8 = null,
    target: ?[]const u8 = null,
    hardlink_to: ?[]const u8 = null,
    xattrs: []const std.json.Value = &.{},
};

const Snapshot = struct {
    filesystem: []Entry,
    dpkg: std.json.Value,
    trace: []const []const u8,

    fn find(self: Snapshot, path: []const u8) ?*Entry {
        for (self.filesystem) |*row| if (eq(row.path, path)) return row;
        return null;
    }
};

const Capture = struct {
    bytes: []u8,
    data: std.json.Parsed(Snapshot),

    fn deinit(self: *Capture, allocator: std.mem.Allocator) void {
        self.data.deinit();
        allocator.free(self.bytes);
    }
};

fn capture(a: std.mem.Allocator, io: std.Io, root: []const u8) !Capture {
    const bytes = try foundation.captureRealRoot(a, io, root, .{}, &.{
        foundation.guard, "usr/bin/dpkg-trigger", lifecycle.trace,
    });
    errdefer a.free(bytes);
    return .{ .bytes = bytes, .data = try std.json.parseFromSlice(Snapshot, a, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    }) };
}

const Identity = struct { device: u64, inode: u64 };
const Diversion = struct { identity: Identity, bytes: []u8 };

fn inode(f: *foundation.Fixture, root: []const u8, relative: []const u8) !Identity {
    var dir = try foundation.guardedRoot(f.io, root);
    defer dir.close(f.io);
    const fs: root_fs.Root = .init(f.io, dir);
    const row = try fs.entry(try root_fs.Path.initPackage(relative));
    return .{ .device = row.device, .inode = row.inode };
}

fn diversion(f: *foundation.Fixture, root: []const u8) !?Diversion {
    const relative = try std.fmt.allocPrint(f.allocator, "{s}/var/lib/dpkg/diversions", .{root[f.path.len + 1 ..]});
    defer f.allocator.free(relative);
    if (f.dir.statFile(f.io, relative, .{ .follow_symlinks = false })) |row| {
        if (row.kind != .file) return error.UnsafeDiversionDatabase;
    } else |err| {
        if (err == error.FileNotFound) return null;
        return err;
    }
    return .{ .identity = try inode(f, root, "var/lib/dpkg/diversions"), .bytes = try lifecycle.read(f, relative, 65536) };
}

fn verifyDiversion(c: Case, before: ?Diversion, after: ?Diversion, reinstall: bool) !void {
    const source = memberPath(c.member);
    try check((before == null) == (if (reinstall) eq(c.update, "remove") else eq(c.update, "create")), "pre-invocation diversion presence");
    if (eq(c.update, "remove")) {
        try check(after == null, "removed diversion database");
        return;
    }
    const current = after orelse return fail("missing live diversion database");
    const desired = if (eq(c.update, "empty"))
        ""
    else blk: {
        const suffix = if (eq(c.update, "unchanged") or eq(c.update, "exempt")) ".original" else ".changed";
        const owner = if (eq(c.update, "exempt")) package else ":";
        break :blk try std.fmt.allocPrint(std.heap.page_allocator, "/{s}\n/{s}{s}\n{s}\n", .{ source, source, suffix, owner });
    };
    defer if (!eq(c.update, "empty")) std.heap.page_allocator.free(desired);
    try check(eq(current.bytes, desired), "live diversion bytes");
    if (before != null)
        try check((before.?.identity.device == current.identity.device and before.?.identity.inode == current.identity.inode) == (reinstall or eq(c.update, "inplace")), "diversion database identity");
}

fn contentFor(path: []const u8, version: []const u8) ?[]const u8 {
    if (eq(path, base ++ "/mode")) return "permission-sensitive payload\n";
    if (eq(path, base ++ "/data") or eq(path, base ++ "/data.link"))
        return if (eq(version, "1")) "data version 1\n" else "data version 2\n";
    if (eq(path, base ++ "/obsolete")) return "only in 1\n";
    if (eq(path, base ++ "/introduced")) return "only in 2\n";
    if (eq(path, config)) return if (eq(version, "1")) "configuration 1\n" else "configuration 2\n";
    if (eq(path, literal)) return if (eq(version, "1")) "literal version 1\n" else "literal version 2\n";
    return null;
}

fn payloadRow(path: []const u8, version: []const u8) Entry {
    const directory = eq(path, base) or eq(path, base ++ "/empty");
    const symbolic = eq(path, base ++ "/current");
    const mode: u32 = if (directory) (if (eq(path, base)) 0o755 else 0o750) else if (symbolic) 0o777 else if (eq(path, base ++ "/mode")) (if (eq(version, "1")) 0o600 else 0o640) else 0o644;
    const content = contentFor(path, version);
    return .{ .path = path, .kind = if (directory) "directory" else if (symbolic) "symlink" else "regular", .mode = mode, .uid = 0, .gid = 0, .mtime_ns = if (directory) null else epoch_ns, .size = if (content) |text| text.len else null, .target = if (symbolic) "data" else null };
}

fn verifyPayload(actual: *const Entry, path: []const u8, version: []const u8, clock: bool, start: i128, finish: i128) !void {
    const want = payloadRow(path, version);
    try check(eq(actual.kind, want.kind) and actual.mode == want.mode and actual.uid == 0 and actual.gid == 0 and actual.xattrs.len == 0, "payload kind/mode/owner/xattrs");
    if (actual.size != want.size or
        ((actual.target == null) != (want.target == null)) or
        (actual.target != null and !eq(actual.target.?, want.target.?)))
    {
        if (!builtin.is_test) std.debug.print("{s}: size {any} expected {any}, target {s} expected {s}\n", .{
            actual.path, actual.size, want.size, actual.target orelse "<absent>", want.target orelse "<absent>",
        });
        return fail("payload size/link target");
    }
    if (contentFor(path, version)) |text| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(text, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        try check(actual.sha256 != null and eq(actual.sha256.?, &hex), "payload SHA256");
    } else try check(actual.sha256 == null, "unexpected payload digest");
    if (clock) {
        try check(actual.mtime_ns != null and actual.mtime_ns.? >= start and actual.mtime_ns.? <= finish, "recreated symlink invocation clock");
    } else try check(actual.mtime_ns == want.mtime_ns, "payload mtime");
}

fn require(snapshot: Snapshot, path: []const u8) !*Entry {
    return snapshot.find(path) orelse {
        if (!builtin.is_test) std.debug.print("missing settlement path: {s}\n", .{path});
        return fail("missing settlement path");
    };
}

fn expectedFiles(a: std.mem.Allocator, snapshot: Snapshot, c: Case, upgrade: bool, start: i128, finish: i128) !void {
    const source = memberPath(c.member);
    const original = if (eq(c.update, "create")) source else try std.fmt.allocPrint(a, "{s}.original", .{source});
    const version: []const u8 = if (upgrade and eq(c.update, "rollback")) "1" else "2";
    const baseline = [_][]const u8{ base, base ++ "/empty", base ++ "/data", base ++ "/data.link", base ++ "/mode", base ++ "/current", config, literal };
    var expected: std.StringHashMap(void) = .init(a);
    defer expected.deinit();
    for (baseline) |path| {
        const selected = if (eq(path, source) and !eq(c.member, "directory")) original else path;
        try expected.put(selected, {});
        const value_version: []const u8 = if (eq(path, source) and (eq(c.member, "conffile") or eq(c.member, "obsolete"))) "1" else if (upgrade and eq(c.update, "rollback") and eq(path, source)) "2" else version;
        const clock = upgrade and eq(c.update, "rollback") and !eq(c.member, "symlink") and eq(path, base ++ "/current");
        try verifyPayload(try require(snapshot, selected), path, value_version, clock, start, finish);
    }
    const changing = if (eq(version, "1")) base ++ "/obsolete" else base ++ "/introduced";
    if (eq(changing, source) and !eq(c.member, "directory")) {
        try expected.put(original, {});
        try verifyPayload(try require(snapshot, original), source, if (eq(c.member, "obsolete")) "1" else "2", false, start, finish);
    } else {
        try expected.put(changing, {});
        try verifyPayload(try require(snapshot, changing), changing, version, false, start, finish);
    }
    if (eq(c.member, "obsolete") or (eq(c.member, "introduced") and eq(version, "1"))) {
        try expected.put(original, {});
        try verifyPayload(try require(snapshot, original), source, if (eq(c.member, "obsolete")) "1" else "2", false, start, finish);
    }
    if (eq(c.member, "directory")) {
        try expected.put(original, {});
        try verifyPayload(try require(snapshot, original), source, "1", false, start, finish);
    }
    if (eq(c.member, "conffile")) {
        const staged = try std.fmt.allocPrint(a, "{s}.dpkg-new", .{original});
        try expected.put(staged, {});
        try verifyPayload(try require(snapshot, staged), source, "2", false, start, finish);
    }
    const backup_member = eq(c.member, "regular") or eq(c.member, "symlink") or std.mem.startsWith(u8, c.member, "hardlink-");
    if (backup_member and !eq(c.update, "unchanged") and !eq(c.update, "inplace")) {
        const backup = try std.fmt.allocPrint(a, "{s}.dpkg-tmp", .{original});
        try expected.put(backup, {});
        try verifyPayload(try require(snapshot, backup), source, "1", eq(c.member, "symlink"), start, finish);
    }
    if (!upgrade) {
        const current = try route(a, c.update, source);
        if (eq(c.member, "conffile")) {
            const dist = try std.fmt.allocPrint(a, "{s}.dpkg-dist", .{current});
            try expected.put(dist, {});
            try verifyPayload(try require(snapshot, dist), source, "2", false, start, finish);
        } else if (!eq(c.member, "obsolete")) {
            try expected.put(current, {});
            try verifyPayload(try require(snapshot, current), source, "2", false, start, finish);
        }
    }
    var seen: usize = 0;
    for (snapshot.filesystem) |row| {
        if (eq(row.path, base) or std.mem.startsWith(u8, row.path, base ++ "/") or
            std.mem.startsWith(u8, row.path, base ++ ".") or eq(row.path, config) or
            std.mem.startsWith(u8, row.path, config ++ ".") or eq(row.path, literal))
        {
            seen += 1;
            if (!expected.contains(row.path)) {
                if (!builtin.is_test) std.debug.print("unexpected settlement path: {s}\n", .{row.path});
                return fail("unexpected settlement path");
            }
        }
    }
    try check(seen == expected.count(), "settled filesystem member count");
    const link_a = if (eq(c.member, "hardlink-source")) (if (upgrade and eq(c.update, "rollback")) try std.fmt.allocPrint(a, "{s}.dpkg-tmp", .{original}) else if (upgrade) original else try route(a, c.update, source)) else base ++ "/data";
    const link_b = if (eq(c.member, "hardlink-member")) (if (upgrade) original else try route(a, c.update, source)) else base ++ "/data.link";
    const first = if (std.mem.lessThan(u8, link_a, link_b)) link_a else link_b;
    for (snapshot.filesystem) |row| {
        if (!expected.contains(row.path)) continue;
        const linked = eq(row.path, link_a) or eq(row.path, link_b);
        try check(if (linked) row.hardlink_to != null and eq(row.hardlink_to.?, first) else row.hardlink_to == null, "settled hardlink group");
    }
}

const Call = struct { identity: []const u8, args: []const []const u8 };

fn expectedCalls(a: std.mem.Allocator, c: Case, reinstall: bool) ![]const Call {
    const old: []const u8 = if (reinstall) "2" else "1";
    var list: std.ArrayList(Call) = .empty;
    try list.appendSlice(a, &.{
        .{ .identity = try std.fmt.allocPrint(a, "{s}@{s}:prerm", .{ package, old }), .args = &.{ "upgrade", "2" } },
        .{ .identity = package ++ "@2:preinst", .args = &.{ "upgrade", old, "2" } },
        .{ .identity = try std.fmt.allocPrint(a, "{s}@{s}:postrm", .{ package, old }), .args = &.{ "upgrade", "2" } },
    });
    if (!reinstall and (eq(c.update, "rollback") or eq(c.update, "unwind-success")))
        try list.append(a, .{ .identity = package ++ "@2:postrm", .args = &.{ "failed-upgrade", "1", "2" } });
    if (!reinstall and eq(c.update, "rollback")) try list.appendSlice(a, &.{
        .{ .identity = package ++ "@1:preinst", .args = &.{ "abort-upgrade", "2" } },
        .{ .identity = package ++ "@2:postrm", .args = &.{ "abort-upgrade", "1", "2" } },
        .{ .identity = package ++ "@1:postinst", .args = &.{ "abort-upgrade", "2" } },
    }) else try list.append(a, .{ .identity = package ++ "@2:postinst", .args = &.{ "configure", old } });
    if (!eq(c.member, "obsolete")) {
        const source = memberPath(c.member);
        const diverted = if (reinstall)
            try route(a, c.update, source)
        else if (eq(c.update, "create"))
            source
        else
            try std.fmt.allocPrint(a, "{s}.original", .{source});
        const path = if (eq(c.member, "directory") and !reinstall)
            try std.fmt.allocPrint(a, "/{s} /{s}", .{ source, diverted })
        else
            try std.fmt.allocPrint(a, "/{s}", .{diverted});
        try list.append(a, .{ .identity = watcher ++ "@1:postinst", .args = &.{ "triggered", path } });
    }
    for (list.items) |*call| call.args = try a.dupe([]const u8, call.args);
    return list.items;
}

fn scriptLines(a: std.mem.Allocator, trace: []const u8, arch: []const u8, expected: []const Call) ![]const []const u8 {
    var observed: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, trace, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "backup-stat:")) continue;
        try observed.append(a, line);
    }
    try check(observed.items.len == expected.len, "script and trigger call count");
    for (observed.items, expected) |line, call| {
        var fields = std.mem.splitScalar(u8, line, '\t');
        const identity = fields.next() orelse return fail("missing script identity");
        const pkg = fields.next() orelse return fail("missing script package");
        const kind = fields.next() orelse return fail("missing script kind");
        const architecture = fields.next() orelse return fail("missing script architecture");
        const count_text = fields.next() orelse return fail("missing script argc");
        try check(eq(identity, call.identity), "script order and trigger routes");
        const at = std.mem.indexOfScalar(u8, identity, '@') orelse return fail("invalid script identity");
        const colon = std.mem.lastIndexOfScalar(u8, identity, ':') orelse return fail("invalid script kind");
        try check(eq(pkg, identity[0..at]) and eq(kind, identity[colon + 1 ..]) and eq(architecture, arch), "script identity/environment");
        try check((std.fmt.parseInt(usize, count_text, 10) catch return fail("invalid script argc")) == call.args.len, "script argument count");
        for (call.args) |argument| {
            const field = fields.next() orelse return fail("missing script argument");
            const separator = std.mem.indexOfScalar(u8, field, ':') orelse return fail("missing script argument length");
            const length = std.fmt.parseInt(usize, field[0..separator], 10) catch return fail("invalid script argument length");
            try check(length == field[separator + 1 ..].len and eq(field[separator + 1 ..], argument), "script argument bytes/length");
        }
        const payload = fields.next() orelse return fail("missing script payload");
        try check(std.mem.startsWith(u8, payload, "payload=") and fields.next() == null, "script trace width/payload");
    }
    return observed.items;
}

const Backup = struct { mode: u32, uid: u32, gid: u32, seconds: i128, inode: u64 };

fn backupLine(line: []const u8) !struct { path: []const u8, value: Backup } {
    var fields = std.mem.splitScalar(u8, line, ':');
    if (!eq(fields.next() orelse "", "backup-stat")) return fail("invalid backup prefix");
    const path = fields.next() orelse return fail("missing backup path");
    const mode = std.fmt.parseInt(u32, fields.next() orelse return fail("missing backup mode"), 8) catch return fail("invalid backup mode");
    const uid = std.fmt.parseInt(u32, fields.next() orelse return fail("missing backup uid"), 10) catch return fail("invalid backup uid");
    const gid = std.fmt.parseInt(u32, fields.next() orelse return fail("missing backup gid"), 10) catch return fail("invalid backup gid");
    const seconds = std.fmt.parseInt(i128, fields.next() orelse return fail("missing backup timestamp"), 10) catch return fail("invalid backup timestamp");
    const number = std.fmt.parseInt(u64, fields.next() orelse return fail("missing backup inode"), 10) catch return fail("invalid backup inode");
    try check(fields.next() == null, "backup trace width");
    return .{ .path = path, .value = .{ .mode = mode, .uid = uid, .gid = gid, .seconds = seconds, .inode = number } };
}

fn verifyBackups(
    a: std.mem.Allocator,
    c: Case,
    trace: []const u8,
    before: Snapshot,
    prior: *const std.StringHashMap(Identity),
    start: i128,
    finish: i128,
) !void {
    var backups: std.StringHashMap(Backup) = .init(a);
    defer backups.deinit();
    var immediate = false;
    var found = false;
    var lines = std.mem.splitScalar(u8, trace, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, package ++ "@1:postrm\t")) {
            immediate = true;
            found = true;
            continue;
        }
        if (found and !immediate) break;
        if (std.mem.startsWith(u8, line, "backup-stat:")) {
            const stat = try backupLine(line);
            try check(!backups.contains(stat.path), "duplicate visible backup");
            try backups.put(stat.path, stat.value);
        } else if (immediate) break;
    }
    try check(found, "missing old postrm backup probe");
    const members = [_][]const u8{ base ++ "/data", base ++ "/data.link", base ++ "/mode", base ++ "/current", literal };
    try check(backups.count() == members.len, "old postrm visible backups");
    for (members) |path| {
        const redirected = if (eq(memberPath(c.member), path) and !eq(c.update, "create"))
            try std.fmt.allocPrint(a, "{s}.original", .{path})
        else
            path;
        const before_row = try require(before, redirected);
        const visible = try std.fmt.allocPrint(a, "/{s}.dpkg-tmp", .{redirected});
        const value = backups.get(visible) orelse return fail("missing old postrm visible backup");
        try check(value.mode == before_row.mode and value.uid == before_row.uid and value.gid == before_row.gid, "old postrm backup metadata");
        const identity = prior.get(redirected) orelse return fail("missing pre-invocation backup identity");
        if (eq(before_row.kind, "symlink")) {
            try check(value.seconds >= @divTrunc(start, std.time.ns_per_s) and value.seconds <= @divTrunc(finish, std.time.ns_per_s), "visible symlink backup timestamp");
            try check(value.inode != identity.inode, "visible symlink backup was not recreated");
        } else {
            try check(value.seconds == foundation.epoch, "regular backup timestamp");
            try check(value.inode == identity.inode, "regular backup inode");
        }
    }
}

fn verifyDatabase(f: *foundation.Fixture, c: Case, root: []const u8, version: []const u8, controls: [2][]const u8, reinstall: bool) !void {
    const relative = root[f.path.len + 1 ..];
    const status_path = try std.fmt.allocPrint(f.allocator, "{s}/var/lib/dpkg/status", .{relative});
    defer f.allocator.free(status_path);
    const status = try lifecycle.read(f, status_path, 1024 * 1024);
    defer f.allocator.free(status);
    var records = std.mem.splitSequence(u8, status, "\n\n");
    var match: ?[]const u8 = null;
    var count: usize = 0;
    while (records.next()) |record| {
        if (std.mem.startsWith(u8, record, "Package: " ++ package ++ "\n")) {
            match = record;
            count += 1;
        }
    }
    try check(count == 1, "settled package status count");
    const record = match.?;
    const desired_status = if (eq(c.update, "postinst-failure")) "install ok half-configured" else "install ok installed";
    const conf_version: []const u8 = if (eq(version, "1") or (eq(c.member, "conffile") and !reinstall)) "1" else "2";
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash(contentFor(config, conf_version).?, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const conf = try std.fmt.allocPrint(f.allocator, "Conffiles:\n /{s} {s}", .{ config, hex });
    defer f.allocator.free(conf);
    try check(std.mem.indexOf(u8, record, try std.fmt.allocPrint(f.allocator, "Version: {s}\n", .{version})) != null, "settled package version");
    try check(std.mem.indexOf(u8, record, try std.fmt.allocPrint(f.allocator, "Status: {s}\n", .{desired_status})) != null, "settled package status");
    try check(std.mem.indexOf(u8, record, conf) != null, "recorded conffile digest");
    const list_path = try std.fmt.allocPrint(f.allocator, "{s}/var/lib/dpkg/info/{s}.list", .{ relative, package });
    defer f.allocator.free(list_path);
    const list = try lifecycle.read(f, list_path, 65536);
    defer f.allocator.free(list);
    var expected: std.ArrayList([]const u8) = .empty;
    defer expected.deinit(f.allocator);
    try expected.appendSlice(f.allocator, &.{ "/.", "/etc", "/usr", "/usr/share", "/" ++ base, "/" ++ base ++ "/empty", "/" ++ base ++ "/data", "/" ++ base ++ "/data.link", "/" ++ base ++ "/mode", "/" ++ base ++ "/current", "/" ++ config, "/" ++ literal, if (eq(version, "1")) "/" ++ base ++ "/obsolete" else "/" ++ base ++ "/introduced" });
    var found: std.ArrayList([]const u8) = .empty;
    defer found.deinit(f.allocator);
    var split = std.mem.splitScalar(u8, list, '\n');
    while (split.next()) |line| if (line.len != 0) try found.append(f.allocator, line);
    const less = struct {
        fn compare(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.compare;
    std.mem.sort([]const u8, expected.items, {}, less);
    std.mem.sort([]const u8, found.items, {}, less);
    try check(found.items.len == expected.items.len, "logical installed file list count");
    for (found.items, expected.items) |left, right| try check(eq(left, right), "logical installed file list");
    for ([_][]const u8{ "preinst", "postinst", "prerm", "postrm", "md5sums", "conffiles" }) |kind| {
        const origin = try std.fmt.allocPrint(f.allocator, "{s}/DEBIAN/{s}", .{ if (eq(version, "1")) controls[0] else controls[1], kind });
        defer f.allocator.free(origin);
        const installed = try std.fmt.allocPrint(f.allocator, "{s}/var/lib/dpkg/info/{s}.{s}", .{ relative, package, kind });
        defer f.allocator.free(installed);
        const want = try lifecycle.read(f, origin, 65536);
        defer f.allocator.free(want);
        const have = try lifecycle.read(f, installed, 65536);
        defer f.allocator.free(have);
        try check(eq(want, have), "installed control bytes");
    }
}

fn normalized(a: std.mem.Allocator, snapshot: Snapshot, start: i128, finish: i128) ![]u8 {
    var image = snapshot;
    for (image.filesystem) |*row| {
        if (eq(row.kind, "symlink") and row.mtime_ns != epoch_ns) {
            try check(row.mtime_ns != null and row.mtime_ns.? >= start and row.mtime_ns.? <= finish, "dynamic symlink mtime outside invocation clock");
            row.mtime_ns = 0;
        }
    }
    image.trace = &.{};
    return std.json.Stringify.valueAlloc(a, image, .{});
}

fn makePackage(f: *foundation.Fixture, arch: []const u8, version: []const u8) ![]u8 {
    const extra = [_]foundation.Fixture.ExtraFile{.{
        .path = literal,
        .content = if (eq(version, "1")) "literal version 1\n" else "literal version 2\n",
    }};
    const archive = try f.makePackageWith(arch, version, .conffile, .{
        .workspace = "packages",
        .name = package,
        .conffile_content = if (eq(version, "1")) "configuration 1\n" else "configuration 2\n",
        .extra_files = &extra,
    });
    const source = try std.fmt.allocPrint(f.allocator, "packages/{s}_{s}_conffile.source", .{ package, version });
    defer f.allocator.free(source);
    try lifecycle.scripts(f, source, package, version);
    var probes: std.ArrayList(u8) = .empty;
    defer probes.deinit(f.allocator);
    const paths = [_][]const u8{
        base ++ "/mode", base ++ "/current", base ++ "/data",     base ++ "/data.link",
        config,          base,               base ++ "/obsolete", base ++ "/introduced",
        literal,
    };
    for (paths) |path| for ([_][]const u8{ "", ".original", ".changed" }) |suffix| {
        const word = try std.fmt.allocPrint(f.allocator, " '/{s}{s}.dpkg-tmp'", .{ path, suffix });
        defer f.allocator.free(word);
        try probes.appendSlice(f.allocator, word);
    };
    const probe = try std.fmt.allocPrint(f.allocator,
        \\if [ "$DPKG_MAINTSCRIPT_NAME" = postrm ]; then
        \\    for backup in{s}; do
        \\        if [ -L "$backup" ] || [ -f "$backup" ] || [ -d "$backup" ]; then
        \\            /diversion-stat --printf='backup-stat:%n:%a:%u:%g:%Y:%i\n' "$backup" >> /{s} || exit 30
        \\        fi
        \\    done
        \\    if [ -f /diversion-remove-record ]; then
        \\        /diversion-remove -f /var/lib/dpkg/diversions || exit 29
        \\    fi
        \\fi
        \\
    , .{ probes.items, lifecycle.trace });
    defer f.allocator.free(probe);
    const mutation =
        \\replacement="/diversion-$DPKG_MAINTSCRIPT_NAME-replace"
        \\if [ -f "$replacement" ]; then
        \\    /diversion-mv "$replacement" /var/lib/dpkg/diversions || exit 26
        \\fi
        \\inplace="/diversion-$DPKG_MAINTSCRIPT_NAME-inplace"
        \\if [ "$DPKG_MAINTSCRIPT_NAME" = preinst ] && [ -f /diversion-inplace-record ]; then
        \\    inplace=/diversion-inplace-record
        \\fi
        \\if [ -f "$inplace" ]; then
        \\    while IFS= read -r line; do
        \\        printf '%s\n' "$line"
        \\    done < "$inplace" > /var/lib/dpkg/diversions
        \\fi
        \\
    ;
    for (lifecycle.kinds) |kind| {
        const script_path = try std.fmt.allocPrint(f.allocator, "{s}/DEBIAN/{s}", .{ source, kind });
        defer f.allocator.free(script_path);
        const script = try lifecycle.read(f, script_path, 65536);
        defer f.allocator.free(script);
        const injection = if (eq(kind, "postrm"))
            try std.mem.concat(f.allocator, u8, &.{ probe, mutation })
        else
            try f.allocator.dupe(u8, mutation);
        defer f.allocator.free(injection);
        const marker = "if [ -f /" ++ lifecycle.failure ++ " ]; then";
        try check(std.mem.count(u8, script, marker) == 1, "fixture script injection boundary");
        const rewritten = try std.mem.replaceOwned(u8, f.allocator, script, marker, try std.mem.concat(f.allocator, u8, &.{ injection, marker }));
        defer f.allocator.free(rewritten);
        try f.write(script_path, rewritten, 0o755);
    }
    const rebuilt = try f.buildPackage(source, try std.fmt.allocPrint(f.allocator, "packages/{s}_{s}_conffile.deb", .{ package, version }), .{});
    f.allocator.free(rebuilt);
    return archive;
}

fn seedRecord(f: *foundation.Fixture, root: []const u8, relative: []const u8, content: []const u8) !void {
    const file = try std.fmt.allocPrint(f.allocator, "{s}/{s}", .{ root[f.path.len + 1 ..], relative });
    defer f.allocator.free(file);
    try lifecycle.fixtureFile(f, file, content, 0o644);
}

fn diversionRecord(a: std.mem.Allocator, source: []const u8, destination: []const u8, owner: []const u8) ![]const u8 {
    return std.fmt.allocPrint(a, "/{s}\n/{s}\n{s}\n", .{ source, destination, owner });
}

fn setup(f: *foundation.Fixture, c: Case, root: []const u8) !void {
    const relative = root[f.path.len + 1 ..];
    try lifecycle.copyProgram(f, relative, "/usr/bin/stat", "/diversion-stat");
    try lifecycle.copyProgram(f, relative, "/bin/mv", "/diversion-mv");
    const source = memberPath(c.member);
    const original = try std.fmt.allocPrint(f.allocator, "{s}.original", .{source});
    const changed = try std.fmt.allocPrint(f.allocator, "{s}.changed", .{source});
    if (eq(c.member, "directory")) {
        const path = try std.fmt.allocPrint(f.allocator, "{s}/{s}", .{ relative, base });
        try f.directory(path);
        try f.dir.setTimestamps(f.io, path, .{ .modify_timestamp = .{ .new = .{ .nanoseconds = epoch_ns } } });
    }
    if (!eq(c.update, "create")) try seedRecord(f, root, "var/lib/dpkg/diversions", try diversionRecord(f.allocator, source, original, ":"));
    const failures: ?[]const u8 = if (eq(c.update, "rollback"))
        package ++ "@1:postrm:upgrade\n" ++ package ++ "@2:postrm:failed-upgrade\n"
    else if (eq(c.update, "unwind-success"))
        package ++ "@1:postrm:upgrade\n"
    else if (eq(c.update, "postinst-failure"))
        package ++ "@2:postinst:configure\n"
    else
        null;
    if (failures) |text| try seedRecord(f, root, lifecycle.failure, text);
    if (eq(c.update, "inplace")) {
        try seedRecord(f, root, "diversion-postrm-inplace", try diversionRecord(f.allocator, source, changed, ":"));
    } else if (!eq(c.update, "remove")) {
        const records: []const u8 = if (eq(c.update, "empty")) "" else if (eq(c.update, "exempt")) try diversionRecord(f.allocator, source, original, package) else try diversionRecord(f.allocator, source, if (eq(c.update, "unchanged")) original else changed, ":");
        try seedRecord(f, root, "diversion-postrm-replace", records);
    }
    if (eq(c.update, "remove")) {
        try lifecycle.copyProgram(f, relative, "/usr/bin/rm", "/diversion-remove");
        try seedRecord(f, root, "diversion-remove-record", "");
    }
}

fn collectInodes(a: std.mem.Allocator, f: *foundation.Fixture, root: []const u8, before: Snapshot) !std.StringHashMap(Identity) {
    var result: std.StringHashMap(Identity) = .init(a);
    for (before.filesystem) |row| {
        if (eq(row.path, base) or std.mem.startsWith(u8, row.path, base ++ "/") or eq(row.path, literal))
            try result.put(row.path, try inode(f, root, row.path));
    }
    return result;
}

fn phaseCheck(
    a: std.mem.Allocator,
    f: *foundation.Fixture,
    c: Case,
    root: []const u8,
    before: Snapshot,
    prior: *const std.StringHashMap(Identity),
    before_diversion: ?Diversion,
    after: Snapshot,
    after_diversion: ?Diversion,
    trace: []const u8,
    controls: [2][]const u8,
    arch: []const u8,
    upgrade: bool,
    start: i128,
    finish: i128,
) ![]const []const u8 {
    try expectedFiles(a, after, c, upgrade, start, finish);
    try verifyDiversion(c, before_diversion, after_diversion, !upgrade);
    const version: []const u8 = if (upgrade and eq(c.update, "rollback")) "1" else "2";
    try verifyDatabase(f, c, root, version, controls, !upgrade);
    const calls = try scriptLines(a, trace, arch, try expectedCalls(a, c, !upgrade));
    if (upgrade) try verifyBackups(a, c, trace, before, prior, start, finish);
    try lifecycle.assertNoActiveEvidence(f, root);
    return calls;
}

fn runCase(f: *foundation.Fixture, driver: []const u8, dpkg: []const u8, helper: []const u8, arch: []const u8, first: []const u8, second: []const u8, controls: [2][]const u8, c: Case) !bool {
    const a = f.allocator;
    const label = try std.fmt.allocPrint(a, "{s}-{s}", .{ c.update, c.member });
    var scenario = try lifecycle.Scenario.init(f, label, driver, dpkg, arch, true);
    defer scenario.deinit();
    const watcher_source = memberPath(c.member);
    const declarations = try std.fmt.allocPrint(a, "interest-noawait /{s}\ninterest-noawait /{s}.original\ninterest-noawait /{s}.changed\n", .{ watcher_source, watcher_source, watcher_source });
    const receiver = try lifecycle.makePackage(f, arch, "1", watcher, label, .{ .declarations = declarations });
    for ([_][]const u8{ scenario.reference_root, scenario.native_root }, [_][]const u8{ "reference", "native" }) |root, side| {
        try setup(f, c, root);
        const destination = try std.fmt.allocPrint(a, "{s}/seed-{s}", .{ label, side });
        try f.directory(destination);
        if (try lifecycle.reference(f, dpkg, root, .{ .operation = "install", .archives = &.{ receiver, first }, .triggers = true }, destination) != 0)
            return fail("reference seed install");
        try seedRecord(f, root, lifecycle.trace, "");
        if (eq(c.update, "cached-activation")) {
            const source = memberPath(c.member);
            const changed = try std.fmt.allocPrint(a, "{s}.changed", .{source});
            try seedRecord(f, root, "diversion-preinst-inplace", try diversionRecord(a, source, changed, ":"));
        }
    }
    {
        const relative = try std.fmt.allocPrint(a, "{s}/native/usr/bin/dpkg-trigger", .{label});
        try f.dir.deleteFile(f.io, relative);
        const native_relative = try std.fmt.allocPrint(a, "{s}/native", .{label});
        try lifecycle.copyProgram(f, native_relative, helper, "/usr/bin/dpkg-trigger");
    }
    {
        var reference_seed = try capture(a, f.io, scenario.reference_root);
        defer reference_seed.deinit(a);
        var native_seed = try capture(a, f.io, scenario.native_root);
        defer native_seed.deinit(a);
        const now = std.Io.Clock.real.now(f.io).nanoseconds;
        const left = try normalized(a, reference_seed.data.value, epoch_ns, now);
        const right = try normalized(a, native_seed.data.value, epoch_ns, now);
        try check(eq(left, right), "seed root status/trigger/filesystem parity");
        try lifecycle.assertNoActiveEvidence(f, scenario.native_root);
    }
    var earliest = [2]i128{ 0, 0 };
    for ([_][]const u8{ "upgrade", "reinstall" }, 0..) |operation, phase_index| {
        if (phase_index != 0 and !succeeds(c)) break;
        const destination = try std.fmt.allocPrint(a, "{s}/{s}", .{ label, operation });
        try f.directory(destination);
        var reference_before = try capture(a, f.io, scenario.reference_root);
        defer reference_before.deinit(a);
        var native_before = try capture(a, f.io, scenario.native_root);
        defer native_before.deinit(a);
        var ref_inodes = try collectInodes(a, f, scenario.reference_root, reference_before.data.value);
        defer ref_inodes.deinit();
        var nat_inodes = try collectInodes(a, f, scenario.native_root, native_before.data.value);
        defer nat_inodes.deinit();
        const ref_db_before = try diversion(f, scenario.reference_root);
        const nat_db_before = try diversion(f, scenario.native_root);
        const input: lifecycle.Phase = .{ .operation = operation, .archives = &.{second}, .triggers = true, .recovery = true };
        const reference_start = std.Io.Clock.real.now(f.io).nanoseconds;
        if (phase_index == 0) earliest[0] = reference_start;
        const reference_exit = try lifecycle.reference(f, dpkg, scenario.reference_root, input, destination);
        const reference_end = std.Io.Clock.real.now(f.io).nanoseconds;
        try check((reference_exit != 0) == (phase_index == 0 and !succeeds(c)), "reference upgrade exit");
        const native_start = std.Io.Clock.real.now(f.io).nanoseconds;
        if (phase_index == 0) earliest[1] = native_start;
        var report = try lifecycle.native(f, driver, scenario.native_root, arch, input, destination);
        defer report.deinit();
        const native_end = std.Io.Clock.real.now(f.io).nanoseconds;
        try check(eq(report.value.outcome, if (reference_exit == 0) "applied" else "script_failed"), "native outcome differs from reference");
        var reference_after = try capture(a, f.io, scenario.reference_root);
        defer reference_after.deinit(a);
        var native_after = try capture(a, f.io, scenario.native_root);
        defer native_after.deinit(a);
        const ref_trace_path = try std.fmt.allocPrint(a, "{s}/{s}", .{ scenario.reference_root[f.path.len + 1 ..], lifecycle.trace });
        const nat_trace_path = try std.fmt.allocPrint(a, "{s}/{s}", .{ scenario.native_root[f.path.len + 1 ..], lifecycle.trace });
        const ref_trace = try lifecycle.read(f, ref_trace_path, 1024 * 1024);
        const nat_trace = try lifecycle.read(f, nat_trace_path, 1024 * 1024);
        const ref_calls = try phaseCheck(a, f, c, scenario.reference_root, reference_before.data.value, &ref_inodes, ref_db_before, reference_after.data.value, try diversion(f, scenario.reference_root), ref_trace, controls, arch, phase_index == 0, earliest[0], reference_end);
        const nat_calls = try phaseCheck(a, f, c, scenario.native_root, native_before.data.value, &nat_inodes, nat_db_before, native_after.data.value, try diversion(f, scenario.native_root), nat_trace, controls, arch, phase_index == 0, earliest[1], native_end);
        try check(ref_calls.len == nat_calls.len, "native/reference script count");
        for (ref_calls, nat_calls) |left, right| try check(eq(left, right), "native/reference script and trigger trace");
        const reference_snapshot = try normalized(a, reference_after.data.value, earliest[0], reference_end);
        const native_snapshot = try normalized(a, native_after.data.value, earliest[1], native_end);
        if (!eq(reference_snapshot, native_snapshot)) {
            var at: usize = 0;
            while (at < @min(reference_snapshot.len, native_snapshot.len) and reference_snapshot[at] == native_snapshot[at]) : (at += 1) {}
            std.debug.print("{s}/{s}: native/dpkg root mismatch at byte {d}:\nreference: {s}\nnative: {s}\n", .{
                label, operation, at, reference_snapshot[at..@min(reference_snapshot.len, at + 160)], native_snapshot[at..@min(native_snapshot.len, at + 160)],
            });
            return error.SettlementMismatch;
        }
        std.debug.print("{s}/{s}: native/dpkg exact settlement passed\n", .{ label, operation });
        if (phase_index == 0 and succeeds(c)) {
            try seedRecord(f, scenario.reference_root, lifecycle.trace, "");
            try seedRecord(f, scenario.native_root, lifecycle.trace, "");
        }
    }
    return succeeds(c);
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    var helper: ?[]const u8 = null;
    var pinned: ?[]const u8 = null;
    while (args.next()) |argument| {
        if (eq(argument, "--native-helper")) {
            if (helper != null) return error.DuplicateHelper;
            helper = args.next() orelse return error.MissingNativeHelper;
        } else if (eq(argument, "--reference-dpkg")) {
            if (pinned != null) return error.DuplicateReference;
            pinned = args.next() orelse return error.MissingReferencePath;
        } else return error.InvalidArguments;
    }
    const helper_path = helper orelse return error.MissingNativeHelper;
    const helper_absolute = try std.fs.path.resolve(a, &.{ options.repository, helper_path });
    const reference = try lifecycle.prerequisites(init, a, pinned orelse return error.MissingPinnedReference);
    var fixture = try foundation.Fixture.init(a, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    try fixture.directory("packages");
    const first = try makePackage(&fixture, reference.architecture, "1");
    const second = try makePackage(&fixture, reference.architecture, "2");
    const controls: [2][]const u8 = .{ "packages/" ++ package ++ "_1_conffile.source", "packages/" ++ package ++ "_2_conffile.source" };
    var subsequent: usize = 0;
    for (cases) |c| {
        subsequent += @intFromBool(runCase(&fixture, driver, reference.executable, helper_absolute, reference.architecture, first, second, controls, c) catch |err| {
            std.debug.print("{s}-{s}: {s}\n", .{ c.update, c.member, @errorName(err) });
            try lifecycle.assertHostUnchanged(a, init.io, reference.before);
            return err;
        });
    }
    try check(subsequent == 16, "expected exactly sixteen subsequent invocations");
    try lifecycle.assertHostUnchanged(a, init.io, reference.before);
}

fn sampleRow(a: std.mem.Allocator, path: []const u8, version: []const u8) !Entry {
    var row = payloadRow(path, version);
    if (contentFor(path, version)) |content| {
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(content, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        row.sha256 = try a.dupe(u8, &hex);
    }
    return row;
}

fn sample(a: std.mem.Allocator, c: Case) !Snapshot {
    var list: std.ArrayList(Entry) = .empty;
    const version: []const u8 = if (eq(c.update, "rollback")) "1" else "2";
    const paths = [_][]const u8{ base, base ++ "/empty", base ++ "/data", base ++ "/data.link", base ++ "/mode", base ++ "/current", config, literal };
    const source = memberPath(c.member);
    const original = try std.fmt.allocPrint(a, "{s}.original", .{source});
    for (paths) |path| {
        var row = try sampleRow(a, path, if (eq(path, source)) "2" else version);
        if (eq(path, source)) row.path = original;
        if (eq(path, base ++ "/current") and eq(version, "1")) row.mtime_ns = epoch_ns + 100 * std.time.ns_per_s;
        try list.append(a, row);
    }
    try list.append(a, try sampleRow(a, if (eq(version, "1")) base ++ "/obsolete" else base ++ "/introduced", version));
    var old = try sampleRow(a, source, "1");
    old.path = try std.fmt.allocPrint(a, "{s}.dpkg-tmp", .{original});
    try list.append(a, old);
    const first: []const u8 = if (eq(c.member, "hardlink-source")) base ++ "/data.link" else base ++ "/data";
    for (list.items) |*row| {
        if (eq(c.member, "hardlink-source")) {
            if (eq(row.path, first) or eq(row.path, old.path)) row.hardlink_to = first;
        } else if (eq(row.path, base ++ "/data") or eq(row.path, base ++ "/data.link")) {
            row.hardlink_to = first;
        }
    }
    return .{ .filesystem = list.items, .dpkg = .null, .trace = &.{} };
}

test "settlement matrix includes all 24 upgrades, 16 follow-ups and six partial rollbacks" {
    try std.testing.expectEqual(24, cases.len);
    var followups: usize = 0;
    var rollback: usize = 0;
    var published: usize = 0;
    var successful_postrm: usize = 0;
    for (cases, 0..) |c, index| {
        for (cases[0..index]) |prior| try std.testing.expect(!eq(c.update, prior.update) or !eq(c.member, prior.member));
        followups += @intFromBool(succeeds(c));
        rollback += @intFromBool(eq(c.update, "rollback"));
        published += @intFromBool(!eq(c.update, "rollback"));
        successful_postrm += @intFromBool(succeeds(c) and !eq(c.update, "unwind-success"));
    }
    try std.testing.expectEqual(16, followups);
    try std.testing.expectEqual(6, rollback);
    try std.testing.expectEqual(18, published);
    try std.testing.expectEqual(15, successful_postrm);
}

test "settlement filesystem mutations reject missing backups, wrong metadata and partial rollback repair" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c: Case = .{ .update = "atomic", .member = "regular" };
    const start = epoch_ns + 100 * std.time.ns_per_s;
    const finish = start + std.time.ns_per_s;
    const snapshot = try sample(a, c);
    try expectedFiles(a, snapshot, c, true, start, finish);
    const backup = snapshot.find(base ++ "/mode.original.dpkg-tmp").?;
    backup.mode = 0o640;
    try std.testing.expectError(error.SettlementMismatch, expectedFiles(a, snapshot, c, true, start, finish));
    try std.testing.expectEqualStrings("payload kind/mode/owner/xattrs", last_failure);
    backup.mode = 0o600;
    backup.sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    try std.testing.expectError(error.SettlementMismatch, expectedFiles(a, snapshot, c, true, start, finish));
    backup.sha256 = (try sampleRow(a, base ++ "/mode", "1")).sha256;
    backup.uid = 1;
    try std.testing.expectError(error.SettlementMismatch, expectedFiles(a, snapshot, c, true, start, finish));
    backup.uid = 0;
    backup.mtime_ns = 0;
    try std.testing.expectError(error.SettlementMismatch, expectedFiles(a, snapshot, c, true, start, finish));
    backup.mtime_ns = epoch_ns;
    backup.path = "unexpected-missing-backup";
    try std.testing.expectError(error.SettlementMismatch, expectedFiles(a, snapshot, c, true, start, finish));
    try std.testing.expectEqualStrings("missing settlement path", last_failure);

    const partial: Case = .{ .update = "rollback", .member = "hardlink-source" };
    const rolled = try sample(a, partial);
    try expectedFiles(a, rolled, partial, true, start, finish);
    const original = rolled.find(base ++ "/data.original").?;
    original.sha256 = (try sampleRow(a, base ++ "/data", "1")).sha256;
    try std.testing.expectError(error.SettlementMismatch, expectedFiles(a, rolled, partial, true, start, finish));
    original.sha256 = (try sampleRow(a, base ++ "/data", "2")).sha256;
    rolled.find(base ++ "/data.original.dpkg-tmp").?.hardlink_to = null;
    try std.testing.expectError(error.SettlementMismatch, expectedFiles(a, rolled, partial, true, start, finish));
}

test "diversion identity, removal and symlink invocation clocks are independently observable" {
    const c: Case = .{ .update = "atomic", .member = "regular" };
    const bytes = "/" ++ base ++ "/mode\n/" ++ base ++ "/mode.changed\n:\n";
    const before: Diversion = .{ .identity = .{ .device = 1, .inode = 7 }, .bytes = @constCast("/" ++ base ++ "/mode\n/" ++ base ++ "/mode.original\n:\n") };
    var after: Diversion = .{ .identity = .{ .device = 1, .inode = 8 }, .bytes = @constCast(bytes) };
    try verifyDiversion(c, before, after, false);
    after.identity.inode = 7;
    try std.testing.expectError(error.SettlementMismatch, verifyDiversion(c, before, after, false));
    try std.testing.expectEqualStrings("diversion database identity", last_failure);
    after.identity.inode = 8;
    after.bytes = before.bytes;
    try std.testing.expectError(error.SettlementMismatch, verifyDiversion(c, before, after, false));
    try std.testing.expectError(error.SettlementMismatch, verifyDiversion(.{ .update = "remove", .member = "regular" }, before, after, false));
    var link = try sampleRow(std.testing.allocator, base ++ "/current", "1");
    try verifyPayload(&link, base ++ "/current", "1", false, 0, 0);
    try std.testing.expectError(error.SettlementMismatch, verifyPayload(&link, base ++ "/current", "1", true, epoch_ns + 100, epoch_ns + 200));
    link.mtime_ns = epoch_ns + 150;
    try verifyPayload(&link, base ++ "/current", "1", true, epoch_ns + 100, epoch_ns + 200);
}

test "script trace refuses rerouted triggers, missing compensation and malformed argument lengths" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c: Case = .{ .update = "rollback", .member = "hardlink-source" };
    const calls = try expectedCalls(a, c, false);
    var text: std.ArrayList(u8) = .empty;
    for (calls) |call| {
        const at = std.mem.indexOfScalar(u8, call.identity, '@').?;
        const colon = std.mem.lastIndexOfScalar(u8, call.identity, ':').?;
        const prefix = try std.fmt.allocPrint(a, "{s}\t{s}\t{s}\tarm64\t{d}", .{ call.identity, call.identity[0..at], call.identity[colon + 1 ..], call.args.len });
        try text.appendSlice(a, prefix);
        for (call.args) |argument| try text.appendSlice(a, try std.fmt.allocPrint(a, "\t{d}:{s}", .{ argument.len, argument }));
        try text.appendSlice(a, "\tpayload=fixture\n");
    }
    try std.testing.expectEqual(calls.len, (try scriptLines(a, text.items, "arm64", calls)).len);
    const rerouted = try std.mem.replaceOwned(u8, a, text.items, "/usr/share/diversion-lifecycle/data.original", "/usr/share/diversion-lifecycle/data.changed");
    try std.testing.expectError(error.SettlementMismatch, scriptLines(a, rerouted, "arm64", calls));
    const missing = try std.mem.replaceOwned(u8, a, text.items, package ++ "@1:preinst", package ++ "@2:preinst");
    try std.testing.expectError(error.SettlementMismatch, scriptLines(a, missing, "arm64", calls));
    const invalid = try std.mem.replaceOwned(u8, a, text.items, "\t7:upgrade", "\t8:upgrade");
    try std.testing.expectError(error.SettlementMismatch, scriptLines(a, invalid, "arm64", calls));
}

test "old-postrm probe rejects deferred backups, metadata mutation and replacement inode" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const c: Case = .{ .update = "atomic", .member = "regular" };
    const names = [_][]const u8{ base ++ "/data", base ++ "/data.link", base ++ "/mode.original", base ++ "/current", literal };
    var entries: std.ArrayList(Entry) = .empty;
    var prior: std.StringHashMap(Identity) = .init(a);
    var probe: std.ArrayList(u8) = .empty;
    try probe.appendSlice(a, package ++ "@1:postrm\tupgrade\n");
    for (names, 0..) |path, index| {
        const logical = if (eq(path, base ++ "/mode.original")) base ++ "/mode" else path;
        const old = try sampleRow(a, logical, "1");
        var before = old;
        before.path = path;
        try entries.append(a, before);
        try prior.put(path, .{ .device = 1, .inode = 100 + index });
        const symbolic = eq(path, base ++ "/current");
        try probe.appendSlice(a, try std.fmt.allocPrint(a, "backup-stat:/{s}.dpkg-tmp:{o}:0:0:{d}:{d}\n", .{
            path,                                           old.mode, if (symbolic) foundation.epoch + 100 else foundation.epoch,
            if (symbolic) @as(usize, 900) else 100 + index,
        }));
    }
    try probe.appendSlice(a, package ++ "@2:postinst\tconfigure\n");
    const before: Snapshot = .{ .filesystem = entries.items, .dpkg = .null, .trace = &.{} };
    const start = epoch_ns + 100 * std.time.ns_per_s;
    const finish = start + std.time.ns_per_s;
    try verifyBackups(a, c, probe.items, before, &prior, start, finish);
    try prior.put(base ++ "/mode.original", .{ .device = 1, .inode = 999 });
    try std.testing.expectError(error.SettlementMismatch, verifyBackups(a, c, probe.items, before, &prior, start, finish));
    try prior.put(base ++ "/mode.original", .{ .device = 1, .inode = 102 });
    const wrong_mode = try std.mem.replaceOwned(u8, a, probe.items, "/mode.original.dpkg-tmp:600:", "/mode.original.dpkg-tmp:640:");
    try std.testing.expectError(error.SettlementMismatch, verifyBackups(a, c, wrong_mode, before, &prior, start, finish));
    try std.testing.expectEqualStrings("old postrm backup metadata", last_failure);
    const deferred = try std.mem.replaceOwned(u8, a, probe.items, package ++ "@1:postrm\tupgrade\n", package ++ "@1:postrm\tupgrade\n" ++ package ++ "@2:postinst\tconfigure\n");
    try std.testing.expectError(error.SettlementMismatch, verifyBackups(a, c, deferred, before, &prior, start, finish));
    const duplicated = try std.mem.concat(a, u8, &.{ probe.items, "backup-stat:/" ++ base ++ "/data.dpkg-tmp:644:0:0:1700000000:100\n" });
    // Only the uninterrupted backup block immediately after the old postrm is authoritative.
    try verifyBackups(a, c, duplicated, before, &prior, start, finish);
}

test "status, logical list and installed controls cannot be inferred from successful exit" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var fixture = try foundation.Fixture.init(a, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("status-root", "arm64");
    const source = [2][]const u8{ "old-control", "new-control" };
    for (lifecycle.kinds ++ [_][]const u8{ "md5sums", "conffiles" }) |name| {
        const old = try std.fmt.allocPrint(a, "{s}/DEBIAN/{s}", .{ source[0], name });
        const fresh = try std.fmt.allocPrint(a, "{s}/DEBIAN/{s}", .{ source[1], name });
        const installed = try std.fmt.allocPrint(a, "status-root/var/lib/dpkg/info/{s}.{s}", .{ package, name });
        try fixture.write(old, "old control\n", 0o644);
        try fixture.write(fresh, "new control\n", 0o644);
        try fixture.write(installed, "new control\n", 0o644);
    }
    const files =
        \\/.
        \\/etc
        \\/usr
        \\/usr/share
        \\/usr/share/diversion-lifecycle
        \\/usr/share/diversion-lifecycle/empty
        \\/usr/share/diversion-lifecycle/data
        \\/usr/share/diversion-lifecycle/data.link
        \\/usr/share/diversion-lifecycle/mode
        \\/usr/share/diversion-lifecycle/current
        \\/usr/share/diversion-lifecycle/introduced
        \\/etc/debz-native.conf
        \\/etc/diversion\literal
        \\
    ;
    const list_path = "status-root/var/lib/dpkg/info/" ++ package ++ ".list";
    try fixture.write(list_path, files, 0o644);
    var digest: [16]u8 = undefined;
    std.crypto.hash.Md5.hash("configuration 2\n", &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const status = try std.fmt.allocPrint(a, "Package: {s}\nStatus: install ok installed\nVersion: 2\nArchitecture: arm64\nConffiles:\n /{s} {s}\n\n", .{ package, config, hex });
    const status_path = "status-root/var/lib/dpkg/status";
    try fixture.write(status_path, status, 0o644);
    const c: Case = .{ .update = "atomic", .member = "regular" };
    try verifyDatabase(&fixture, c, root, "2", source, false);
    for ([_][]const u8{
        try std.mem.replaceOwned(u8, a, status, "Version: 2", "Version: 1"),
        try std.mem.replaceOwned(u8, a, status, "install ok installed", "install ok half-configured"),
        try std.mem.replaceOwned(u8, a, status, &hex, "00000000000000000000000000000000"),
    }) |mutant| {
        try fixture.write(status_path, mutant, 0o644);
        try std.testing.expectError(error.SettlementMismatch, verifyDatabase(&fixture, c, root, "2", source, false));
    }
    try fixture.write(status_path, status, 0o644);
    try fixture.write(list_path, files ++ "/unexpected\n", 0o644);
    try std.testing.expectError(error.SettlementMismatch, verifyDatabase(&fixture, c, root, "2", source, false));
    try fixture.write(list_path, files, 0o644);
    try fixture.write("status-root/var/lib/dpkg/info/" ++ package ++ ".postrm", "old control\n", 0o644);
    try std.testing.expectError(error.SettlementMismatch, verifyDatabase(&fixture, c, root, "2", source, false));
    try std.testing.expectEqualStrings("installed control bytes", last_failure);
}

fn corpusField(row: std.json.Value, name: []const u8) !std.json.Value {
    if (row != .object) return fail("non-object settlement corpus profile");
    return row.object.get(name) orelse return fail(name);
}

fn corpusText(row: std.json.Value, name: []const u8, expected: []const u8) !void {
    const value = try corpusField(row, name);
    if (value != .string or !eq(value.string, expected)) {
        const update = try corpusField(row, "update");
        const member = try corpusField(row, "member");
        if (!builtin.is_test) std.debug.print("corpus {s}-{s}/{s}: expected {s}, got {s}\n", .{
            if (update == .string) update.string else "<malformed>",
            if (member == .string) member.string else "<malformed>",
            name,
            expected,
            if (value == .string) value.string else "<non-text>",
        });
        return fail(name);
    }
}

fn validateCorpus(a: std.mem.Allocator, rows: []const std.json.Value) !void {
    try check(rows.len == 15, "settlement corpus profile count");
    var index: usize = 0;
    for (cases) |c| {
        if (!succeeds(c) or eq(c.update, "unwind-success")) continue;
        const row = rows[index];
        index += 1;
        try check(row == .object and row.object.count() == 10, "settlement corpus field set");
        try corpusText(row, "update", c.update);
        try corpusText(row, "member", c.member);
        const source = memberPath(c.member);
        const payload_route = if (eq(c.update, "create")) source else try std.fmt.allocPrint(a, "{s}.original", .{source});
        const script_route = if (eq(c.update, "inplace")) payload_route else try route(a, c.update, source);
        const changed = !eq(payload_route, script_route);
        try corpusText(row, "payload_route", payload_route);
        try corpusText(row, "post_script_route", script_route);
        try corpusText(row, "backup", if (eq(c.member, "regular") or eq(c.member, "symlink") or std.mem.startsWith(u8, c.member, "hardlink-")) (if (changed) "retain" else "discard") else "none");
        try corpusText(row, "staging", if (eq(c.member, "conffile") and changed) "retain" else "absent");
        try corpusText(row, "ownership", if (eq(c.member, "obsolete")) "previous" else if (eq(c.member, "introduced")) "resulting" else "previous_and_resulting");
        const paths = try corpusField(row, "trigger_paths");
        try check(paths == .array, "trigger path list");
        const count: usize = if (eq(c.member, "obsolete")) 0 else if (eq(c.member, "directory")) 2 else 1;
        try check(paths.array.items.len == count, "trigger path count");
        if (count == 2) try check(paths.array.items[0] == .string and eq(paths.array.items[0].string, try std.fmt.allocPrint(a, "/{s}", .{source})), "directory source trigger");
        if (count != 0) try check(paths.array.items[count - 1] == .string and eq(paths.array.items[count - 1].string, try std.fmt.allocPrint(a, "/{s}", .{payload_route})), "trigger payload route");
        const removal = try corpusField(row, "removal_route");
        if (eq(c.member, "obsolete"))
            try check(removal == .string and eq(removal.string, "post_script"), "obsolete removal route")
        else
            try check(removal == .null, "invented obsolete removal");
        var digest: [16]u8 = undefined;
        std.crypto.hash.Md5.hash(contentFor(config, if (eq(c.member, "conffile") and changed) "1" else "2").?, &digest, .{});
        const hex = std.fmt.bytesToHex(digest, .lower);
        try corpusText(row, "recorded_md5", &hex);
    }
    try check(index == rows.len, "settlement corpus coverage");
}

test "successful settlement corpus exactly lowers 15 profiles and refuses malformed mutations" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const filename = try std.fs.path.join(a, &.{ options.repository, "src/fixtures/native-diversion-success-settlement-v1.json" });
    var file = try std.Io.Dir.openFileAbsolute(std.testing.io, filename, .{});
    defer file.close(std.testing.io);
    var reader = file.reader(std.testing.io, &.{});
    const bytes = try reader.interface.allocRemaining(a, .limited(64 * 1024));
    const document = try std.json.parseFromSlice([]const std.json.Value, a, bytes, .{ .allocate = .alloc_always });
    defer document.deinit();
    try validateCorpus(a, document.value);
    try std.testing.expectError(error.SettlementMismatch, validateCorpus(a, document.value[0..14]));
    const changed = try a.dupe(std.json.Value, document.value);
    changed[0] = .null;
    try std.testing.expectError(error.SettlementMismatch, validateCorpus(a, changed));
    changed[0] = document.value[0];
    try changed[0].object.put(a, "trigger_paths", .{ .string = "not a trigger path list" });
    try std.testing.expectError(error.SettlementMismatch, validateCorpus(a, changed));
    try std.testing.expectEqualStrings("trigger path list", last_failure);
    try changed[0].object.put(a, "update", .{ .integer = 17 });
    try std.testing.expectError(error.SettlementMismatch, validateCorpus(a, changed));
}
