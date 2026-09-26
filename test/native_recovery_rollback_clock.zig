const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const oracle = @import("native_recovery_oracle.zig");
const options = @import("native_test_options");

const package = "rollback-clock";
const link = "usr/share/" ++ package ++ "/current";

fn linkTime(snapshot: std.json.Value) !i128 {
    if (snapshot != .object) return error.InvalidRollbackSnapshot;
    const files = snapshot.object.get("filesystem") orelse return error.InvalidRollbackSnapshot;
    if (files != .array) return error.InvalidRollbackSnapshot;
    for (files.array.items) |entry| {
        if (entry != .object) return error.InvalidRollbackSnapshot;
        const path = entry.object.get("path") orelse return error.InvalidRollbackSnapshot;
        if (path != .string or !std.mem.eql(u8, path.string, link)) continue;
        const kind = entry.object.get("kind") orelse return error.InvalidRollbackSnapshot;
        const time = entry.object.get("mtime_ns") orelse return error.InvalidRollbackSnapshot;
        if (kind != .string or !std.mem.eql(u8, kind.string, "symlink") or time != .integer)
            return error.InvalidRollbackSnapshot;
        return time.integer;
    }
    return error.MissingRollbackPath;
}

fn normalize(snapshot: *std.json.Value, original: i128, started: i128, ended: i128) !void {
    const files = snapshot.object.getPtr("filesystem") orelse return error.InvalidRollbackSnapshot;
    if (files.* != .array) return error.InvalidRollbackSnapshot;
    for (files.array.items) |*entry| {
        if (entry.* != .object) return error.InvalidRollbackSnapshot;
        const path = entry.object.get("path") orelse return error.InvalidRollbackSnapshot;
        if (path != .string or !std.mem.eql(u8, path.string, link)) continue;
        const time = try linkTime(snapshot.*);
        var observed = [_]oracle.RollbackEntry{.{
            .path = path.string,
            .kind = .symlink,
            .modified_nanoseconds = time,
        }};
        try oracle.normalizeRollbackTimes(&observed, &.{.{
            .path = link,
            .original_nanoseconds = original,
        }}, started, ended, true);
        const field = entry.object.getPtr("mtime_ns") orelse return error.InvalidRollbackSnapshot;
        field.* = .{ .integer = @intCast(observed[0].modified_nanoseconds) };
        return;
    }
    return error.MissingRollbackPath;
}

fn requireRefusedTimestamp(allocator: std.mem.Allocator, raw: []const u8, time: i128, original: i128, started: i128, ended: i128) !void {
    var snapshot = try std.json.parseFromSlice(std.json.Value, allocator, raw, .{});
    defer snapshot.deinit();
    _ = try linkTime(snapshot.value);
    const files = snapshot.value.object.getPtr("filesystem") orelse return error.InvalidRollbackSnapshot;
    for (files.array.items) |*entry| {
        const path = entry.object.get("path") orelse return error.InvalidRollbackSnapshot;
        if (path != .string or !std.mem.eql(u8, path.string, link)) continue;
        const field = entry.object.getPtr("mtime_ns") orelse return error.InvalidRollbackSnapshot;
        field.* = .{ .integer = @intCast(time) };
        break;
    }
    normalize(&snapshot.value, original, started, ended) catch |err| {
        if (err == error.UnexpectedRollbackSymlinkTimestamp) return;
        return err;
    };
    return error.InvalidRollbackClockAccepted;
}

fn run(fixture: *foundation.Fixture, driver: []const u8, reference: []const u8, arch: []const u8) !void {
    var case = try support.Scenario.init(fixture, package, driver, reference, arch, false);
    defer case.deinit();
    const first = try support.makePackage(fixture, arch, "1", package, "rollback-clock-packages", .{
        .full_payload = true,
        .conffile_content = "configuration 1\n",
    });
    const second = try support.makePackage(fixture, arch, "2", package, "rollback-clock-packages", .{
        .full_payload = true,
        .conffile_content = "configuration 2\n",
    });
    try case.seed(first);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/{s}", .{ package, side, support.failure });
        try support.fixtureFile(fixture, relative, package ++ "@1:postrm:upgrade\n" ++
            package ++ "@2:postrm:failed-upgrade\n", 0o644);
    }
    const before_reference = try foundation.capture(fixture.allocator, fixture.io, case.reference_root);
    const before_native = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    var before_left = try std.json.parseFromSlice(std.json.Value, fixture.allocator, before_reference, .{});
    defer before_left.deinit();
    var before_right = try std.json.parseFromSlice(std.json.Value, fixture.allocator, before_native, .{});
    defer before_right.deinit();
    const original_reference = try linkTime(before_left.value);
    const original_native = try linkTime(before_right.value);
    const destination = package ++ "/failed-upgrade";
    try fixture.directory(destination);
    try fixture.write(destination ++ "/reference.before.json", before_reference, 0o644);
    try fixture.write(destination ++ "/native.before.json", before_native, 0o644);
    const selection = [_]foundation.PackageIdentity{.{ .name = package, .architecture = arch }};
    const phase: support.Phase = .{
        .operation = "upgrade",
        .archives = &.{second},
        .packages = &selection,
    };
    const started = std.Io.Clock.real.now(fixture.io).nanoseconds;
    const reference_status = try support.reference(fixture, reference, case.reference_root, phase, destination);
    if (reference_status != 1) return error.ReferenceUpgradeDidNotFail;
    var report = try support.native(fixture, driver, case.native_root, arch, phase, destination);
    defer report.deinit();
    if (!std.mem.eql(u8, report.value.outcome, "script_failed"))
        return error.NativeUpgradeDidNotFail;
    try support.assertNoActiveEvidence(fixture, case.native_root);
    const ended = std.Io.Clock.real.now(fixture.io).nanoseconds;
    const after_reference = try foundation.capture(fixture.allocator, fixture.io, case.reference_root);
    const after_native = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    try fixture.write(destination ++ "/reference.after.json", after_reference, 0o644);
    try fixture.write(destination ++ "/native.after.json", after_native, 0o644);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const status_path = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/var/lib/dpkg/status", .{ package, side });
        const status = try support.read(fixture, status_path, 64 * 1024);
        if (std.mem.indexOf(u8, status, "Package: " ++ package ++ "\n") == null or
            std.mem.indexOf(u8, status, "Version: 1\n") == null)
            return error.RollbackDidNotRestorePackageVersion;
    }
    var left = try std.json.parseFromSlice(std.json.Value, fixture.allocator, after_reference, .{});
    defer left.deinit();
    var right = try std.json.parseFromSlice(std.json.Value, fixture.allocator, after_native, .{});
    defer right.deinit();
    const reference_time = try linkTime(left.value);
    const native_time = try linkTime(right.value);
    if (original_reference >= started or original_native >= started or
        reference_time == original_reference or native_time == original_native)
        return error.RollbackDidNotRecreateSymlink;
    const native_trace = try support.read(fixture, package ++ "/native/" ++ support.trace, 1024 * 1024);
    if (std.mem.indexOf(u8, native_trace, package ++ "@1:postrm") == null or
        std.mem.indexOf(u8, native_trace, package ++ "@2:postrm") == null or
        std.mem.indexOf(u8, native_trace, "failed-upgrade") == null)
        return error.MissingFailedUpgradeRollbackTrace;
    try normalize(&left.value, original_reference, started, ended);
    try normalize(&right.value, original_reference, started, ended);
    for ([_]i128{ original_reference, original_native, started - 1, ended + 1 }) |invalid|
        try requireRefusedTimestamp(fixture.allocator, after_native, invalid, original_reference, started, ended);
    const expected = try std.json.Stringify.valueAlloc(fixture.allocator, left.value, .{});
    const actual = try std.json.Stringify.valueAlloc(fixture.allocator, right.value, .{});
    if (!std.mem.eql(u8, expected, actual)) {
        var at: usize = 0;
        while (at < @min(expected.len, actual.len) and expected[at] == actual[at]) : (at += 1) {}
        std.debug.print("real failed-upgrade snapshots differ at byte {d}: expected {s}; native {s}\n", .{
            at,
            expected[at..@min(expected.len, at + 160)],
            actual[at..@min(actual.len, at + 160)],
        });
        return error.NativeDpkgRollbackMismatch;
    }
    std.debug.print("real pinned-dpkg/native failed upgrade: recreated symlink clocks {d}/{d} in [{d},{d}], original/arbitrary timestamps refused; normalized snapshots match\n", .{
        reference_time, native_time, started, ended,
    });
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    if (!std.mem.eql(u8, args.next() orelse return error.MissingReferencePath, "--reference-dpkg"))
        return error.PinnedReferenceRequired;
    const pinned = args.next() orelse return error.MissingReferencePath;
    if (args.next() != null) return error.InvalidArguments;
    const reference = try support.prerequisites(init, allocator, pinned);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed after rollback failure: {s}\n", .{@errorName(err)});
    try run(&fixture, driver, reference.executable, reference.architecture);
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
