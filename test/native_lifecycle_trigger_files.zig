const std = @import("std");
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

const workspace = "packages/trigger-files";
const receiver = "trigger-file-receiver";
const source = "trigger-file-source";
const event = "debz-trigger-file-event";

const receiver_v1 = "# Interest declared by the debz fixture\n\n \tinterest-noawait\t" ++ event ++ " \t\n";
const receiver_v2 = "  # Only this comment changed\ninterest-noawait " ++ event ++ "\n\n";
const source_v1 = "# Triggers added by dh_makeshlibs/14.5ubuntu1\nactivate-noawait " ++ event ++ "\n";
const source_v2 = "# Same declaration, other bytes\n\tactivate-noawait   " ++ event ++ "\t\n  \n";
const quiet = "trigger-file-quiet";
const quiet_v1 = "# Nothing is declared here\n";
const quiet_v2 = "\n  # Still nothing, other bytes\n\t\n";

/// Builds a package whose `DEBIAN/triggers` member is exactly `member`,
/// through the real `dpkg-deb` like distribution packages. `dpkg-deb`
/// normalizes control member modes, so every member is 0644 here; the
/// archive application unit tests cover retaining other member modes.
fn triggerPackage(fixture: *foundation.Fixture, arch: []const u8, name: []const u8, version: []const u8, member: []const u8) ![]u8 {
    return support.makePackage(fixture, arch, version, name, workspace, .{ .declarations = member });
}

/// dpkg 1.22.22 renames every control member into `info/` unchanged
/// (`pkg_infodb_update`), so both roots must hold the member's exact bytes
/// and mode, comments and blanks included.
fn expectTriggerFile(case: *support.Scenario, package: []const u8, expected: ?[]const u8) !void {
    const allocator = case.fixture.allocator;
    const relative = try std.fmt.allocPrint(allocator, "var/lib/dpkg/info/{s}.triggers", .{package});
    defer allocator.free(relative);
    const path = try root_fs.Path.initPackage(relative);
    for ([_][]const u8{ case.reference_root, case.native_root }) |root_path| {
        var dir = try foundation.guardedRoot(case.fixture.io, root_path);
        defer dir.close(case.fixture.io);
        const root = root_fs.Root.init(case.fixture.io, dir);
        const entry = try root.entryIfExists(path);
        const bytes = expected orelse {
            if (entry != null) return error.TriggerFileLeftBehind;
            continue;
        };
        const found = entry orelse return error.MissingTriggerFile;
        if (found.kind != .file or found.mode != 0o644 or found.uid != 0 or found.gid != 0) {
            std.debug.print("{s}: {s} mode {o} owner {d}:{d}\n", .{ root_path, relative, found.mode, found.uid, found.gid });
            return error.WrongTriggerFileMetadata;
        }
        const actual = try root.readFileAlloc(allocator, path, 64 * 1024);
        defer allocator.free(actual);
        if (!std.mem.eql(u8, actual, bytes)) {
            std.debug.print("{s}: {s} holds {f}, expected {f}\n", .{
                root_path, relative, std.zig.fmtString(actual), std.zig.fmtString(bytes),
            });
            return error.TriggerFileNotVerbatim;
        }
    }
}

/// Trigger control members are compared byte for byte against pinned dpkg
/// across install, upgrades that change only comments and blanks, a
/// comment-only member, removal, and purge. Every phase also compares the
/// whole root, so the declarations debz parsed from the comment-bearing files
/// must drive the same trigger processing as dpkg.
pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const interest_first = try triggerPackage(fixture, arch, receiver, "1", receiver_v1);
    defer fixture.allocator.free(interest_first);
    const interest_second = try triggerPackage(fixture, arch, receiver, "2", receiver_v2);
    defer fixture.allocator.free(interest_second);
    const first = try triggerPackage(fixture, arch, source, "1", source_v1);
    defer fixture.allocator.free(first);
    const second = try triggerPackage(fixture, arch, source, "2", source_v2);
    defer fixture.allocator.free(second);
    const quiet_first = try triggerPackage(fixture, arch, quiet, "1", quiet_v1);
    defer fixture.allocator.free(quiet_first);
    const quiet_second = try triggerPackage(fixture, arch, quiet, "2", quiet_v2);
    defer fixture.allocator.free(quiet_second);
    const receiving = [_]foundation.PackageIdentity{.{ .name = receiver, .architecture = arch }};
    const activating = [_]foundation.PackageIdentity{.{ .name = source, .architecture = arch }};
    const silent = [_]foundation.PackageIdentity{.{ .name = quiet, .architecture = arch }};

    var case = try support.Scenario.init(fixture, "trigger-files-verbatim", driver, dpkg, arch, false);
    defer case.deinit();
    try case.phase(.{ .operation = "install", .archives = &.{interest_first}, .packages = &receiving, .triggers = true }, false);
    try expectTriggerFile(&case, receiver, receiver_v1);
    try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &activating, .triggers = true }, false);
    try expectTriggerFile(&case, source, source_v1);
    try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &activating, .triggers = true }, false);
    try expectTriggerFile(&case, source, source_v2);
    try case.phase(.{ .operation = "upgrade", .archives = &.{interest_second}, .packages = &receiving, .triggers = true }, false);
    try expectTriggerFile(&case, receiver, receiver_v2);
    try case.phase(.{ .operation = "install", .archives = &.{quiet_first}, .packages = &silent, .triggers = true }, false);
    try expectTriggerFile(&case, quiet, quiet_v1);
    try case.phase(.{ .operation = "upgrade", .archives = &.{quiet_second}, .packages = &silent, .triggers = true }, false);
    try expectTriggerFile(&case, quiet, quiet_v2);
    try case.phase(.{ .operation = "downgrade", .archives = &.{quiet_first}, .packages = &silent, .triggers = true }, false);
    try expectTriggerFile(&case, quiet, quiet_v1);
    try case.phase(.{ .operation = "remove", .packages = &silent, .triggers = true }, false);
    try expectTriggerFile(&case, quiet, null);
    try case.phase(.{ .operation = "purge", .packages = &silent, .triggers = true }, false);
    try case.phase(.{ .operation = "remove", .packages = &receiving, .triggers = true }, false);
    try expectTriggerFile(&case, receiver, null);
    // No installed package declares an interest any more, so the native
    // fixture driver has no trigger authority to request.
    try case.phase(.{ .operation = "purge", .packages = &receiving }, false);

    // A comment-only member declares nothing, so it needs no trigger
    // execution, yet dpkg still installs it.
    var quiet_case = try support.Scenario.init(fixture, "trigger-files-comment-only", driver, dpkg, arch, false);
    defer quiet_case.deinit();
    try quiet_case.phase(.{ .operation = "install", .archives = &.{quiet_first}, .packages = &silent }, false);
    try expectTriggerFile(&quiet_case, quiet, quiet_v1);
    try quiet_case.phase(.{ .operation = "upgrade", .archives = &.{quiet_second}, .packages = &silent }, false);
    try expectTriggerFile(&quiet_case, quiet, quiet_v2);
    try quiet_case.phase(.{ .operation = "remove", .packages = &silent }, false);
    try expectTriggerFile(&quiet_case, quiet, null);
    try quiet_case.phase(.{ .operation = "purge", .packages = &silent }, false);
    std.debug.print("trigger-files: verbatim install, comment-only upgrades, comment-only members, remove, and purge match pinned dpkg\n", .{});
}
