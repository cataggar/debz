const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");

const package = foundation.package;

fn failureMarker(case: *support.Scenario, content: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |label| {
        const relative = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{
            case.name, label, support.failure,
        });
        defer case.fixture.allocator.free(relative);
        if (content.len == 0) {
            try case.fixture.dir.deleteFile(case.fixture.io, relative);
        } else try support.fixtureFile(case.fixture, relative, content, 0o644);
    }
}

fn runLifecycle(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first = try support.makePackage(fixture, arch, "1", package, "packages", .{});
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, arch, "2", package, "packages", .{});
    defer fixture.allocator.free(second);
    const selected = [_]foundation.PackageIdentity{.{ .name = package, .architecture = arch }};
    for ([_]struct { name: []const u8, initial: ?[]const u8, archive: []const u8 }{
        .{ .name = "fresh-install", .initial = null, .archive = first },
        .{ .name = "upgrade", .initial = first, .archive = second },
        .{ .name = "downgrade", .initial = second, .archive = first },
        .{ .name = "reinstall", .initial = first, .archive = first },
    }) |entry| {
        var case = try support.Scenario.init(fixture, entry.name, driver, dpkg, arch, false);
        defer case.deinit();
        if (entry.initial) |initial| try case.seed(initial);
        try case.phase(.{
            .operation = if (entry.initial == null) "install" else entry.name,
            .archives = &.{entry.archive},
            .packages = &selected,
        }, false);
    }
    for ([_][]const u8{ "remove", "purge" }) |operation| {
        var case = try support.Scenario.init(fixture, operation, driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        try case.phase(.{ .operation = operation, .packages = &selected }, false);
        try case.phase(.{ .operation = operation, .packages = &selected }, false);
        if (std.mem.eql(u8, operation, "remove"))
            try case.phase(.{ .operation = "purge", .packages = &selected }, false);
    }
    for ([_][]const u8{ "preinst", "postinst" }) |kind| {
        const name = try std.fmt.allocPrint(fixture.allocator, "fresh-{s}-failure", .{kind});
        defer fixture.allocator.free(name);
        var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, false);
        defer case.deinit();
        const marker = try std.fmt.allocPrint(fixture.allocator, "{s}@1:{s}:{s}\n", .{
            package, kind, if (std.mem.eql(u8, kind, "preinst")) "install" else "configure",
        });
        defer fixture.allocator.free(marker);
        try failureMarker(&case, marker);
        try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &selected }, true);
        if (std.mem.eql(u8, kind, "postinst")) {
            try failureMarker(&case, "");
            try case.phase(.{ .operation = "configure", .archives = &.{first}, .packages = &selected }, false);
        }
    }
    {
        var case = try support.Scenario.init(fixture, "upgrade-prerm-unwind", driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        try failureMarker(&case, package ++ "@1:prerm:upgrade\n");
        try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &selected }, false);
    }
    {
        var case = try support.Scenario.init(fixture, "upgrade-postinst-failure", driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        try failureMarker(&case, package ++ "@2:postinst:configure\n");
        try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &selected }, true);
        try failureMarker(&case, "");
        try case.phase(.{ .operation = "configure", .archives = &.{second}, .packages = &selected }, false);
    }
    const first_config = try support.makePackage(fixture, arch, "1", "conffile-lifecycle", "conffile-packages", .{
        .conffile_content = "configuration 1\n",
    });
    defer fixture.allocator.free(first_config);
    const second_config = try support.makePackage(fixture, arch, "2", "conffile-lifecycle", "conffile-packages", .{
        .conffile_content = "configuration 2\n",
    });
    defer fixture.allocator.free(second_config);
    const configured = [_]foundation.PackageIdentity{.{ .name = "conffile-lifecycle", .architecture = arch }};
    for ([_][]const u8{ "keep_existing", "use_package_version" }) |policy| {
        const label = try std.fmt.allocPrint(fixture.allocator, "script-conffile-{s}", .{policy});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first_config);
        for ([_][]const u8{ "reference", "native" }) |side| {
            const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/etc/debz-native.conf", .{ label, side });
            defer fixture.allocator.free(relative);
            try support.fixtureFile(fixture, relative, "administrator configuration\n", 0o644);
        }
        try case.phase(.{
            .operation = "upgrade",
            .archives = &.{second_config},
            .packages = &configured,
            .policy = policy,
        }, false);
        try case.phase(.{ .operation = "remove", .packages = &configured, .policy = policy }, false);
        try case.phase(.{ .operation = "purge", .packages = &configured, .policy = policy }, false);
    }
}

fn runDiversions(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first = try support.makePackage(fixture, arch, "1", "diversion-lifecycle", "diversion-packages", .{});
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, arch, "2", "diversion-lifecycle", "diversion-packages", .{});
    defer fixture.allocator.free(second);
    const name = "diversion-lifecycle";
    const source = "usr/share/diversion-lifecycle/data";
    const destination = source ++ ".distrib";
    const record = "/" ++ source ++ "\n/" ++ destination ++ "\n:\n";
    var case = try support.Scenario.init(fixture, "diverted-hardlink", driver, dpkg, arch, false);
    defer case.deinit();
    for ([_][]const u8{ "reference", "native" }) |label| {
        const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/var/lib/dpkg/diversions", .{ case.name, label });
        defer fixture.allocator.free(relative);
        try support.fixtureFile(fixture, relative, record, 0o644);
    }
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &selected }, false);
    try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &selected }, false);
    try case.phase(.{ .operation = "remove", .packages = &selected }, false);
    try case.phase(.{ .operation = "purge", .packages = &selected }, false);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    const driver = arguments.next() orelse return error.MissingNativeDriver;
    var pinned: ?[]const u8 = null;
    var diversions_only = false;
    while (arguments.next()) |option| {
        if (std.mem.eql(u8, option, "--reference-dpkg")) {
            if (pinned != null) return error.DuplicateReference;
            pinned = arguments.next() orelse return error.MissingReferencePath;
        } else if (std.mem.eql(u8, option, "--diversions-only")) {
            if (diversions_only) return error.DuplicateSelector;
            diversions_only = true;
        } else return error.InvalidArguments;
    }
    const reference = try support.prerequisites(init, allocator, pinned);
    defer allocator.free(reference.architecture);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    if (!diversions_only) runLifecycle(&fixture, driver, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    runDiversions(&fixture, driver, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}

test "lifecycle scripts encode empty arguments, environment, payload and failure boundary" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    try fixture.directory("scripts");
    try support.scripts(&fixture, "scripts", "fixture", "1");
    for (support.kinds) |kind| {
        const member = try std.fmt.allocPrint(std.testing.allocator, "scripts/DEBIAN/{s}", .{kind});
        defer std.testing.allocator.free(member);
        const body = try support.read(&fixture, member, 64 * 1024);
        defer std.testing.allocator.free(body);
        for ([_][]const u8{
            "fixture@1:",                     "\"$DPKG_MAINTSCRIPT_ARCH\"", "\"$#\"",
            "\"${#argument}\" \"$argument\"", "payload='<absent>'",         "exit 23",
        }) |needle| try std.testing.expect(std.mem.indexOf(u8, body, needle) != null);
        const file = try fixture.absolute(member);
        defer std.testing.allocator.free(file);
        try fixture.run(&.{ "/bin/sh", "-n", file }, "script-syntax.log", 10);
    }
}

test "reference refuses unguarded roots without invoking selected executable" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    try fixture.write("fake-dpkg", "#!/bin/sh\nexit 0\n", 0o755);
    const binary = try fixture.absolute("fake-dpkg");
    defer std.testing.allocator.free(binary);
    const root = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(root);
    try fixture.write("root/" ++ foundation.guard, "not disposable\n", 0o600);
    try std.testing.expectError(error.NotDisposableRoot, support.reference(
        &fixture,
        binary,
        root,
        .{ .operation = "purge" },
        "unused",
    ));
    try support.absent(&fixture, "unused/reference.log");
}
