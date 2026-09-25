const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

const name = "native-alternatives";
const group = "debz-native-alternatives";

fn archive(fixture: *foundation.Fixture, arch: []const u8, version: []const u8) ![]u8 {
    const candidate = try std.fmt.allocPrint(fixture.allocator, "usr/lib/debz-alternatives/{s}-{s}", .{ name, version });
    defer fixture.allocator.free(candidate);
    const manual = try std.fmt.allocPrint(fixture.allocator, "usr/share/man/man1/{s}-{s}.1", .{ name, version });
    defer fixture.allocator.free(manual);
    const content = try std.fmt.allocPrint(fixture.allocator, "provider {s}\n", .{version});
    defer fixture.allocator.free(content);
    const manual_content = try std.fmt.allocPrint(fixture.allocator, "manual {s}\n", .{version});
    defer fixture.allocator.free(manual_content);
    const initial = try support.makePackage(fixture, arch, version, name, "packages/alternatives", .{
        .no_scripts = true,
        .extra_files = &.{
            .{ .path = candidate, .content = content },
            .{ .path = manual, .content = manual_content },
        },
    });
    defer fixture.allocator.free(initial);
    const source = try std.fmt.allocPrint(fixture.allocator, "packages/alternatives/{s}_{s}_data.source", .{ name, version });
    defer fixture.allocator.free(source);
    const postinst = try std.fmt.allocPrint(fixture.allocator,
        \\#!/bin/sh
        \\case "$1" in
        \\ configure|abort-upgrade|abort-remove|abort-deconfigure)
        \\  /usr/bin/update-alternatives --install /usr/bin/{s} {s} /{s} {s} --slave /usr/share/man/man1/{s}.1 {s}.1 /{s}
        \\  ;;
        \\esac
        \\
    , .{ group, group, candidate, if (std.mem.eql(u8, version, "1")) "10" else "20", group, group, manual });
    defer fixture.allocator.free(postinst);
    const prerm = try std.fmt.allocPrint(fixture.allocator,
        \\#!/bin/sh
        \\case "$1" in
        \\ remove|upgrade|deconfigure)
        \\  /usr/bin/update-alternatives --remove {s} /{s}
        \\  ;;
        \\esac
        \\
    , .{ group, candidate });
    defer fixture.allocator.free(prerm);
    for ([_][]const u8{ "postinst", "prerm" }, [_][]const u8{ postinst, prerm }) |kind, script| {
        const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/DEBIAN/{s}", .{ source, kind });
        defer fixture.allocator.free(relative);
        try fixture.write(relative, script, 0o755);
    }
    const output = try std.fmt.allocPrint(fixture.allocator, "packages/alternatives/{s}_{s}_data.deb", .{ name, version });
    defer fixture.allocator.free(output);
    return fixture.buildPackage(source, output, .{});
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, pinned: bool) !void {
    if (!pinned) {
        std.debug.print("native alternatives acceptance requires pinned update-alternatives; skipping host fallback\n", .{});
        return;
    }
    const tool = try std.fs.path.join(fixture.allocator, &.{ std.fs.path.dirname(dpkg) orelse return error.InvalidReferencePath, "update-alternatives" });
    defer fixture.allocator.free(tool);
    var file = try std.Io.Dir.openFileAbsolute(fixture.io, tool, .{ .follow_symlinks = false });
    defer file.close(fixture.io);
    var reader = file.reader(fixture.io, &.{});
    const bytes = try reader.interface.allocRemaining(fixture.allocator, .limited(8 * 1024 * 1024));
    defer fixture.allocator.free(bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    const expected = if (std.mem.eql(u8, arch, "amd64"))
        "b02b581c6a7f85679f32efe18c9aaeb05316847fa90d3d3fda30b57defab9b13"
    else
        "35616ec58ba58f3fb8b4820bdf893c47a842d56684b3335ba6ebf6df86b27cc5";
    if (!std.mem.eql(u8, &std.fmt.bytesToHex(digest, .lower), expected))
        return error.PinnedAlternativesDigestMismatch;
    const first = try archive(fixture, arch, "1");
    defer fixture.allocator.free(first);
    const second = try archive(fixture, arch, "2");
    defer fixture.allocator.free(second);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    var case = try support.Scenario.init(fixture, "native-alternatives-lifecycle-zig", driver, dpkg, arch, false);
    defer case.deinit();
    for ([_][]const u8{ "reference", "native" }) |side| {
        const root = try support.path(fixture.allocator, case.name, side);
        defer fixture.allocator.free(root);
        for ([_][]const u8{
            "etc/alternatives",   "usr/bin",                   "usr/lib/debz-alternatives",
            "usr/share/man/man1", "var/lib/dpkg/alternatives", "var/log",
        }) |relative| {
            const path = try support.path(fixture.allocator, root, relative);
            defer fixture.allocator.free(path);
            try fixture.directory(path);
        }
        try support.copyProgram(fixture, root, tool, "/usr/bin/update-alternatives");
    }
    case.alternatives = true;
    for ([_][]const u8{ "install", "reinstall", "upgrade" }, [_][]const u8{ first, first, second }) |operation, selected_archive| {
        try case.phase(.{ .operation = operation, .archives = &.{selected_archive}, .packages = &selected }, false);
    }
    try case.phase(.{ .operation = "remove", .packages = &selected }, false);
    try case.phase(.{ .operation = "purge", .packages = &selected }, false);
}
