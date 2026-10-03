const std = @import("std");
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

const Link = struct { path: []const u8, target: []const u8 };

const workspace = "packages/symlink-chains";
const chain_name = "symlink-chain";
const lib = "usr/lib/" ++ chain_name;
const share = "usr/share/" ++ chain_name;

/// Adds symbolic links to the unpacked `makePackage` source and rebuilds it,
/// so the real `dpkg-deb` chooses the tar order exactly as for distribution
/// packages: symlinks last and sorted by path. `libchain.so.3` therefore
/// precedes the `libchain.so.4` hop it names, the libcurl3t64-gnutls order
/// from #342, while `libchain.so.5` follows it.
fn linkPackage(
    fixture: *foundation.Fixture,
    arch: []const u8,
    name: []const u8,
    version: []const u8,
    control_fields: []const u8,
    links: []const Link,
    files: []const foundation.Fixture.ExtraFile,
) ![]u8 {
    const original = try support.makePackage(fixture, arch, version, name, workspace, .{
        .no_scripts = true,
        .control_fields = control_fields,
        .extra_files = files,
    });
    defer fixture.allocator.free(original);
    const source = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_{s}_data.source", .{ workspace, name, version });
    defer fixture.allocator.free(source);
    for (links) |link| {
        const relative = try support.path(fixture.allocator, source, link.path);
        defer fixture.allocator.free(relative);
        try fixture.directory(std.fs.path.dirname(relative).?);
        try fixture.dir.symLink(fixture.io, link.target, relative, .{});
    }
    const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_{s}_links.deb", .{ workspace, name, version });
    defer fixture.allocator.free(destination);
    return fixture.buildPackage(source, destination, .{});
}

fn expectLink(case: *support.Scenario, relative: []const u8, literal: []const u8) !void {
    for ([_][]const u8{ case.reference_root, case.native_root }) |root_path| {
        var dir = try foundation.guardedRoot(case.fixture.io, root_path);
        defer dir.close(case.fixture.io);
        var buffer: [root_fs.maximum_link_target_bytes]u8 = undefined;
        const actual = try (root_fs.Root.init(case.fixture.io, dir)).readSymbolicLink(try root_fs.Path.initPackage(relative), &buffer);
        if (!std.mem.eql(u8, actual, literal)) {
            std.debug.print("{s}: {s} -> {s}, expected {s}\n", .{ root_path, relative, actual, literal });
            return error.WrongSymbolicLink;
        }
    }
}

fn expectAbsentBoth(case: *support.Scenario, relative: []const u8) !void {
    for ([_][]const u8{ case.reference_root, case.native_root }) |root_path| {
        var dir = try foundation.guardedRoot(case.fixture.io, root_path);
        defer dir.close(case.fixture.io);
        if (try (root_fs.Root.init(case.fixture.io, dir)).entryIfExists(try root_fs.Path.initPackage(relative)) != null)
            return error.SymbolicLinkLeftBehind;
    }
}

/// Runs one install that pinned dpkg completes but debz refuses on purpose,
/// and proves the native root is untouched. dpkg 1.22.22 creates every
/// symlink from its literal bytes and never resolves it while unpacking, so
/// it installs cyclic and root-escaping chains that debz rejects at payload
/// validation. In `--oracle-only` mode both roots run pinned dpkg instead.
fn expectPayloadRefusal(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    label: []const u8,
    archive: []const u8,
    name: []const u8,
    detail: []const u8,
) !void {
    var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
    defer case.deinit();
    const destination = try support.path(fixture.allocator, case.name, "divergence");
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "install",
        .archives = &.{archive},
    }, destination) != 0) return error.UnexpectedReferenceRefusal;
    if (fixture.oracle_only) {
        const oracle = try support.path(fixture.allocator, destination, "oracle");
        defer fixture.allocator.free(oracle);
        try fixture.directory(oracle);
        if (try support.reference(fixture, dpkg, case.native_root, .{
            .operation = "install",
            .archives = &.{archive},
        }, oracle) != 0) return error.NonRepeatableReferenceInstall;
        try support.compare(fixture, case.reference_root, case.native_root, destination, false);
        return;
    }
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    var result = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "install",
        .archives = &.{archive},
        .packages = &selected,
    }, destination);
    defer result.deinit();
    if (!std.mem.eql(u8, result.value.outcome, "refused") or
        !std.mem.eql(u8, result.value.detail, detail))
    {
        std.debug.print("{s}: {s}: {s}\n", .{ label, result.value.outcome, result.value.detail });
        return error.UnexpectedPayloadRefusal;
    }
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.PayloadRefusalChangedRoot;
    try support.assertNoActiveEvidence(fixture, case.native_root);
}

/// In-archive symlink chains are compared exactly against pinned dpkg across
/// install, an upgrade that retargets a middle hop and drops a chain head, a
/// downgrade, removal, and purge. Every phase compares the whole root
/// (kind, mode, owner, mtime, and literal link bytes), `status`,
/// `info/*.list`, `info/*.md5sums`, the exit status, and the script trace.
fn chains(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const common_links = [_]Link{
        // Head first: the libcurl3t64-gnutls `so.3 -> so.4 -> so.4.8.0` order.
        .{ .path = lib ++ "/libchain.so.3", .target = "libchain.so.4" },
        // A three-hop chain, also head first, through a parent-relative hop
        // into another directory.
        .{ .path = lib ++ "/a-tool", .target = "b-tool" },
        .{ .path = lib ++ "/b-tool", .target = "../../share/" ++ chain_name ++ "/c-tool" },
        .{ .path = share ++ "/c-tool", .target = "data" },
        // Tail first, ending at a directory through an absolute hop.
        .{ .path = lib ++ "/dir-hop", .target = "/" ++ share },
        .{ .path = lib ++ "/dir-link", .target = "dir-hop" },
        // An absolute head that sorts after the whole chain it enters.
        .{ .path = share ++ "/three", .target = "/" ++ lib ++ "/libchain.so.3" },
    };
    const first = try linkPackage(fixture, arch, chain_name, "1", "", &(common_links ++ [_]Link{
        .{ .path = lib ++ "/libchain.so.4", .target = "libchain.so.4.8.0" },
        // Tail first: `libchain.so.4` already precedes this head.
        .{ .path = lib ++ "/libchain.so.5", .target = "libchain.so.4" },
    }), &.{
        .{ .path = lib ++ "/libchain.so.4.8.0", .content = "chain library 4.8.0\n" },
    });
    defer fixture.allocator.free(first);
    const second = try linkPackage(fixture, arch, chain_name, "2", "", &(common_links ++ [_]Link{
        .{ .path = lib ++ "/libchain.so.4", .target = "libchain.so.4.9.0" },
    }), &.{
        .{ .path = lib ++ "/libchain.so.4.9.0", .content = "chain library 4.9.0\n" },
    });
    defer fixture.allocator.free(second);
    const selected = [_]foundation.PackageIdentity{.{ .name = chain_name, .architecture = arch }};
    {
        var case = try support.Scenario.init(fixture, "symlink-chain", driver, dpkg, arch, false);
        defer case.deinit();
        try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &selected }, false);
        try expectLink(&case, lib ++ "/libchain.so.3", "libchain.so.4");
        try expectLink(&case, lib ++ "/libchain.so.4", "libchain.so.4.8.0");
        try expectLink(&case, share ++ "/three", "/" ++ lib ++ "/libchain.so.3");
        try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &selected }, false);
        try expectLink(&case, lib ++ "/libchain.so.4", "libchain.so.4.9.0");
        try expectAbsentBoth(&case, lib ++ "/libchain.so.5");
        try expectAbsentBoth(&case, lib ++ "/libchain.so.4.8.0");
        try case.phase(.{ .operation = "downgrade", .archives = &.{first}, .packages = &selected }, false);
        try expectLink(&case, lib ++ "/libchain.so.5", "libchain.so.4");
        try case.phase(.{ .operation = "remove", .packages = &selected }, false);
        try expectAbsentBoth(&case, lib ++ "/libchain.so.3");
        try case.phase(.{ .operation = "purge", .packages = &selected }, false);
        try expectAbsentBoth(&case, lib);
    }

    // A development package links into another package's chain, as
    // libcurl4-gnutls-dev does into libcurl3t64-gnutls. dpkg checks only the
    // paths a package ships, never where its links point, so both accept it
    // and leave it dangling once the owner is removed.
    const dev_name = chain_name ++ "-dev";
    const dev = try linkPackage(fixture, arch, dev_name, "1", "", &.{
        .{ .path = "usr/lib/" ++ dev_name ++ "/libchain.so", .target = "../" ++ chain_name ++ "/libchain.so.3" },
    }, &.{});
    defer fixture.allocator.free(dev);
    const developing = [_]foundation.PackageIdentity{.{ .name = dev_name, .architecture = arch }};
    {
        var case = try support.Scenario.init(fixture, "symlink-chain-cross-package", driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        try case.phase(.{ .operation = "install", .archives = &.{dev}, .packages = &developing }, false);
        try case.phase(.{ .operation = "purge", .packages = &selected }, false);
        try expectLink(&case, "usr/lib/" ++ dev_name ++ "/libchain.so", "../" ++ chain_name ++ "/libchain.so.3");
        try case.phase(.{ .operation = "purge", .packages = &developing }, false);
    }

    // Taking over another package's chain hop still needs `Replaces:`.
    const intruder_name = chain_name ++ "-intruder";
    const intruder_links = [_]Link{
        .{ .path = lib ++ "/libchain.so.4", .target = "libchain.so.4.8.0.intruder" },
        .{ .path = "usr/lib/" ++ intruder_name ++ "/entry", .target = "/" ++ lib ++ "/libchain.so.4" },
    };
    const replacing = try linkPackage(fixture, arch, intruder_name, "1", "Replaces: " ++ chain_name ++ "\n", &intruder_links, &.{});
    defer fixture.allocator.free(replacing);
    const intruding = [_]foundation.PackageIdentity{.{ .name = intruder_name, .architecture = arch }};
    {
        var case = try support.Scenario.init(fixture, "symlink-chain-replaces", driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        try case.phase(.{ .operation = "install", .archives = &.{replacing}, .packages = &intruding }, false);
        try case.phase(.{ .operation = "purge", .packages = &selected }, false);
        try expectLink(&case, lib ++ "/libchain.so.4", "libchain.so.4.8.0.intruder");
        try case.phase(.{ .operation = "purge", .packages = &intruding }, false);
    }
    try overwriteWithoutReplaces(fixture, driver, dpkg, arch, first, intruder_name, &intruder_links);
    std.debug.print("symlink-chain: head-first, tail-first, three-hop, cross-package, and Replaces chains match pinned dpkg\n", .{});
}

/// A package that ships another package's chain hop without `Replaces:` is
/// refused by both dpkg and debz before anything changes.
fn overwriteWithoutReplaces(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    owner_archive: []const u8,
    intruder_name: []const u8,
    links: []const Link,
) !void {
    const intruder = try linkPackage(fixture, arch, intruder_name, "2", "", links, &.{});
    defer fixture.allocator.free(intruder);
    var case = try support.Scenario.init(fixture, "symlink-chain-unreplaced", driver, dpkg, arch, false);
    defer case.deinit();
    try case.seed(owner_archive);
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const destination = try support.path(fixture.allocator, case.name, "collision");
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "install",
        .archives = &.{intruder},
    }, destination) != 1) return error.UnexpectedOwnershipConflictExit;
    const reference_log = try support.path(fixture.allocator, destination, "reference.log");
    defer fixture.allocator.free(reference_log);
    const reference_output = try support.read(fixture, reference_log, 1024 * 1024);
    defer fixture.allocator.free(reference_output);
    if (std.mem.indexOf(u8, reference_output, "trying to overwrite '/" ++ lib ++ "/libchain.so.4'") == null or
        std.mem.indexOf(u8, reference_output, "also in package " ++ chain_name ++ " ") == null)
        return error.UnexpectedOwnershipConflictDiagnostic;
    if (fixture.oracle_only) {
        const oracle = try support.path(fixture.allocator, destination, "oracle");
        defer fixture.allocator.free(oracle);
        try fixture.directory(oracle);
        if (try support.reference(fixture, dpkg, case.native_root, .{
            .operation = "install",
            .archives = &.{intruder},
        }, oracle) != 1) return error.NonRepeatableOwnershipConflict;
        try support.compare(fixture, case.reference_root, case.native_root, destination, false);
        return;
    }
    const selected = [_]foundation.PackageIdentity{.{ .name = intruder_name, .architecture = arch }};
    var result = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "install",
        .archives = &.{intruder},
        .packages = &selected,
    }, destination);
    defer result.deinit();
    if (!std.mem.eql(u8, result.value.outcome, "refused") or
        !std.mem.eql(u8, result.value.detail, "ownership_conflict"))
    {
        std.debug.print("symlink-chain-unreplaced: {s}: {s}\n", .{ result.value.outcome, result.value.detail });
        return error.UnexpectedOwnershipRefusal;
    }
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.OwnershipRefusalChangedRoot;
    try support.assertNoActiveEvidence(fixture, case.native_root);
}

/// debz keeps refusing chains that never terminate or leave the root,
/// whatever their tar order. These are deliberate, documented divergences:
/// pinned dpkg installs both archives.
fn refusals(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const cycle_name = "symlink-chain-cycle";
    const cycle = try linkPackage(fixture, arch, cycle_name, "1", "", &.{
        .{ .path = "usr/lib/" ++ cycle_name ++ "/a", .target = "b" },
        .{ .path = "usr/lib/" ++ cycle_name ++ "/b", .target = "c" },
        .{ .path = "usr/lib/" ++ cycle_name ++ "/c", .target = "/usr/lib/" ++ cycle_name ++ "/a" },
    }, &.{});
    defer fixture.allocator.free(cycle);
    try expectPayloadRefusal(fixture, driver, dpkg, arch, cycle_name, cycle, cycle_name, "archive_payload_conflicting_path");

    const escape_name = "symlink-chain-escape";
    const escape = try linkPackage(fixture, arch, escape_name, "1", "", &.{
        .{ .path = "usr/lib/" ++ escape_name ++ "/a", .target = "b" },
        .{ .path = "usr/lib/" ++ escape_name ++ "/b", .target = "../../../../outside" },
    }, &.{});
    defer fixture.allocator.free(escape);
    try expectPayloadRefusal(fixture, driver, dpkg, arch, escape_name, escape, escape_name, "archive_payload_unsafe_link");
    if (fixture.oracle_only)
        std.debug.print("symlink-chain: pinned dpkg installs cyclic and root-escaping chains repeatably\n", .{})
    else
        std.debug.print("symlink-chain: cyclic and root-escaping chains are refused before mutation; pinned dpkg installs both\n", .{});
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    try chains(fixture, driver, dpkg, arch);
    try refusals(fixture, driver, dpkg, arch);
}
