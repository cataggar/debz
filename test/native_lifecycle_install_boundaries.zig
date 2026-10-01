const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const statoverride = @import("native_lifecycle_statoverride.zig");
const fifo = @import("native_fifo_fixture.zig");

fn failureMarker(case: *support.Scenario, content: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const marker = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, support.failure });
        defer case.fixture.allocator.free(marker);
        try support.fixtureFile(case.fixture, marker, content, 0o644);
    }
}

fn assertNoConsumerTrace(case: *support.Scenario, consumer: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const trace = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, support.trace });
        defer case.fixture.allocator.free(trace);
        const bytes = try support.read(case.fixture, trace, 16 * 1024 * 1024);
        defer case.fixture.allocator.free(bytes);
        if (std.mem.indexOf(u8, bytes, consumer) != null) return error.DependentScriptRan;
    }
}

fn dependencyFailures(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const provider = "failure-provider";
    const consumer = "failure-consumer";
    const base = "packages/install-failures";
    const provider_archive = try support.makePackage(fixture, arch, "1", provider, base, .{});
    defer fixture.allocator.free(provider_archive);
    const consumer_archive = try support.makePackage(fixture, arch, "1", consumer, base, .{
        .control_fields = "Pre-Depends: " ++ provider ++ " (= 1)\n",
    });
    defer fixture.allocator.free(consumer_archive);
    const selected = [_]foundation.PackageIdentity{
        .{ .name = provider, .architecture = arch },
        .{ .name = consumer, .architecture = arch },
    };
    const actions = [_]support.Action{
        .{ .sequence = 0, .kind = "unpack", .package = provider, .architecture = arch },
        .{ .sequence = 1, .kind = "configure_pending", .package = consumer, .architecture = arch },
        .{ .sequence = 2, .kind = "unpack", .package = consumer, .architecture = arch },
        .{ .sequence = 3, .kind = "configure_pending", .package = consumer, .architecture = arch },
    };
    const groups = [_][]const []const u8{ &.{provider_archive}, &.{consumer_archive} };
    for ([_][]const u8{ "preinst", "postinst" }) |kind| {
        const label = try std.fmt.allocPrint(fixture.allocator, "pre-depends-provider-{s}-failure", .{kind});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        const marker = try std.fmt.allocPrint(fixture.allocator, "{s}@1:{s}:{s}\n", .{
            provider, kind, if (std.mem.eql(u8, kind, "preinst")) "install" else "configure",
        });
        defer fixture.allocator.free(marker);
        try failureMarker(&case, marker);
        try case.phase(.{
            .operation = "install",
            .archives = &.{ provider_archive, consumer_archive },
            .reference_groups = &groups,
            .packages = &selected,
            .ordered_actions = &actions,
        }, true);
        try assertNoConsumerTrace(&case, consumer);
    }
}

fn ownership(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const owner = "shared-file-owner";
    const challenger = "shared-file-challenger";
    const common = "usr/share/debz-shared/owned";
    const first = try support.makePackage(fixture, arch, "1", owner, "packages/ownership", .{
        .no_scripts = true,
        .extra_files = &.{.{ .path = common, .content = "owner payload\n" }},
    });
    defer fixture.allocator.free(first);
    const replacement = try support.makePackage(fixture, arch, "1", challenger, "packages/ownership", .{
        .no_scripts = true,
        .control_fields = "Replaces: " ++ owner ++ "\n",
        .extra_files = &.{.{ .path = common, .content = "replacement payload\n" }},
    });
    defer fixture.allocator.free(replacement);
    const selected = [_]foundation.PackageIdentity{.{ .name = challenger, .architecture = arch }};
    {
        var case = try support.Scenario.init(fixture, "replaces-competing-file-owner", driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        try case.phase(.{ .operation = "install", .archives = &.{replacement}, .packages = &selected }, false);
    }
    const collision = try support.makePackage(fixture, arch, "1", challenger, "packages/ownership-conflict", .{
        .no_scripts = true,
        .extra_files = &.{.{ .path = common, .content = "conflicting payload\n" }},
    });
    defer fixture.allocator.free(collision);
    var case = try support.Scenario.init(fixture, "unreplaced-competing-file-owner", driver, dpkg, arch, false);
    defer case.deinit();
    try case.seed(first);
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const destination = try support.path(fixture.allocator, case.name, "collision");
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "install",
        .archives = &.{collision},
    }, destination) != 1) return error.UnexpectedOwnershipConflictExit;
    const reference_log = try support.path(fixture.allocator, destination, "reference.log");
    defer fixture.allocator.free(reference_log);
    const reference_output = try support.read(fixture, reference_log, 1024 * 1024);
    defer fixture.allocator.free(reference_output);
    if (std.mem.indexOf(u8, reference_output, "trying to overwrite") == null or
        std.mem.indexOf(u8, reference_output, owner) == null or
        std.mem.indexOf(u8, reference_output, common) == null)
        return error.UnexpectedOwnershipConflictDiagnostic;
    if (fixture.oracle_only) {
        const oracle = try support.path(fixture.allocator, destination, "oracle");
        defer fixture.allocator.free(oracle);
        try fixture.directory(oracle);
        if (try support.reference(fixture, dpkg, case.native_root, .{
            .operation = "install",
            .archives = &.{collision},
        }, oracle) != 1) return error.NonRepeatableOwnershipConflict;
        try support.compare(fixture, case.reference_root, case.native_root, destination, false);
        return;
    }
    var result = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "install",
        .archives = &.{collision},
        .packages = &selected,
    }, destination);
    defer result.deinit();
    if (!std.mem.eql(u8, result.value.outcome, "refused") or
        !std.mem.eql(u8, result.value.detail, "ownership_conflict"))
    {
        std.debug.print("competing ownership: {s}: {s}\n", .{ result.value.outcome, result.value.detail });
        return error.UnexpectedOwnershipRefusal;
    }
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.OwnershipRefusalChangedRoot;
    try support.assertNoActiveEvidence(fixture, case.native_root);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const path = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, support.trace });
        defer fixture.allocator.free(path);
        const bytes = try support.read(fixture, path, 16 * 1024 * 1024);
        defer fixture.allocator.free(bytes);
        if (bytes.len != 0) return error.UnexpectedConflictScript;
    }
}

const fifo_name = "fifo-payload";
const fifo_base = "usr/share/" ++ fifo_name;

const Pipe = fifo.Pipe;
const Link = fifo.Link;

fn fifoArchive(
    fixture: *foundation.Fixture,
    arch: []const u8,
    version: []const u8,
    pipes: []const Pipe,
    links: []const Link,
    extra_files: []const foundation.Fixture.ExtraFile,
) ![]u8 {
    return fifoPackage(fixture, arch, fifo_name, version, "", pipes, links, extra_files);
}

fn fifoPackage(
    fixture: *foundation.Fixture,
    arch: []const u8,
    name: []const u8,
    version: []const u8,
    control_fields: []const u8,
    pipes: []const Pipe,
    links: []const Link,
    extra_files: []const foundation.Fixture.ExtraFile,
) ![]u8 {
    return fifo.build(fixture, arch, .{
        .name = name,
        .version = version,
        .control_fields = control_fields,
        .pipes = pipes,
        .links = links,
        .extra_files = extra_files,
    });
}

fn expectFifo(case: *support.Scenario, relative: []const u8, mode: u32, uid: u32, gid: u32) !void {
    return fifo.expect(case.fixture, &.{ case.reference_root, case.native_root }, relative, mode, uid, gid);
}

fn expectAbsentBoth(case: *support.Scenario, relative: []const u8) !void {
    return fifo.expectAbsent(case.fixture, &.{ case.reference_root, case.native_root }, relative);
}

/// FIFO payloads are compared exactly against pinned dpkg across install,
/// an upgrade that changes a FIFO's metadata and crosses it with a regular
/// file and a symbolic link in both directions, removal, and purge. Every
/// phase compares the whole root, including `status`, `info/*.list`, and
/// `info/*.md5sums`, the exit status, and the script trace.
fn fifoPayload(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first = try fifoArchive(fixture, arch, "1", &.{
        .{ .path = fifo_base ++ "/pipe", .mode = "0640" },
        .{ .path = fifo_base ++ "/becomes-file", .mode = "0600" },
        .{ .path = fifo_base ++ "/becomes-link", .mode = "0644" },
        .{ .path = fifo_base ++ "/obsolete", .mode = "0644" },
    }, &.{
        .{ .path = fifo_base ++ "/link-becomes-pipe", .target = "data" },
    }, &.{
        .{ .path = fifo_base ++ "/file-becomes-pipe", .content = "regular in 1\n" },
    });
    defer fixture.allocator.free(first);
    const second = try fifoArchive(fixture, arch, "2", &.{
        .{ .path = fifo_base ++ "/pipe", .mode = "2660" },
        .{ .path = fifo_base ++ "/file-becomes-pipe", .mode = "0600" },
        .{ .path = fifo_base ++ "/link-becomes-pipe", .mode = "0644" },
    }, &.{
        .{ .path = fifo_base ++ "/becomes-link", .target = "data" },
    }, &.{
        .{ .path = fifo_base ++ "/becomes-file", .content = "regular in 2\n" },
    });
    defer fixture.allocator.free(second);
    const selected = [_]foundation.PackageIdentity{.{ .name = fifo_name, .architecture = arch }};

    {
        var case = try support.Scenario.init(fixture, "fifo-payload", driver, dpkg, arch, false);
        defer case.deinit();
        try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &selected }, false);
        try expectFifo(&case, fifo_base ++ "/pipe", 0o640, 0, 0);
        try expectFifo(&case, fifo_base ++ "/becomes-file", 0o600, 0, 0);
        try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &selected }, false);
        try expectFifo(&case, fifo_base ++ "/pipe", 0o2660, 0, 0);
        try expectFifo(&case, fifo_base ++ "/file-becomes-pipe", 0o600, 0, 0);
        try expectFifo(&case, fifo_base ++ "/link-becomes-pipe", 0o644, 0, 0);
        try expectAbsentBoth(&case, fifo_base ++ "/obsolete");
        try case.phase(.{ .operation = "downgrade", .archives = &.{first}, .packages = &selected }, false);
        try expectFifo(&case, fifo_base ++ "/becomes-link", 0o644, 0, 0);
        try case.phase(.{ .operation = "remove", .packages = &selected }, false);
        try expectAbsentBoth(&case, fifo_base ++ "/pipe");
        try case.phase(.{ .operation = "purge", .packages = &selected }, false);
        try expectAbsentBoth(&case, fifo_base);
    }

    {
        // dpkg applies a stat override to a FIFO exactly as to a regular file.
        var case = try support.Scenario.init(fixture, "fifo-payload-statoverride", driver, dpkg, arch, false);
        defer case.deinit();
        const record = "#42420 #42421 0620 /" ++ fifo_base ++ "/pipe\n";
        try statoverride.seed(&case, record);
        try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &selected }, false);
        try expectFifo(&case, fifo_base ++ "/pipe", 0o620, 42420, 42421);
        try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &selected }, false);
        try expectFifo(&case, fifo_base ++ "/pipe", 0o620, 42420, 42421);
        try case.phase(.{ .operation = "remove", .packages = &selected }, false);
        try case.phase(.{ .operation = "purge", .packages = &selected }, false);
    }

    // A package that `Replaces:` the owner takes over one FIFO as a FIFO and
    // another as a regular file; removing the displaced owner leaves both,
    // and a direct purge of the replacer removes its FIFO.
    const replacer_name = "fifo-payload-replacer";
    const replacer = try fifoPackage(fixture, arch, replacer_name, "1", "Replaces: " ++ fifo_name ++ "\n", &.{
        .{ .path = fifo_base ++ "/pipe", .mode = "0600" },
    }, &.{}, &.{
        .{ .path = fifo_base ++ "/becomes-file", .content = "replacer regular\n" },
    });
    defer fixture.allocator.free(replacer);
    const replacing = [_]foundation.PackageIdentity{.{ .name = replacer_name, .architecture = arch }};
    var case = try support.Scenario.init(fixture, "fifo-payload-replaces", driver, dpkg, arch, false);
    defer case.deinit();
    try case.seed(first);
    try case.phase(.{ .operation = "install", .archives = &.{replacer}, .packages = &replacing }, false);
    try expectFifo(&case, fifo_base ++ "/pipe", 0o600, 0, 0);
    try case.phase(.{ .operation = "remove", .packages = &selected }, false);
    try case.phase(.{ .operation = "purge", .packages = &selected }, false);
    try expectFifo(&case, fifo_base ++ "/pipe", 0o600, 0, 0);
    try case.phase(.{ .operation = "purge", .packages = &replacing }, false);
    try expectAbsentBoth(&case, fifo_base ++ "/pipe");
    std.debug.print("fifo-payload: install, upgrade, downgrade, remove, purge, statoverride, and Replaces match pinned dpkg\n", .{});
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    try dependencyFailures(fixture, driver, dpkg, arch);
    try ownership(fixture, driver, dpkg, arch);
    try fifoPayload(fixture, driver, dpkg, arch);
}
