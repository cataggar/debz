const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

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

fn unsupportedArchive(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const name = "unsupported-special";
    const workspace = "packages/unsupported";
    const original = try support.makePackage(fixture, arch, "1", name, workspace, .{ .no_scripts = true });
    defer fixture.allocator.free(original);
    const source = workspace ++ "/" ++ name ++ "_1_data.source";
    const fifo = source ++ "/usr/share/" ++ name ++ "/pipe";
    const fifo_absolute = try fixture.absolute(fifo);
    defer fixture.allocator.free(fifo_absolute);
    try fixture.run(&.{ "/usr/bin/mkfifo", fifo_absolute }, workspace ++ "/mkfifo.log", 10);
    const archive = try fixture.buildPackage(source, workspace ++ "/" ++ name ++ "_special.deb", .{});
    defer fixture.allocator.free(archive);
    var case = try support.Scenario.init(fixture, "unsupported-fifo-payload", driver, dpkg, arch, false);
    defer case.deinit();
    const destination = try support.path(fixture.allocator, case.name, "install");
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const status = try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "install",
        .archives = &.{archive},
    }, destination);
    if (status != 0) return error.UnexpectedSpecialFileReferenceOutcome;
    const reference_pipe = try std.fmt.allocPrint(fixture.allocator, "{s}/reference/usr/share/{s}/pipe", .{ case.name, name });
    defer fixture.allocator.free(reference_pipe);
    const installed = try fixture.dir.statFile(fixture.io, reference_pipe, .{ .follow_symlinks = false });
    if (installed.kind != .named_pipe) return error.ReferenceDidNotInstallFifo;
    if (fixture.oracle_only) {
        const oracle = try support.path(fixture.allocator, destination, "oracle");
        defer fixture.allocator.free(oracle);
        try fixture.directory(oracle);
        if (try support.reference(fixture, dpkg, case.native_root, .{
            .operation = "install",
            .archives = &.{archive},
        }, oracle) != 0) return error.NonRepeatableFifoInstall;
        try support.compare(fixture, case.reference_root, case.native_root, destination, false);
        return;
    }
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    var result = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "install",
        .archives = &.{archive},
        .packages = &selected,
    }, destination);
    defer result.deinit();
    if (!std.mem.eql(u8, result.value.outcome, "refused") or
        !std.mem.eql(u8, result.value.detail, "archive_payload_unsupported_file_type"))
    {
        std.debug.print("unsupported FIFO: dpkg exit {d}, native {s}: {s}\n", .{ status, result.value.outcome, result.value.detail });
        return error.UnexpectedArchiveRefusal;
    }
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.UnsupportedArchiveChangedRoot;
    try support.assertNoActiveEvidence(fixture, case.native_root);
    const reference = try foundation.capture(fixture.allocator, fixture.io, case.reference_root);
    defer fixture.allocator.free(reference);
    if (std.mem.eql(u8, reference, after)) return error.UnsupportedArchiveAccidentallyMatched;
    for ([_][]const u8{ "reference", "native" }) |side| {
        const trace = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, support.trace });
        defer fixture.allocator.free(trace);
        const bytes = try support.read(fixture, trace, 16 * 1024 * 1024);
        defer fixture.allocator.free(bytes);
        if (bytes.len != 0) return error.UnsupportedArchiveRanScript;
    }
    std.debug.print("unsupported-fifo-payload/install: dpkg exit {d}, native refused before mutation\n", .{status});
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    try dependencyFailures(fixture, driver, dpkg, arch);
    try ownership(fixture, driver, dpkg, arch);
    try unsupportedArchive(fixture, driver, dpkg, arch);
}
