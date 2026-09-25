const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const scripts = @import("native_lifecycle_scripts.zig");
const conffile_scripts = @import("native_lifecycle_conffile_scripts.zig");
const statoverride = @import("native_lifecycle_statoverride.zig");
const diversions = @import("native_lifecycle_diversions.zig");
const metadata = @import("native_lifecycle_metadata.zig");
const alternatives = @import("native_lifecycle_alternatives.zig");
const negative = @import("native_lifecycle_negative.zig");
const options = @import("native_test_options");

const package = foundation.package;

test {
    _ = @import("native_failure_schema_validation.zig");
}

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

fn validateSelection(driver: ?[]const u8, oracle_only: bool) !void {
    if (oracle_only == (driver != null)) return error.InvalidReferenceSelection;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    var driver: ?[]const u8 = null;
    var pinned: ?[]const u8 = null;
    var workspace: ?[]const u8 = null;
    var oracle_only = false;
    var diversions_only = false;
    while (arguments.next()) |option| {
        if (std.mem.eql(u8, option, "--reference-dpkg")) {
            if (pinned != null) return error.DuplicateReference;
            pinned = arguments.next() orelse return error.MissingReferencePath;
        } else if (std.mem.eql(u8, option, "--workspace")) {
            if (workspace != null) return error.DuplicateWorkspace;
            workspace = arguments.next() orelse return error.MissingWorkspacePath;
        } else if (std.mem.eql(u8, option, "--oracle-only")) {
            if (oracle_only) return error.DuplicateSelector;
            oracle_only = true;
        } else if (std.mem.eql(u8, option, "--diversions-only")) {
            if (diversions_only) return error.DuplicateSelector;
            diversions_only = true;
        } else if (std.mem.startsWith(u8, option, "-") or driver != null) return error.InvalidArguments else {
            driver = option;
        }
    }
    try validateSelection(driver, oracle_only);
    const reference = try support.prerequisites(init, allocator, pinned);
    defer allocator.free(reference.architecture);
    var fixture = try foundation.Fixture.initWorkspace(allocator, init.io, options.repository, workspace);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    fixture.oracle_only = oracle_only;
    const selected = driver orelse "";
    if (!diversions_only) runLifecycle(&fixture, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    if (!diversions_only) scripts.run(&fixture, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    if (!diversions_only) conffile_scripts.run(&fixture, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    if (!diversions_only) statoverride.run(&fixture, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    if (!diversions_only) metadata.run(&fixture, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    if (!diversions_only) alternatives.run(&fixture, selected, reference.executable, reference.architecture, pinned != null) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    if (!diversions_only and !oracle_only) negative.run(&fixture, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    diversions.run(&fixture, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    runDiversions(&fixture, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}

test "standalone lifecycle selector requires exactly one of native driver and oracle-only" {
    try validateSelection(null, true);
    try validateSelection("driver", false);
    try std.testing.expectError(error.InvalidReferenceSelection, validateSelection(null, false));
    try std.testing.expectError(error.InvalidReferenceSelection, validateSelection("driver", true));
}

test "requested workspace is a new retained direct child of the fixture parent" {
    const a = std.testing.allocator;
    var random: [8]u8 = undefined;
    try std.testing.io.randomSecure(&random);
    const relative = try std.fmt.allocPrint(a, ".tmp/native-zig-workspace-{x}", .{std.fmt.bytesToHex(random, .lower)});
    defer a.free(relative);
    var fixture = try foundation.Fixture.initWorkspace(a, std.testing.io, options.repository, relative);
    try std.testing.expect(fixture.retain);
    try std.testing.expectError(error.PathAlreadyExists, foundation.Fixture.initWorkspace(a, std.testing.io, options.repository, relative));
    try std.testing.expectError(error.WorkspaceOutsideFixtureParent, foundation.Fixture.initWorkspace(a, std.testing.io, options.repository, ".tmp"));
    try std.testing.expectError(error.WorkspaceOutsideFixtureParent, foundation.Fixture.initWorkspace(a, std.testing.io, options.repository, ".tmp/../escape"));
    fixture.retain = false;
    fixture.diagnostics = false;
    fixture.deinit();
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

test "bootstrap archive includes essential controls, executable interpreter, checksum and plain payload" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const archive = try support.makePackage(&fixture, "arm64", "1", "debz-lifecycle-essential", "bootstrap", .{
        .control_fields = "Essential: yes\n",
        .bootstrap_shell = true,
    });
    defer std.testing.allocator.free(archive);
    const prefix = "bootstrap/debz-lifecycle-essential_1_data.source";
    const control = try support.read(&fixture, prefix ++ "/DEBIAN/control", 16 * 1024);
    defer std.testing.allocator.free(control);
    try std.testing.expect(std.mem.indexOf(u8, control, "Essential: yes\n") != null);
    const manifest = try support.read(&fixture, prefix ++ "/DEBIAN/md5sums", 16 * 1024);
    defer std.testing.allocator.free(manifest);
    try std.testing.expect(std.mem.indexOf(u8, manifest, "  bin/sh\n") != null);
    for ([_][]const u8{ prefix ++ "/bin/sh", prefix ++ "/DEBIAN/preinst", prefix ++ "/DEBIAN/postinst", prefix ++ "/DEBIAN/prerm", prefix ++ "/DEBIAN/postrm" }) |name| {
        const file = try fixture.dir.statFile(std.testing.io, name, .{});
        try std.testing.expectEqual(@as(u32, 0o755), file.permissions.toMode() & 0o777);
    }
    const listing = try std.process.run(std.testing.allocator, std.testing.io, .{
        .argv = &.{ "/usr/bin/ar", "t", archive },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer std.testing.allocator.free(listing.stdout);
    defer std.testing.allocator.free(listing.stderr);
    try std.testing.expect(listing.term == .exited and listing.term.exited == 0);
    try std.testing.expect(std.mem.indexOf(u8, listing.stdout, "data.tar\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, listing.stdout, "data.tar.gz") == null);
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

test "lifecycle request preserves reviewed order and script fault boundary" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(root);
    try fixture.directory("request");
    const report_path = try fixture.absolute("request/native.report.json");
    defer std.testing.allocator.free(report_path);
    const script = try std.fmt.allocPrint(
        std.testing.allocator,
        "#!/bin/sh\nprintf '%s' '{{\"outcome\":\"applied\"}}' > '{s}'\n",
        .{report_path},
    );
    defer std.testing.allocator.free(script);
    try fixture.write("fake-driver", script, 0o755);
    const driver = try fixture.absolute("fake-driver");
    defer std.testing.allocator.free(driver);
    const actions = [_]support.Action{
        .{ .sequence = 0, .kind = "unpack", .package = "provider", .architecture = "amd64" },
        .{ .sequence = 1, .kind = "configure_pending", .package = "consumer", .architecture = "amd64" },
        .{ .sequence = 2, .kind = "unpack", .package = "consumer", .architecture = "amd64" },
        .{ .sequence = 3, .kind = "configure_pending", .package = "consumer", .architecture = "amd64" },
    };
    var report = try support.native(&fixture, driver, root, "amd64", .{
        .operation = "install",
        .archives = &.{"package.deb"},
        .ordered_actions = &actions,
        .fault = "after_script_before_record",
    }, "request");
    defer report.deinit();
    try std.testing.expectEqualStrings("applied", report.value.outcome);
    const request_bytes = try support.read(&fixture, "request/native.request.json", 64 * 1024);
    defer std.testing.allocator.free(request_bytes);
    const Request = struct {
        operation: []const u8,
        ordered_actions: []const support.Action,
        fault: []const u8,
    };
    const request = try std.json.parseFromSlice(Request, std.testing.allocator, request_bytes, .{
        .ignore_unknown_fields = true,
    });
    defer request.deinit();
    try std.testing.expectEqualStrings("install", request.value.operation);
    try std.testing.expectEqualStrings("after_script_before_record", request.value.fault);
    try std.testing.expectEqual(actions.len, request.value.ordered_actions.len);
    for (actions, request.value.ordered_actions) |expected, actual| {
        try std.testing.expectEqual(expected.sequence, actual.sequence);
        try std.testing.expectEqualStrings(expected.kind, actual.kind);
        try std.testing.expectEqualStrings(expected.package, actual.package);
        try std.testing.expectEqualStrings(expected.architecture, actual.architecture);
    }
}

test "published compensation schema bounds count, rollback and script digest" {
    const schema_path = try std.fs.path.join(std.testing.allocator, &.{
        options.repository, "schema/native-transaction-program-v1.json",
    });
    defer std.testing.allocator.free(schema_path);
    var file = try std.Io.Dir.openFileAbsolute(std.testing.io, schema_path, .{ .follow_symlinks = false });
    defer file.close(std.testing.io);
    var reader = file.reader(std.testing.io, &.{});
    const bytes = try reader.interface.allocRemaining(std.testing.allocator, .limited(256 * 1024));
    defer std.testing.allocator.free(bytes);
    const document = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer document.deinit();
    const definitions = document.value.object.get("$defs").?.object;
    const failure = definitions.get("scriptFailure").?.object.get("properties").?.object;
    const compensations = failure.get("compensations").?.object;
    try std.testing.expectEqual(@as(i64, 8), compensations.get("maxItems").?.integer);
    try std.testing.expectEqualStrings("#/$defs/unwind", compensations.get("items").?.object.get("$ref").?.string);
    const rollback = failure.get("rollback_after_compensations").?.object.get("oneOf").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), rollback.len);
    try std.testing.expectEqualStrings("null", rollback[0].object.get("type").?.string);
    try std.testing.expectEqualStrings("integer", rollback[1].object.get("type").?.string);
    try std.testing.expectEqual(@as(i64, 0), rollback[1].object.get("minimum").?.integer);
    try std.testing.expectEqual(@as(i64, 8), rollback[1].object.get("maximum").?.integer);
    const unwind = definitions.get("unwind").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings("#/$defs/sha256", unwind.get("script_sha256").?.object.get("$ref").?.string);
    try std.testing.expectEqualStrings("^[0-9a-f]{64}$", definitions.get("sha256").?.object.get("pattern").?.string);
}
