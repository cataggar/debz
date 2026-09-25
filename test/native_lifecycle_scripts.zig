const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

const package = foundation.package;

fn selected(name: []const u8, arch: []const u8) [1]foundation.PackageIdentity {
    return .{.{ .name = name, .architecture = arch }};
}

fn failures(case: *support.Scenario, markers: []const []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const relative = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, support.failure });
        defer case.fixture.allocator.free(relative);
        if (markers.len == 0) {
            support.absent(case.fixture, relative) catch |err| {
                if (err != error.UnexpectedArtifact) return err;
                try case.fixture.dir.deleteFile(case.fixture.io, relative);
            };
        } else {
            const text = try std.mem.join(case.fixture.allocator, "\n", markers);
            defer case.fixture.allocator.free(text);
            const content = try std.fmt.allocPrint(case.fixture.allocator, "{s}\n", .{text});
            defer case.fixture.allocator.free(content);
            try support.fixtureFile(case.fixture, relative, content, 0o644);
        }
    }
}

fn verifyTrace(case: *support.Scenario, needle: []const u8) !void {
    const relative = try std.fmt.allocPrint(case.fixture.allocator, "{s}/reference/{s}", .{ case.name, support.trace });
    defer case.fixture.allocator.free(relative);
    const trace = try support.read(case.fixture, relative, 16 * 1024 * 1024);
    defer case.fixture.allocator.free(trace);
    if (std.mem.indexOf(u8, trace, needle) == null) return error.MissingScriptInvocation;
}

fn statusContains(case: *support.Scenario, needle: []const u8) !void {
    const relative = try std.fmt.allocPrint(case.fixture.allocator, "{s}/reference/var/lib/dpkg/status", .{case.name});
    defer case.fixture.allocator.free(relative);
    const text = try support.read(case.fixture, relative, 64 * 1024 * 1024);
    defer case.fixture.allocator.free(text);
    if (std.mem.indexOf(u8, text, needle) == null) return error.WrongPackageStatus;
}

fn runScriptFailures(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, first: []const u8, second: []const u8) !void {
    const identities = selected(package, arch);
    {
        var case = try support.Scenario.init(fixture, "script-upgrade-unconfigured", driver, dpkg, arch, false);
        defer case.deinit();
        try case.seedWith(first, false);
        try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &identities }, false);
    }
    {
        var case = try support.Scenario.init(fixture, "script-fresh-abort-install-failure", driver, dpkg, arch, false);
        defer case.deinit();
        try failures(&case, &.{ package ++ "@1:preinst:install", package ++ "@1:postrm:abort-install" });
        try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &identities }, true);
        try verifyTrace(&case, package ++ "@1:postrm\t");
    }
    const without_postrm = try support.makePackage(fixture, arch, "1", package, "packages/no-postrm", .{
        .scripts = .{ .omit_postrm = true },
    });
    defer fixture.allocator.free(without_postrm);
    {
        var case = try support.Scenario.init(fixture, "script-fresh-preinst-no-postrm", driver, dpkg, arch, false);
        defer case.deinit();
        try failures(&case, &.{package ++ "@1:preinst:install"});
        try case.phase(.{ .operation = "install", .archives = &.{without_postrm}, .packages = &identities }, true);
    }

    const upgrades = [_]struct { name: []const u8, markers: []const []const u8, failed: bool }{
        .{ .name = "old-prerm", .markers = &.{package ++ "@1:prerm:upgrade"}, .failed = false },
        .{ .name = "failed-upgrade-prerm", .markers = &.{ package ++ "@1:prerm:upgrade", package ++ "@2:prerm:failed-upgrade" }, .failed = true },
        .{ .name = "new-preinst", .markers = &.{package ++ "@2:preinst:upgrade"}, .failed = true },
        .{ .name = "old-postrm", .markers = &.{package ++ "@1:postrm:upgrade"}, .failed = false },
        .{ .name = "failed-upgrade-postrm", .markers = &.{ package ++ "@1:postrm:upgrade", package ++ "@2:postrm:failed-upgrade" }, .failed = true },
        .{ .name = "new-postinst", .markers = &.{package ++ "@2:postinst:configure"}, .failed = true },
        .{ .name = "abort-upgrade-postinst", .markers = &.{ package ++ "@2:preinst:upgrade", package ++ "@1:postinst:abort-upgrade" }, .failed = true },
        .{ .name = "abort-upgrade-preinst", .markers = &.{ package ++ "@1:postrm:upgrade", package ++ "@2:postrm:failed-upgrade", package ++ "@1:preinst:abort-upgrade" }, .failed = true },
        .{ .name = "abort-upgrade-postrm", .markers = &.{ package ++ "@1:postrm:upgrade", package ++ "@2:postrm:failed-upgrade", package ++ "@2:postrm:abort-upgrade" }, .failed = true },
    };
    for (upgrades) |entry| {
        const label = try std.fmt.allocPrint(fixture.allocator, "script-upgrade-{s}-failure", .{entry.name});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        try failures(&case, entry.markers);
        const rollback: []const []const u8 = for (entry.markers) |marker| {
            if (std.mem.eql(u8, marker, package ++ "@2:postrm:failed-upgrade"))
                break &.{foundation.payload ++ "/current"};
        } else &.{};
        try case.phase(.{
            .operation = "upgrade",
            .archives = &.{second},
            .packages = &identities,
            .rollback_links = rollback,
        }, entry.failed);
        if (std.mem.eql(u8, entry.name, "new-postinst")) {
            try statusContains(&case, "Status: install ok half-configured");
            try failures(&case, &.{});
            try case.phase(.{ .operation = "configure", .archives = &.{second}, .packages = &identities }, false);
        }
    }
    for ([_]struct { name: []const u8, operation: []const u8, markers: []const []const u8 }{
        .{ .name = "remove-prerm", .operation = "remove", .markers = &.{package ++ "@1:prerm:remove"} },
        .{ .name = "remove-abort-remove", .operation = "remove", .markers = &.{ package ++ "@1:prerm:remove", package ++ "@1:postinst:abort-remove" } },
        .{ .name = "remove-postrm", .operation = "remove", .markers = &.{package ++ "@1:postrm:remove"} },
        .{ .name = "purge-postrm", .operation = "purge", .markers = &.{package ++ "@1:postrm:purge"} },
    }) |entry| {
        const label = try std.fmt.allocPrint(fixture.allocator, "script-{s}-failure", .{entry.name});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        try failures(&case, entry.markers);
        try case.phase(.{ .operation = entry.operation, .packages = &identities }, true);
    }
}

fn runDependencies(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const provider = "debz-lifecycle-provider";
    const consumer = "debz-lifecycle-consumer";
    const provider_archive = try support.makePackage(fixture, arch, "1", provider, "packages/dependencies", .{});
    defer fixture.allocator.free(provider_archive);
    const barrier = "if [ \"$DPKG_MAINTSCRIPT_NAME\" = preinst ]; then\n" ++
        "    configured=no\n" ++
        "    while IFS= read -r invocation; do\n" ++
        "        case \"$invocation\" in\n" ++
        "            'debz-lifecycle-provider@1:postinst'*) configured=yes ;;\n" ++
        "        esac\n" ++
        "    done < /" ++ support.trace ++ "\n" ++
        "    [ \"$configured\" = yes ] || exit 24\n" ++
        "fi\n";
    const consumer_archive = try support.makePackage(fixture, arch, "1", consumer, "packages/dependencies", .{
        .control_fields = "Pre-Depends: " ++ provider ++ " (= 1)\n",
        .scripts = .{ .after_failure = barrier },
    });
    defer fixture.allocator.free(consumer_archive);
    {
        var case = try support.Scenario.init(fixture, "script-pre-depends-barrier", driver, dpkg, arch, false);
        defer case.deinit();
        const names = [_]foundation.PackageIdentity{
            .{ .name = provider, .architecture = arch },
            .{ .name = consumer, .architecture = arch },
        };
        const actions = [_]support.Action{
            .{ .sequence = 0, .kind = "unpack", .package = provider, .architecture = arch },
            .{ .sequence = 1, .kind = "configure_pending", .package = consumer, .architecture = arch },
            .{ .sequence = 2, .kind = "unpack", .package = consumer, .architecture = arch },
            .{ .sequence = 3, .kind = "configure_pending", .package = consumer, .architecture = arch },
        };
        const provider_group = [_][]const u8{provider_archive};
        const consumer_group = [_][]const u8{consumer_archive};
        const groups = [_][]const []const u8{ &provider_group, &consumer_group };
        try case.phase(.{
            .operation = "install",
            .archives = &.{ provider_archive, consumer_archive },
            .reference_groups = &groups,
            .packages = &names,
            .ordered_actions = &actions,
        }, false);
        try verifyTrace(&case, consumer ++ "@1:preinst\t");
    }
    const cycle_a = "debz-lifecycle-cycle-a";
    const cycle_b = "debz-lifecycle-cycle-b";
    var archives: [2][]u8 = undefined;
    for ([_][]const u8{ cycle_a, cycle_b }, [_][]const u8{ cycle_b, cycle_a }, 0..) |name, peer, index| {
        const control = try std.fmt.allocPrint(fixture.allocator, "Depends: {s} (= 1)\n", .{peer});
        defer fixture.allocator.free(control);
        const check = try std.fmt.allocPrint(
            fixture.allocator,
            "if [ \"$DPKG_MAINTSCRIPT_NAME\" = postinst ]; then\n    [ -f /usr/share/{s}/data ] || exit 24\nfi\n",
            .{peer},
        );
        defer fixture.allocator.free(check);
        archives[index] = try support.makePackage(fixture, arch, "1", name, "packages/cycle", .{
            .control_fields = control,
            .scripts = .{ .after_failure = check },
        });
    }
    defer for (archives) |archive| fixture.allocator.free(archive);
    var case = try support.Scenario.init(fixture, "script-dependency-cycle", driver, dpkg, arch, false);
    defer case.deinit();
    const names = [_]foundation.PackageIdentity{
        .{ .name = cycle_a, .architecture = arch },
        .{ .name = cycle_b, .architecture = arch },
    };
    try case.phase(.{ .operation = "install", .archives = &archives, .packages = &names }, false);
}

fn runBootstrap(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const name = "debz-lifecycle-essential";
    const archive = try support.makePackage(fixture, arch, "1", name, "packages/bootstrap", .{
        .control_fields = "Essential: yes\n",
        .bootstrap_shell = true,
    });
    defer fixture.allocator.free(archive);
    var case = try support.Scenario.initWith(fixture, "script-essential-bootstrap", driver, dpkg, arch, false, true);
    defer case.deinit();
    for ([_][]const u8{ "reference", "native" }) |side| {
        const shell = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/bin/sh", .{ case.name, side });
        defer fixture.allocator.free(shell);
        try support.absent(fixture, shell);
    }
    try fixture.run(&.{ "dpkg-deb", "--extract", archive, case.reference_root }, "script-essential-bootstrap/bootstrap.log", 120);
    const names = selected(name, arch);
    const actions = [_]support.Action{
        .{ .sequence = 0, .kind = "bootstrap_extract", .package = name, .architecture = arch },
        .{ .sequence = 1, .kind = "unpack", .package = name, .architecture = arch },
        .{ .sequence = 2, .kind = "configure_pending", .package = name, .architecture = arch },
    };
    try case.phase(.{ .operation = "install", .archives = &.{archive}, .packages = &names, .ordered_actions = &actions }, false);
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first = try support.makePackage(fixture, arch, "1", package, "packages/script-flows", .{});
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, arch, "2", package, "packages/script-flows", .{});
    defer fixture.allocator.free(second);
    try runScriptFailures(fixture, driver, dpkg, arch, first, second);
    try runDependencies(fixture, driver, dpkg, arch);
    try runBootstrap(fixture, driver, dpkg, arch);
}
