const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");

const receiver = "debz-trigger-receiver";
const source = "debz-trigger-source";
const trigger = "debz-test-trigger";

const SettlementCase = struct { update: []const u8, member: []const u8 };
const settlement_cases = [_]SettlementCase{
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

fn copyNativeHelper(fixture: *foundation.Fixture, case: *support.Scenario, helper: []const u8) !void {
    var executable = try std.Io.Dir.cwd().openFile(fixture.io, helper, .{ .follow_symlinks = false });
    defer executable.close(fixture.io);
    var stream = executable.reader(fixture.io, &.{});
    const binary = try stream.interface.allocRemaining(fixture.allocator, .limited(16 * 1024 * 1024));
    defer fixture.allocator.free(binary);
    const reference_path = try std.fmt.allocPrint(fixture.allocator, "{s}/reference/usr/bin/dpkg-trigger", .{case.name});
    defer fixture.allocator.free(reference_path);
    const reference = try support.read(fixture, reference_path, 16 * 1024 * 1024);
    defer fixture.allocator.free(reference);
    var digest: [32]u8 = undefined;
    var reference_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(binary, &digest, .{});
    std.crypto.hash.sha2.Sha256.hash(reference, &reference_digest, .{});
    if (std.mem.eql(u8, &digest, &reference_digest)) return error.ReferenceHelperIsNotNative;
    const candidate = try std.fmt.allocPrint(fixture.allocator, "{s}/native/usr/bin/dpkg-trigger", .{case.name});
    defer fixture.allocator.free(candidate);
    try support.fixtureFile(fixture, candidate, binary, 0o755);
    const installed = try support.read(fixture, candidate, 16 * 1024 * 1024);
    defer fixture.allocator.free(installed);
    if (!std.mem.eql(u8, installed, binary)) return error.NativeHelperCopyMismatch;
}

fn runTriggerCases(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    for ([_][]const u8{ "interest-await", "interest-noawait" }) |interest| {
        const declarations = try std.fmt.allocPrint(fixture.allocator, "{s} {s}\n", .{ interest, trigger });
        defer fixture.allocator.free(declarations);
        const handler = try support.makePackage(fixture, arch, "1", receiver, interest, .{ .declarations = declarations });
        defer fixture.allocator.free(handler);
        const activation = try std.fmt.allocPrint(fixture.allocator, "activate-noawait {s}\n", .{trigger});
        defer fixture.allocator.free(activation);
        const source_archive = try support.makePackage(fixture, arch, "1", source, interest, .{
            .declarations = activation,
            .activation = trigger,
        });
        defer fixture.allocator.free(source_archive);
        for ([_]bool{ false, true }) |defer_triggers| {
            const name = try std.fmt.allocPrint(fixture.allocator, "{s}-{s}", .{
                interest, if (defer_triggers) "deferred" else "immediate",
            });
            defer fixture.allocator.free(name);
            var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
            defer case.deinit();
            try case.seed(handler);
            try copyNativeHelper(fixture, &case, helper);
            try case.phase(.{
                .operation = "install",
                .archives = &.{source_archive},
                .triggers = true,
                .defer_triggers = defer_triggers,
            }, false);
            if (defer_triggers) try case.phase(.{
                .operation = "process_triggers",
                .triggers = true,
            }, false);
        }
    }
}

fn runTriggeredFailure(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const handler = try support.makePackage(fixture, arch, "1", receiver, "failure-packages", .{
        .declarations = "interest-await " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    const activating = try support.makePackage(fixture, arch, "1", source, "failure-packages", .{
        .declarations = "activate-noawait " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(activating);
    var case = try support.Scenario.init(fixture, "triggered-postinst-failure", driver, dpkg, arch, true);
    defer case.deinit();
    try case.seed(handler);
    try copyNativeHelper(fixture, &case, helper);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const marker = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/{s}", .{
            case.name, side, support.failure,
        });
        defer fixture.allocator.free(marker);
        try support.fixtureFile(fixture, marker, receiver ++ "@1:postinst:triggered\n", 0o644);
    }
    try case.phase(.{ .operation = "install", .archives = &.{activating}, .triggers = true }, true);
}

fn processExistingQueue(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const handler = try support.makePackage(fixture, arch, "1", receiver, "queued-packages", .{
        .declarations = "interest-await " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    const activating = try support.makePackage(fixture, arch, "1", source, "queued-packages", .{});
    defer fixture.allocator.free(activating);
    var case = try support.Scenario.init(fixture, "existing-unincorporated-queue", driver, dpkg, arch, true);
    defer case.deinit();
    try case.seed(handler);
    try case.seed(activating);
    try copyNativeHelper(fixture, &case, helper);
    for ([_][]const u8{ case.reference_root, case.native_root }, [_][]const u8{ "reference", "native" }) |root, side| {
        const admindir = try std.fmt.allocPrint(fixture.allocator, "--admindir={s}/var/lib/dpkg", .{root});
        defer fixture.allocator.free(admindir);
        for ([_][]const u8{ "--no-await", "--await" }) |mode| {
            const log = try std.fmt.allocPrint(fixture.allocator, "{s}/queue-{s}-{s}.log", .{ case.name, side, mode[2..] });
            defer fixture.allocator.free(log);
            if (try support.runExit(fixture, &.{
                "/usr/bin/dpkg-trigger", admindir, "--by-package=" ++ source, mode, trigger,
            }, log) != 0) return error.FailedToSeedTriggerQueue;
        }
    }
    try case.phase(.{ .operation = "process_triggers", .triggers = true }, false);
}

fn refuseMalformedQueue(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const declaration = "interest-await " ++ trigger ++ "\n";
    const archive = try support.makePackage(fixture, arch, "1", receiver, "malformed-packages", .{ .declarations = declaration });
    defer fixture.allocator.free(archive);
    var case = try support.Scenario.init(fixture, "malformed-trigger-queue", driver, dpkg, arch, true);
    defer case.deinit();
    try case.seed(archive);
    try copyNativeHelper(fixture, &case, helper);
    try fixture.write("malformed-trigger-queue/native/var/lib/dpkg/triggers/Unincorp", "invalid\x00trigger -\n", 0o644);
    const excludes: []const []const u8 = &.{ foundation.guard, "usr/bin/dpkg-trigger" };
    const before = try foundation.captureRealRoot(fixture.allocator, fixture.io, case.native_root, .{}, excludes);
    defer fixture.allocator.free(before);
    try fixture.directory("malformed-trigger-queue/refusal");
    var report = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "process_triggers",
        .triggers = true,
    }, "malformed-trigger-queue/refusal");
    defer report.deinit();
    if (!std.mem.eql(u8, report.value.outcome, "refused") and
        !std.mem.eql(u8, report.value.outcome, "handoff"))
        return error.MalformedQueueWasNotRefused;
    const after = try foundation.captureRealRoot(fixture.allocator, fixture.io, case.native_root, .{}, excludes);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.MalformedQueueRefusalChangedRoot;
    try support.assertNoActiveEvidence(fixture, case.native_root);
}

fn runDivertedTrigger(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const name = "diversion-lifecycle";
    const route = "usr/share/diversion-lifecycle/data";
    const watcher = try support.makePackage(fixture, arch, "1", receiver, "diverted-packages", .{
        .declarations = "interest-noawait /" ++ route ++ ".distrib\n",
    });
    defer fixture.allocator.free(watcher);
    const first = try support.makePackage(fixture, arch, "1", name, "diverted-packages", .{});
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, arch, "2", name, "diverted-packages", .{});
    defer fixture.allocator.free(second);
    var case = try support.Scenario.init(fixture, "diverted-file-trigger", driver, dpkg, arch, true);
    defer case.deinit();
    for ([_][]const u8{ "reference", "native" }) |label| {
        const record = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/var/lib/dpkg/diversions", .{ case.name, label });
        defer fixture.allocator.free(record);
        try support.fixtureFile(fixture, record, "/" ++ route ++ "\n/" ++ route ++ ".distrib\n:\n", 0o644);
    }
    try case.seed(watcher);
    try copyNativeHelper(fixture, &case, helper);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    try case.phase(.{ .operation = "install", .archives = &.{first}, .triggers = true }, false);
    try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .triggers = true }, false);
    try case.phase(.{ .operation = "remove", .packages = &selected, .triggers = true }, false);
    try case.phase(.{ .operation = "purge", .packages = &selected, .triggers = true }, false);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    const driver = arguments.next() orelse return error.MissingNativeDriver;
    var helper: ?[]const u8 = null;
    var pinned: ?[]const u8 = null;
    var diversions_only = false;
    while (arguments.next()) |option| {
        if (std.mem.eql(u8, option, "--native-helper")) {
            if (helper != null) return error.DuplicateHelper;
            helper = arguments.next() orelse return error.MissingNativeHelper;
        } else if (std.mem.eql(u8, option, "--reference-dpkg")) {
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
    const selected = helper orelse return error.MissingNativeHelper;
    if (!diversions_only) {
        runTriggerCases(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
            try support.assertHostUnchanged(allocator, init.io, reference.before);
            return err;
        };
        runTriggeredFailure(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
            try support.assertHostUnchanged(allocator, init.io, reference.before);
            return err;
        };
        processExistingQueue(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
            try support.assertHostUnchanged(allocator, init.io, reference.before);
            return err;
        };
        refuseMalformedQueue(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
            try support.assertHostUnchanged(allocator, init.io, reference.before);
            return err;
        };
    }
    runDivertedTrigger(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}

test "trigger helper exclusion cannot hide package status and queue mutations" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("native", "amd64");
    defer std.testing.allocator.free(right);
    try fixture.write("reference/usr/bin/dpkg-trigger", "reference", 0o755);
    try fixture.write("native/usr/bin/dpkg-trigger", "native", 0o755);
    try fixture.directory("observation");
    try support.compare(&fixture, left, right, "observation", true);
    try fixture.write("native/var/lib/dpkg/triggers/Unincorp", "a package -\n", 0o644);
    try std.testing.expectError(error.NativeDpkgTriggerMismatch, support.compare(&fixture, left, right, "observation", true));
    try fixture.dir.deleteFile(std.testing.io, "native/var/lib/dpkg/triggers/Unincorp");
    try fixture.write("native/var/lib/dpkg/status", "Package: receiver\nStatus: install ok triggers-pending\nTriggers-Pending: b a\n\n", 0o644);
    try std.testing.expectError(error.NativeDpkgTriggerMismatch, support.compare(&fixture, left, right, "observation", true));
}

test "trigger-only reference requires a disposable root before execution" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    try std.testing.expectError(error.NotDisposableRoot, support.reference(
        &fixture,
        "/usr/bin/dpkg",
        "/",
        .{ .operation = "process_triggers", .triggers = true },
        "unused",
    ));
    try support.absent(&fixture, "unused/reference.log");
}

test "reference settlement matrix retains all 24 routes and 16 eligible follow-ups" {
    try std.testing.expectEqual(@as(usize, 24), settlement_cases.len);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var seen: std.StringHashMap(void) = .init(arena.allocator());
    defer seen.deinit();
    var eligible: usize = 0;
    var postrm_successes: usize = 0;
    for (settlement_cases) |item| {
        const identity = try std.fmt.allocPrint(arena.allocator(), "{s}/{s}", .{ item.update, item.member });
        try std.testing.expect(!seen.contains(identity));
        try seen.put(identity, {});
        if (!std.mem.eql(u8, item.update, "rollback") and
            !std.mem.eql(u8, item.update, "postinst-failure"))
        {
            eligible += 1;
            if (!std.mem.eql(u8, item.update, "unwind-success")) postrm_successes += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 16), eligible);
    try std.testing.expectEqual(@as(usize, 15), postrm_successes);
    const corpus_path = try std.fs.path.join(std.testing.allocator, &.{
        options.repository, "src/fixtures/native-diversion-success-settlement-v1.json",
    });
    defer std.testing.allocator.free(corpus_path);
    var file = try std.Io.Dir.openFileAbsolute(std.testing.io, corpus_path, .{ .follow_symlinks = false });
    defer file.close(std.testing.io);
    var reader = file.reader(std.testing.io, &.{});
    const document = try reader.interface.allocRemaining(std.testing.allocator, .limited(64 * 1024));
    defer std.testing.allocator.free(document);
    const corpus = try std.json.parseFromSlice(
        []SettlementCase,
        std.testing.allocator,
        document,
        .{ .ignore_unknown_fields = true },
    );
    defer corpus.deinit();
    try std.testing.expectEqual(postrm_successes, corpus.value.len);
    for (corpus.value) |profile| {
        var found = false;
        for (settlement_cases) |item| {
            if (std.mem.eql(u8, item.update, profile.update) and
                std.mem.eql(u8, item.member, profile.member) and
                !std.mem.eql(u8, item.update, "rollback") and
                !std.mem.eql(u8, item.update, "unwind-success") and
                !std.mem.eql(u8, item.update, "postinst-failure"))
            {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

test "private trigger helper cannot alias the reference binary" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    var case = try support.Scenario.init(&fixture, "helper-auth", "driver", "/usr/bin/dpkg", "amd64", true);
    defer case.deinit();
    try std.testing.expectError(error.ReferenceHelperIsNotNative, copyNativeHelper(
        &fixture,
        &case,
        "/usr/bin/dpkg-trigger",
    ));
}
