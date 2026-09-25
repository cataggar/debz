const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");
const root_fs = @import("debz").root_fs;

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
        const scriptless_workspace = try std.fmt.allocPrint(fixture.allocator, "{s}-scriptless", .{interest});
        defer fixture.allocator.free(scriptless_workspace);
        const scriptless = try support.makePackage(fixture, arch, "1", receiver, scriptless_workspace, .{
            .declarations = declarations,
            .postinst = false,
        });
        defer fixture.allocator.free(scriptless);
        const scriptless_source = try support.makePackage(fixture, arch, "1", source, scriptless_workspace, .{
            .declarations = "activate-await " ++ trigger ++ "\n",
        });
        defer fixture.allocator.free(scriptless_source);
        for ([_]bool{ false, true }) |new_handler| for ([_]bool{ false, true }) |defer_triggers| {
            const name = try std.fmt.allocPrint(fixture.allocator, "{s}-no-postinst-{s}-{s}", .{
                interest, if (new_handler) "new" else "installed", if (defer_triggers) "deferred" else "immediate",
            });
            defer fixture.allocator.free(name);
            var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
            defer case.deinit();
            if (!new_handler) try case.seed(scriptless);
            try copyNativeHelper(fixture, &case, helper);
            try case.phase(.{
                .operation = "install",
                .archives = if (new_handler) &.{ scriptless, scriptless_source } else &.{scriptless_source},
                .triggers = true,
                .defer_triggers = defer_triggers,
            }, false);
            if (defer_triggers) try case.phase(.{ .operation = "process_triggers", .triggers = true }, false);
            for ([_][]const u8{ "reference", "native" }) |side| {
                const script = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/var/lib/dpkg/info/{s}.postinst", .{
                    name, side, receiver,
                });
                defer fixture.allocator.free(script);
                try support.absent(fixture, script);
                const trace_path = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/{s}", .{ name, side, support.trace });
                defer fixture.allocator.free(trace_path);
                const recorded = try support.read(fixture, trace_path, 64 * 1024);
                defer fixture.allocator.free(recorded);
                if (std.mem.indexOf(u8, recorded, receiver ++ "@1:postinst") != null)
                    return error.ScriptlessHandlerWasCalled;
            }
        };
        for ([_][]const u8{ "activate-await", "activate-noawait" }) |activation| {
            const declarations_source = try std.fmt.allocPrint(fixture.allocator, "{s} {s}\n", .{ activation, trigger });
            defer fixture.allocator.free(declarations_source);
            const workspace = try std.fmt.allocPrint(fixture.allocator, "{s}-{s}-source", .{ interest, activation });
            defer fixture.allocator.free(workspace);
            const source_archive = try support.makePackage(fixture, arch, "1", source, workspace, .{
                .declarations = declarations_source,
            });
            defer fixture.allocator.free(source_archive);
            for ([_]bool{ false, true }) |defer_triggers| {
                const name = try std.fmt.allocPrint(fixture.allocator, "{s}-{s}-{s}", .{
                    interest, activation, if (defer_triggers) "deferred" else "immediate",
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
                if (defer_triggers) try case.phase(.{ .operation = "process_triggers", .triggers = true }, false);
            }
        }
    }
    const default_handler = try support.makePackage(fixture, arch, "1", receiver, "aliases", .{
        .declarations = "interest " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(default_handler);
    const default_source = try support.makePackage(fixture, arch, "1", source, "aliases", .{
        .declarations = "activate " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(default_source);
    var aliases = try support.Scenario.init(fixture, "default-await-aliases", driver, dpkg, arch, true);
    defer aliases.deinit();
    try aliases.seed(default_handler);
    try copyNativeHelper(fixture, &aliases, helper);
    try aliases.phase(.{ .operation = "install", .archives = &.{default_source}, .triggers = true }, false);

    const upgraded = try support.makePackage(fixture, arch, "2", receiver, "postinst-removed", .{
        .declarations = "interest-await " ++ trigger ++ "\n",
        .postinst = false,
    });
    defer fixture.allocator.free(upgraded);
    var removed = try support.Scenario.init(fixture, "upgrade-removes-postinst", driver, dpkg, arch, true);
    defer removed.deinit();
    try removed.seed(default_handler);
    try copyNativeHelper(fixture, &removed, helper);
    try removed.phase(.{ .operation = "upgrade", .archives = &.{upgraded}, .triggers = true }, false);
    try removed.phase(.{ .operation = "install", .archives = &.{default_source}, .triggers = true }, false);
}

fn runTriggeredFailure(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const handler = try support.makePackage(fixture, arch, "1", receiver, "failure-packages", .{
        .declarations = "interest-await " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    for ([_][]const u8{ "activate-await", "activate-noawait" }) |activation| {
        const declaration = try std.fmt.allocPrint(fixture.allocator, "{s} {s}\n", .{ activation, trigger });
        defer fixture.allocator.free(declaration);
        const workspace = try std.fmt.allocPrint(fixture.allocator, "{s}-failure-packages", .{activation});
        defer fixture.allocator.free(workspace);
        const activating = try support.makePackage(fixture, arch, "1", source, workspace, .{
            .declarations = declaration,
        });
        defer fixture.allocator.free(activating);
        const name = try std.fmt.allocPrint(fixture.allocator, "trigger-failure-{s}", .{
            if (std.mem.eql(u8, activation, "activate-await")) "await" else "noawait",
        });
        defer fixture.allocator.free(name);
        var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
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
}

fn runTriggerLifecycle(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const mixed_handler = try support.makePackage(fixture, arch, "1", receiver, "mixed-packages", .{
        .declarations = "interest-await debz-a\ninterest-noawait debz-b\ninterest-await /usr/share/" ++ source ++ "\n",
    });
    defer fixture.allocator.free(mixed_handler);
    const mixed_source = try support.makePackage(fixture, arch, "1", source, "mixed-packages", .{
        .declarations = "activate-await debz-a\nactivate-await debz-b\n",
    });
    defer fixture.allocator.free(mixed_source);
    var mixed = try support.Scenario.init(fixture, "mixed-trigger-order", driver, dpkg, arch, true);
    defer mixed.deinit();
    try mixed.seed(mixed_handler);
    try copyNativeHelper(fixture, &mixed, helper);
    try mixed.phase(.{
        .operation = "install", .archives = &.{mixed_source}, .triggers = true, .defer_triggers = true,
    }, false);
    try mixed.phase(.{ .operation = "process_triggers", .triggers = true }, false);

    const file_handler = try support.makePackage(fixture, arch, "1", receiver, "file-packages", .{
        .declarations = "interest-noawait /usr/share/" ++ source ++ "\n",
    });
    defer fixture.allocator.free(file_handler);
    const first = try support.makePackage(fixture, arch, "1", source, "file-packages", .{});
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, arch, "2", source, "file-packages", .{});
    defer fixture.allocator.free(second);
    var file_case = try support.Scenario.init(fixture, "file-trigger-lifecycle", driver, dpkg, arch, true);
    defer file_case.deinit();
    try file_case.seed(file_handler);
    try copyNativeHelper(fixture, &file_case, helper);
    try file_case.phase(.{ .operation = "install", .archives = &.{first}, .triggers = true }, false);
    try file_case.phase(.{ .operation = "upgrade", .archives = &.{second}, .triggers = true }, false);
    const selected_source = [_]foundation.PackageIdentity{.{ .name = source, .architecture = arch }};
    const selected_receiver = [_]foundation.PackageIdentity{.{ .name = receiver, .architecture = arch }};
    try file_case.phase(.{ .operation = "remove", .packages = &selected_source, .triggers = true }, false);
    try file_case.phase(.{ .operation = "purge", .packages = &selected_source, .triggers = true }, false);
    try file_case.phase(.{ .operation = "purge", .packages = &selected_receiver, .triggers = true }, false);

    const handler = try support.makePackage(fixture, arch, "1", receiver, "activation-packages", .{
        .declarations = "interest-noawait " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    const activating = try support.makePackage(fixture, arch, "1", source, "activation-packages", .{
        .declarations = "activate-noawait " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(activating);
    for ([_]bool{ false, true }) |source_first| {
        var case = try support.Scenario.init(
            fixture, if (source_first) "new-handler-source-first" else "new-handler-receiver-first",
            driver, dpkg, arch, true,
        );
        defer case.deinit();
        try copyNativeHelper(fixture, &case, helper);
        try case.phase(.{
            .operation = "install",
            .archives = if (source_first) &.{ activating, handler } else &.{ handler, activating },
            .triggers = true,
        }, false);
    }
    const script_source = try support.makePackage(fixture, arch, "1", source, "script-activation", .{
        .activations = &.{ trigger, trigger },
    });
    defer fixture.allocator.free(script_source);
    for ([_]bool{ false, true }) |defer_triggers| {
        var case = try support.Scenario.init(
            fixture, if (defer_triggers) "script-activation-coalesces-deferred" else "script-activation-coalesces",
            driver, dpkg, arch, true,
        );
        defer case.deinit();
        try case.seed(handler);
        try copyNativeHelper(fixture, &case, helper);
        try case.phase(.{
            .operation = "install", .archives = &.{script_source}, .triggers = true, .defer_triggers = defer_triggers,
        }, false);
        if (defer_triggers) try case.phase(.{ .operation = "process_triggers", .triggers = true }, false);
    }
    const removing = try support.makePackage(fixture, arch, "1", source, "script-removal", .{
        .activation = trigger, .activation_kind = "postrm", .activation_when = "remove",
    });
    defer fixture.allocator.free(removing);
    var removal = try support.Scenario.init(fixture, "postrm-script-activation", driver, dpkg, arch, true);
    defer removal.deinit();
    try removal.seed(handler);
    try removal.seed(removing);
    try copyNativeHelper(fixture, &removal, helper);
    try removal.phase(.{ .operation = "remove", .packages = &selected_source, .triggers = true }, false);
}

fn runTriggerChains(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first_name = "debz-trigger-a";
    const second_name = "debz-trigger-b";
    const first = try support.makePackage(fixture, arch, "1", first_name, "chain-packages", .{
        .declarations = "interest-noawait debz-a\n",
        .activation = "debz-b",
        .activation_when = "triggered",
    });
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, arch, "1", second_name, "chain-packages", .{
        .declarations = "interest-noawait debz-b\n",
    });
    defer fixture.allocator.free(second);
    const source_archive = try support.makePackage(fixture, arch, "1", source, "chain-packages", .{
        .declarations = "activate-noawait debz-a\n",
    });
    defer fixture.allocator.free(source_archive);
    var chain = try support.Scenario.init(fixture, "dynamic-trigger-chain", driver, dpkg, arch, true);
    defer chain.deinit();
    try chain.seed(first);
    try chain.seed(second);
    try copyNativeHelper(fixture, &chain, helper);
    try chain.phase(.{ .operation = "install", .archives = &.{source_archive}, .triggers = true }, false);

    const loop = try support.makePackage(fixture, arch, "1", receiver, "cycle-packages", .{
        .declarations = "interest-noawait " ++ trigger ++ "\n",
        .activation = trigger,
        .activation_when = "triggered",
    });
    defer fixture.allocator.free(loop);
    const looping_source = try support.makePackage(fixture, arch, "1", source, "cycle-packages", .{
        .declarations = "activate-noawait " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(looping_source);
    var self_cycle = try support.Scenario.init(fixture, "self-cycle-no-progress", driver, dpkg, arch, true);
    defer self_cycle.deinit();
    try self_cycle.seed(loop);
    try copyNativeHelper(fixture, &self_cycle, helper);
    try self_cycle.phase(.{ .operation = "install", .archives = &.{looping_source}, .triggers = true }, true);

    const cycling_second = try support.makePackage(fixture, arch, "1", second_name, "cycle-packages", .{
        .declarations = "interest-noawait debz-b\n",
        .activation = "debz-a",
        .activation_when = "triggered",
    });
    defer fixture.allocator.free(cycling_second);
    var two_cycle = try support.Scenario.init(fixture, "two-package-cycle", driver, dpkg, arch, true);
    defer two_cycle.deinit();
    try two_cycle.seed(first);
    try two_cycle.seed(cycling_second);
    try copyNativeHelper(fixture, &two_cycle, helper);
    try two_cycle.phase(.{ .operation = "install", .archives = &.{source_archive}, .triggers = true }, true);
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

fn interruptedTriggerHandler(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const handler = try support.makePackage(fixture, arch, "1", receiver, "interruption-packages", .{
        .declarations = "interest-await " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    const activating = try support.makePackage(fixture, arch, "1", source, "interruption-packages", .{
        .declarations = "activate-await " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(activating);
    var case = try support.Scenario.init(fixture, "trigger-script-outcome-unknown", driver, dpkg, arch, true);
    defer case.deinit();
    try case.seed(handler);
    try copyNativeHelper(fixture, &case, helper);
    try fixture.directory("trigger-script-outcome-unknown/interrupted");
    var interrupted = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "install", .archives = &.{activating}, .triggers = true,
        .fault = "after_triggered_postinst_before_record",
    }, "trigger-script-outcome-unknown/interrupted");
    defer interrupted.deinit();
    if (!std.mem.eql(u8, interrupted.value.outcome, "recovery_required"))
        return error.InterruptedTriggerDidNotRequireRecovery;
    const operation_path = "trigger-script-outcome-unknown/native/var/lib/debz/root-operation-v1.json";
    const script_path = "trigger-script-outcome-unknown/native/var/lib/debz/native-lifecycle-script-v1.json";
    const authority_path = "trigger-script-outcome-unknown/native/var/lib/debz/native-trigger-authority-v1.json";
    const operation_bytes = try support.read(fixture, operation_path, 1024 * 1024);
    defer fixture.allocator.free(operation_bytes);
    const script_bytes = try support.read(fixture, script_path, 1024 * 1024);
    defer fixture.allocator.free(script_bytes);
    const authority_bytes = try support.read(fixture, authority_path, 1024 * 1024);
    defer fixture.allocator.free(authority_bytes);
    if (authority_bytes.len == 0) return error.MissingTriggerAuthority;
    const Operation = struct {
        state: []const u8,
        phase: []const u8,
        mutation_started: bool,
        program_sha256: []const u8,
        attempt_id: []const u8,
    };
    const Script = struct {
        program_sha256: []const u8,
        package: []const u8,
        version: []const u8,
        kind: []const u8,
        source: []const u8,
        script_sha256: []const u8,
        arguments: []const []const u8,
        outcome: []const u8,
        exit_code: ?u8,
    };
    const Authority = struct {
        schema: []const u8,
        program_sha256: []const u8,
        attempt_id: []const u8,
        allowed_triggers: []const []const u8,
        callers: []const struct {
            package: struct { name: []const u8, version: []const u8, architecture: []const u8 },
            source: []const u8,
            kind: []const u8,
            script_sha256: []const u8,
        },
    };
    const json_options: std.json.ParseOptions = .{ .ignore_unknown_fields = true };
    const operation = try std.json.parseFromSlice(Operation, fixture.allocator, operation_bytes, json_options);
    defer operation.deinit();
    const script = try std.json.parseFromSlice(Script, fixture.allocator, script_bytes, json_options);
    defer script.deinit();
    const authority = try std.json.parseFromSlice(Authority, fixture.allocator, authority_bytes, json_options);
    defer authority.deinit();
    const installed_script = try support.read(
        fixture, "trigger-script-outcome-unknown/native/var/lib/dpkg/info/" ++ receiver ++ ".postinst", 64 * 1024,
    );
    defer fixture.allocator.free(installed_script);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(installed_script, &digest, .{});
    const script_hash = std.fmt.bytesToHex(digest, .lower);
    const op = operation.value;
    const invocation = script.value;
    const authorization = authority.value;
    if (!std.mem.eql(u8, op.state, "recovery_required") or
        !std.mem.eql(u8, op.phase, "script") or !op.mutation_started or
        !std.mem.eql(u8, invocation.program_sha256, op.program_sha256) or
        !std.mem.eql(u8, invocation.package, receiver) or
        !std.mem.eql(u8, invocation.version, "1") or
        !std.mem.eql(u8, invocation.kind, "postinst") or
        !std.mem.eql(u8, invocation.source, "installed_package") or
        !std.mem.eql(u8, invocation.script_sha256, &script_hash) or
        invocation.arguments.len != 2 or
        !std.mem.eql(u8, invocation.arguments[0], "triggered") or
        !std.mem.eql(u8, invocation.arguments[1], trigger) or
        !std.mem.eql(u8, invocation.outcome, "in_flight") or invocation.exit_code != null or
        !std.mem.eql(u8, authorization.schema, "https://debz.dev/schema/native-trigger-authority-v1") or
        !std.mem.eql(u8, authorization.program_sha256, op.program_sha256) or
        !std.mem.eql(u8, authorization.attempt_id, op.attempt_id))
        return error.IncorrectInterruptedTriggerEvidence;
    var allowed = false;
    for (authorization.allowed_triggers) |name| if (std.mem.eql(u8, name, trigger)) {
        allowed = true;
        break;
    };
    var caller_matched = false;
    for (authorization.callers) |caller| if (std.mem.eql(u8, caller.package.name, receiver) and
        std.mem.eql(u8, caller.package.version, "1") and
        std.mem.eql(u8, caller.package.architecture, arch) and
        std.mem.eql(u8, caller.source, invocation.source) and
        std.mem.eql(u8, caller.kind, invocation.kind) and
        std.mem.eql(u8, caller.script_sha256, invocation.script_sha256))
    {
        caller_matched = true;
        break;
    };
    if (!allowed or !caller_matched) return error.IncorrectInterruptedTriggerAuthority;
    const excludes: []const []const u8 = &.{ foundation.guard, "usr/bin/dpkg-trigger" };
    const before = try foundation.captureRealRoot(fixture.allocator, fixture.io, case.native_root, .{}, excludes);
    defer fixture.allocator.free(before);
    const trace_path = "trigger-script-outcome-unknown/native/" ++ support.trace;
    const trace_bytes = try support.read(fixture, trace_path, 64 * 1024);
    defer fixture.allocator.free(trace_bytes);
    if (std.mem.count(u8, trace_bytes, "\n") != 3 or
        std.mem.indexOf(u8, trace_bytes, receiver ++ "@1:postinst\t") == null)
        return error.InterruptedTriggerHandlerWasNotExecuted;
    const absent_package = [_]foundation.PackageIdentity{.{ .name = "debz-trigger-absent", .architecture = arch }};
    for ([_]support.Phase{
        .{ .operation = "process_triggers", .triggers = true },
        .{ .operation = "purge", .packages = &absent_package, .triggers = true },
    }) |phase| {
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/blocked-{s}", .{ case.name, phase.operation });
        defer fixture.allocator.free(destination);
        try fixture.directory(destination);
        var retry = try support.native(fixture, driver, case.native_root, arch, phase, destination);
        defer retry.deinit();
        if (!std.mem.eql(u8, retry.value.outcome, "recovery_required"))
            return error.InterruptedTriggerAllowedMutation;
        for ([_][]const u8{ operation_path, script_path, authority_path }, [_][]const u8{
            operation_bytes, script_bytes, authority_bytes,
        }) |path, original| {
            const after_record = try support.read(fixture, path, 1024 * 1024);
            defer fixture.allocator.free(after_record);
            if (!std.mem.eql(u8, original, after_record)) return error.InterruptedTriggerReplacedEvidence;
        }
        const after = try foundation.captureRealRoot(fixture.allocator, fixture.io, case.native_root, .{}, excludes);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.InterruptedTriggerChangedRoot;
    }
}

fn deferredSelectionChange(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const unrelated = "debz-trigger-unrelated";
    const handler = try support.makePackage(fixture, arch, "1", receiver, "selection-packages", .{
        .declarations = "interest-await " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    const other = try support.makePackage(fixture, arch, "1", unrelated, "selection-packages", .{});
    defer fixture.allocator.free(other);
    const changing = try support.makePackage(fixture, arch, "1", source, "selection-packages", .{
        .postinst_append =
        \\status=''
        \\selected=no
        \\while IFS= read -r line; do
        \\    case "$line" in
        \\        'Package: debz-trigger-unrelated') selected=yes ;;
        \\        'Package: '*) selected=no ;;
        \\    esac
        \\    if [ "$selected" = yes ] && [ "$line" = 'Status: install ok installed' ]; then
        \\        line='Status: hold ok installed'
        \\    fi
        \\    status="$status$line
        \\"
        \\done < /var/lib/dpkg/status
        \\printf '%s' "$status" > /var/lib/dpkg/status
        \\
    });
    defer fixture.allocator.free(changing);
    var case = try support.Scenario.init(fixture, "deferred-unrelated-selection-change", driver, dpkg, arch, true);
    defer case.deinit();
    try case.seed(handler);
    try case.seed(other);
    try copyNativeHelper(fixture, &case, helper);
    try fixture.directory("deferred-unrelated-selection-change/install");
    var result = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "install", .archives = &.{changing}, .triggers = true, .defer_triggers = true,
    }, "deferred-unrelated-selection-change/install");
    defer result.deinit();
    if (!std.mem.eql(u8, result.value.outcome, "recovery_required"))
        return error.DeferredSelectionMutationWasNotBlocked;
    const operation_bytes = try support.read(
        fixture, "deferred-unrelated-selection-change/native/var/lib/debz/root-operation-v1.json", 1024 * 1024,
    );
    defer fixture.allocator.free(operation_bytes);
    const Operation = struct { state: []const u8, mutation_started: bool, program_sha256: []const u8 };
    const operation = try std.json.parseFromSlice(Operation, fixture.allocator, operation_bytes, .{ .ignore_unknown_fields = true });
    defer operation.deinit();
    if ((!std.mem.eql(u8, operation.value.state, "mutating") and
        !std.mem.eql(u8, operation.value.state, "recovery_required")) or
        !operation.value.mutation_started or result.value.program_sha256 == null or
        !std.mem.eql(u8, operation.value.program_sha256, result.value.program_sha256.?))
        return error.DeferredSelectionLostRecoveryEvidence;
    const status = try support.read(fixture, "deferred-unrelated-selection-change/native/var/lib/dpkg/status", 64 * 1024);
    defer fixture.allocator.free(status);
    if (std.mem.indexOf(u8, status, "Status: hold ok installed") == null or
        std.mem.indexOf(u8, status, "Package: " ++ unrelated) == null)
        return error.DeferredSelectionOverwroteUnrelatedPackage;
    const excludes: []const []const u8 = &.{ foundation.guard, "usr/bin/dpkg-trigger" };
    const before = try foundation.captureRealRoot(fixture.allocator, fixture.io, case.native_root, .{}, excludes);
    defer fixture.allocator.free(before);
    try fixture.directory("deferred-unrelated-selection-change/blocked");
    var retry = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "process_triggers", .triggers = true,
    }, "deferred-unrelated-selection-change/blocked");
    defer retry.deinit();
    if (!std.mem.eql(u8, retry.value.outcome, "recovery_required"))
        return error.DeferredSelectionAllowedMutation;
    const after = try foundation.captureRealRoot(fixture.allocator, fixture.io, case.native_root, .{}, excludes);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.DeferredSelectionChangedRoot;
}

fn refuseUnauthenticatedHelper(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    var case = try support.Scenario.init(fixture, "unauthenticated-trigger-helper", driver, dpkg, arch, true);
    defer case.deinit();
    try copyNativeHelper(fixture, &case, helper);
    const excludes: []const []const u8 = &.{ foundation.guard, "usr/bin/dpkg-trigger" };
    const before = try foundation.captureRealRoot(fixture.allocator, fixture.io, case.native_root, .{}, excludes);
    defer fixture.allocator.free(before);
    try fixture.environment.put("DPKG_MAINTSCRIPT_PACKAGE", receiver);
    try fixture.environment.put("DPKG_MAINTSCRIPT_ARCH", arch);
    try fixture.environment.put("DPKG_ADMINDIR", "/var/lib/dpkg");
    for ([_]struct { name: []const u8, args: []const []const u8 }{
        .{ .name = "missing-authority", .args = &.{ "--no-await", trigger } },
        .{ .name = "wrong-caller", .args = &.{ "--by-package=" ++ source, "--no-await", trigger } },
    }) |attempt| {
        const log = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}.log", .{ case.name, attempt.name });
        defer fixture.allocator.free(log);
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(fixture.allocator);
        try argv.appendSlice(fixture.allocator, &.{ "/usr/sbin/chroot", case.native_root, "/usr/bin/dpkg-trigger" });
        try argv.appendSlice(fixture.allocator, attempt.args);
        if (try support.runExit(fixture, argv.items, log) != 1) return error.UnauthenticatedHelperAccepted;
        const after = try foundation.captureRealRoot(fixture.allocator, fixture.io, case.native_root, .{}, excludes);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.UnauthenticatedHelperChangedRoot;
        try support.assertNoActiveEvidence(fixture, case.native_root);
    }
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

fn divertedTriggerRoutes(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const name = "diversion-lifecycle";
    const route = "usr/share/diversion-lifecycle/mode";
    const old_record = "/" ++ route ++ "\n/" ++ route ++ ".distrib\n:\n";
    const new_record = "/" ++ route ++ "\n/" ++ route ++ ".changed\n:\n";
    const preinst =
        \\if [ -f /diversion-preinst-replace ]; then
        \\    /diversion-mv /diversion-preinst-replace /var/lib/dpkg/diversions || exit 26
        \\fi
        \\if [ -f /diversion-preinst-inplace ]; then
        \\    while IFS= read -r line; do
        \\        printf '%s\n' "$line"
        \\    done < /diversion-preinst-inplace > /var/lib/dpkg/diversions
        \\fi
        \\
    ;
    const first = try support.makePackage(fixture, arch, "1", name, "route-packages", .{
        .extra_files = &.{.{ .path = route, .content = "mode version 1\n", .mode = 0o600 }},
        .conffile_content = "configuration 1\n",
        .preinst_append = preinst,
    });
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, arch, "2", name, "route-packages", .{
        .extra_files = &.{.{ .path = route, .content = "mode version 2\n", .mode = 0o640 }},
        .conffile_content = "configuration 2\n",
        .preinst_append = preinst,
    });
    defer fixture.allocator.free(second);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    for ([_]struct { label: []const u8, interest: []const u8 }{
        .{ .label = "source", .interest = route },
        .{ .label = "destination", .interest = route ++ ".distrib" },
        .{ .label = "updated", .interest = route ++ ".changed" },
        .{ .label = "cached-old", .interest = route ++ ".distrib" },
        .{ .label = "cached-new", .interest = route ++ ".changed" },
    }) |entry| {
        const case_name = try std.fmt.allocPrint(fixture.allocator, "diversion-trigger-{s}", .{entry.label});
        defer fixture.allocator.free(case_name);
        const declaration = try std.fmt.allocPrint(fixture.allocator, "interest-noawait /{s}\n", .{entry.interest});
        defer fixture.allocator.free(declaration);
        const watcher = try support.makePackage(fixture, arch, "1", "diversion-watcher", case_name, .{
            .declarations = declaration,
        });
        defer fixture.allocator.free(watcher);
        var case = try support.Scenario.init(fixture, case_name, driver, dpkg, arch, true);
        defer case.deinit();
        for ([_][]const u8{ "reference", "native" }) |side| {
            const record = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/var/lib/dpkg/diversions", .{case_name, side});
            defer fixture.allocator.free(record);
            try support.fixtureFile(fixture, record, old_record, 0o644);
        }
        try case.seed(watcher);
        if (std.mem.eql(u8, entry.label, "updated") or std.mem.startsWith(u8, entry.label, "cached-")) {
            const replace = std.mem.eql(u8, entry.label, "updated");
            for ([_][]const u8{ "reference", "native" }) |side| {
                const root = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}", .{case_name, side});
                defer fixture.allocator.free(root);
                if (replace) try support.copyProgram(fixture, root, "/bin/mv", "/diversion-mv");
                const diversion_update = try std.fmt.allocPrint(fixture.allocator, "{s}/diversion-preinst-{s}", .{
                    root, if (replace) "replace" else "inplace",
                });
                defer fixture.allocator.free(diversion_update);
                try support.fixtureFile(fixture, diversion_update, new_record, 0o644);
            }
        }
        try copyNativeHelper(fixture, &case, helper);
        try case.phase(.{ .operation = "install", .archives = &.{first}, .triggers = true }, false);
        if (std.mem.startsWith(u8, entry.label, "cached-")) {
            try assertWatchedRoute(fixture, case_name, arch, std.mem.eql(u8, entry.label, "cached-old"));
        }
        try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .triggers = true }, false);
        try case.phase(.{ .operation = "remove", .packages = &selected, .triggers = true }, false);
        try case.phase(.{ .operation = "purge", .packages = &selected, .triggers = true }, false);
        try assertWatchedRoute(fixture, case_name, arch, !std.mem.eql(u8, entry.label, "source"));
    }

    const alias_route = "usr/bin/diversion-mode";
    const alias_destination = "bin/diversion-mode.distrib";
    const alias_archive = try support.makePackage(fixture, arch, "1", name, "alias-packages", .{
        .extra_files = &.{.{ .path = alias_route, .content = "aliased diversion\n" }},
    });
    defer fixture.allocator.free(alias_archive);
    for ([_][]const u8{ "bin", "usr/bin" }) |spelling| {
        const case_name = try std.fmt.allocPrint(fixture.allocator, "diversion-trigger-alias-{s}", .{
            if (std.mem.eql(u8, spelling, "bin")) "bin" else "usr-bin",
        });
        defer fixture.allocator.free(case_name);
        const declaration = try std.fmt.allocPrint(fixture.allocator, "interest-noawait /{s}/diversion-mode.distrib\n", .{spelling});
        defer fixture.allocator.free(declaration);
        const watcher = try support.makePackage(fixture, arch, "1", "diversion-watcher", case_name, .{
            .declarations = declaration,
        });
        defer fixture.allocator.free(watcher);
        var case = try support.Scenario.init(fixture, case_name, driver, dpkg, arch, true);
        defer case.deinit();
        for ([_][]const u8{ "reference", "native" }, [_][]const u8{ case.reference_root, case.native_root }) |side, absolute| {
            const root = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}", .{case_name, side});
            defer fixture.allocator.free(root);
            const original_shell = try std.fmt.allocPrint(fixture.allocator, "{s}/bin/sh", .{root});
            defer fixture.allocator.free(original_shell);
            const moved_shell = try std.fmt.allocPrint(fixture.allocator, "{s}/usr/bin/sh", .{root});
            defer fixture.allocator.free(moved_shell);
            try fixture.dir.rename(original_shell, fixture.dir, moved_shell, fixture.io);
            const bin = try std.fmt.allocPrint(fixture.allocator, "{s}/bin", .{root});
            defer fixture.allocator.free(bin);
            try fixture.dir.deleteDir(fixture.io, bin);
            try fixture.dir.symLink(fixture.io, "usr/bin", bin, .{});
            var guarded = try foundation.guardedRoot(fixture.io, absolute);
            defer guarded.close(fixture.io);
            try (root_fs.Root.init(fixture.io, guarded)).applyMetadata(try root_fs.Path.init("bin"), .{
                .modified_nanoseconds = foundation.epoch * std.time.ns_per_s,
            });
            const record = try std.fmt.allocPrint(fixture.allocator, "{s}/var/lib/dpkg/diversions", .{root});
            defer fixture.allocator.free(record);
            try support.fixtureFile(fixture, record, "/" ++ alias_route ++ "\n/" ++ alias_destination ++ "\n:\n", 0o644);
        }
        try case.seed(watcher);
        try copyNativeHelper(fixture, &case, helper);
        try case.phase(.{ .operation = "install", .archives = &.{alias_archive}, .triggers = true }, false);
        try case.phase(.{ .operation = "remove", .packages = &selected, .triggers = true }, false);
        try case.phase(.{ .operation = "purge", .packages = &selected, .triggers = true }, false);
    }
}

fn assertWatchedRoute(fixture: *foundation.Fixture, case_name: []const u8, arch: []const u8, expected: bool) !void {
    const marker = try std.fmt.allocPrint(fixture.allocator, "diversion-watcher@1:postinst\tdiversion-watcher\tpostinst\t{s}\t2\t9:triggered", .{arch});
    defer fixture.allocator.free(marker);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const path = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}/{s}", .{ case_name, side, support.trace });
        defer fixture.allocator.free(path);
        const trace_bytes = try support.read(fixture, path, 1024 * 1024);
        defer fixture.allocator.free(trace_bytes);
        if ((std.mem.indexOf(u8, trace_bytes, marker) != null) != expected)
            return error.UnexpectedDivertedTrigger;
    }
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
        runTriggerLifecycle(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
            try support.assertHostUnchanged(allocator, init.io, reference.before);
            return err;
        };
        runTriggerChains(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
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
        interruptedTriggerHandler(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
            try support.assertHostUnchanged(allocator, init.io, reference.before);
            return err;
        };
        deferredSelectionChange(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
            try support.assertHostUnchanged(allocator, init.io, reference.before);
            return err;
        };
    }
    runDivertedTrigger(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    divertedTriggerRoutes(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
        try support.assertHostUnchanged(allocator, init.io, reference.before);
        return err;
    };
    refuseUnauthenticatedHelper(&fixture, driver, selected, reference.executable, reference.architecture) catch |err| {
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

test "trigger package declarations, scriptless handler and helper scripts retain exact bytes" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const declarations = "interest-noawait debz-test-trigger\nactivate-await debz-other\n";
    const first = try support.makePackage(&fixture, "amd64", "1", receiver, "unit-declarations", .{
        .declarations = declarations,
        .postinst = false,
    });
    defer std.testing.allocator.free(first);
    const member = "unit-declarations/" ++ receiver ++ "_1_data.source/DEBIAN/";
    const actual = try support.read(&fixture, member ++ "triggers", 1024);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings(declarations, actual);
    try support.absent(&fixture, member ++ "postinst");

    const second = try support.makePackage(&fixture, "amd64", "1", source, "unit-scripts", .{
        .activations = &.{ "first-trigger", "second-trigger" },
        .activation_when = "triggered",
        .activation_await = true,
    });
    defer std.testing.allocator.free(second);
    const postinst = try support.read(&fixture, "unit-scripts/" ++ source ++ "_1_data.source/DEBIAN/postinst", 64 * 1024);
    defer std.testing.allocator.free(postinst);
    try std.testing.expect(std.mem.indexOf(u8, postinst, "if [ \"$1\" = \"triggered\" ]") != null);
    for ([_][]const u8{ "first-trigger", "second-trigger" }) |name| {
        const command = try std.fmt.allocPrint(std.testing.allocator, "/usr/bin/dpkg-trigger --await {s} || exit $?", .{name});
        defer std.testing.allocator.free(command);
        try std.testing.expect(std.mem.indexOf(u8, postinst, command) != null);
    }
    const third = try support.makePackage(&fixture, "amd64", "1", source, "unit-removal", .{
        .activation = trigger, .activation_kind = "postrm", .activation_when = "remove",
    });
    defer std.testing.allocator.free(third);
    const remove_script = try support.read(&fixture, "unit-removal/" ++ source ++ "_1_data.source/DEBIAN/postrm", 64 * 1024);
    defer std.testing.allocator.free(remove_script);
    const install_script = try support.read(&fixture, "unit-removal/" ++ source ++ "_1_data.source/DEBIAN/postinst", 64 * 1024);
    defer std.testing.allocator.free(install_script);
    try std.testing.expect(std.mem.indexOf(u8, remove_script, "if [ \"$1\" = \"remove\" ]") != null);
    try std.testing.expect(std.mem.indexOf(u8, remove_script, "/usr/bin/dpkg-trigger --no-await " ++ trigger ++ " || exit $?") != null);
    try std.testing.expect(std.mem.indexOf(u8, install_script, "/usr/bin/dpkg-trigger") == null);
}

test "reference trigger-only and deferred phases emit distinct guarded dpkg flags" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    try fixture.write("fake-dpkg", "#!/bin/sh\nprintf '%s\\n' \"$@\"\n", 0o755);
    const binary = try fixture.absolute("fake-dpkg");
    defer std.testing.allocator.free(binary);
    const root = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(root);
    try fixture.directory("process");
    try std.testing.expectEqual(@as(u8, 0), try support.reference(
        &fixture, binary, root, .{ .operation = "process_triggers", .triggers = true }, "process",
    ));
    const processed = try support.read(&fixture, "process/reference.log", 64 * 1024);
    defer std.testing.allocator.free(processed);
    for ([_][]const u8{ "--triggers-only\n", "--pending\n" }) |flag|
        try std.testing.expect(std.mem.indexOf(u8, processed, flag) != null);
    try std.testing.expect(std.mem.indexOf(u8, processed, "--no-triggers") == null);
    try std.testing.expect(std.mem.indexOf(u8, processed, "--install") == null);
    try fixture.directory("deferred");
    try std.testing.expectEqual(@as(u8, 0), try support.reference(
        &fixture, binary, root, .{
            .operation = "install", .archives = &.{"package.deb"}, .triggers = true, .defer_triggers = true,
        }, "deferred",
    ));
    const deferred = try support.read(&fixture, "deferred/reference.log", 64 * 1024);
    defer std.testing.allocator.free(deferred);
    try std.testing.expect(std.mem.indexOf(u8, deferred, "--no-triggers\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, deferred, "--install\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, deferred, "--pending") == null);
    try std.testing.expectError(error.InvalidReferenceOperation, support.reference(
        &fixture, binary, root, .{ .operation = "process_triggers" }, "unused",
    ));
    try std.testing.expectError(error.MissingArchive, support.reference(
        &fixture, binary, root, .{ .operation = "install", .triggers = true }, "unused",
    ));
    try std.testing.expectError(error.MissingPackage, support.reference(
        &fixture, binary, root, .{ .operation = "purge", .triggers = true }, "unused",
    ));
    try support.absent(&fixture, "unused/reference.log");
}

test "native trigger-only request does not invent an archive installation" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(root);
    try fixture.directory("process");
    const report_path = try fixture.absolute("process/native.report.json");
    defer std.testing.allocator.free(report_path);
    const fake = try std.fmt.allocPrint(std.testing.allocator,
        "#!/bin/sh\nprintf '%s' '{{\"outcome\":\"applied\"}}' > '{s}'\n",
        .{report_path},
    );
    defer std.testing.allocator.free(fake);
    try fixture.write("fake-driver", fake, 0o755);
    const executable = try fixture.absolute("fake-driver");
    defer std.testing.allocator.free(executable);
    var outcome = try support.native(
        &fixture, executable, root, "amd64",
        .{ .operation = "process_triggers", .triggers = true }, "process",
    );
    defer outcome.deinit();
    try std.testing.expectEqualStrings("applied", outcome.value.outcome);
    const document = try support.read(&fixture, "process/native.request.json", 64 * 1024);
    defer std.testing.allocator.free(document);
    const Request = struct {
        operation: []const u8,
        archives: []const []const u8,
        packages: []const foundation.PackageIdentity,
        triggers: bool,
        defer_triggers: bool,
    };
    const request = try std.json.parseFromSlice(Request, std.testing.allocator, document, .{ .ignore_unknown_fields = true });
    defer request.deinit();
    try std.testing.expectEqualStrings("process_triggers", request.value.operation);
    try std.testing.expectEqual(@as(usize, 0), request.value.archives.len);
    try std.testing.expectEqual(@as(usize, 0), request.value.packages.len);
    try std.testing.expect(request.value.triggers);
    try std.testing.expect(!request.value.defer_triggers);
}

test "trigger registry ordering, noawait markers, trace, and active authority remain observable" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("native", "amd64");
    defer std.testing.allocator.free(right);
    try fixture.directory("comparison");
    for ([_]struct { path: []const u8, expected: []const u8, changed: []const u8 }{
        .{
            .path = "var/lib/dpkg/triggers/" ++ trigger,
            .expected = receiver ++ "\n",
            .changed = receiver ++ "/noawait\n",
        },
        .{
            .path = "var/lib/dpkg/triggers/Unincorp",
            .expected = trigger ++ " " ++ source ++ " -\n",
            .changed = trigger ++ " " ++ source ++ "\n",
        },
        .{
            .path = "var/lib/dpkg/status",
            .expected = "Package: " ++ receiver ++ "\nStatus: install ok triggers-pending\nVersion: 1\nArchitecture: amd64\nTriggers-Pending: a b\n\n",
            .changed = "Package: " ++ receiver ++ "\nStatus: install ok triggers-pending\nVersion: 1\nArchitecture: amd64\nTriggers-Pending: b a\n\n",
        },
        .{
            .path = support.trace,
            .expected = receiver ++ "@1:postinst\t[triggered]\t[a b]\n",
            .changed = receiver ++ "@1:postinst\t[triggered]\t[b a]\n",
        },
        .{
            .path = support.trace,
            .expected = receiver ++ "@1:postinst\t[triggered]\t[a b]\n",
            .changed = receiver ++ "@1:postinst\t[triggered]\t[a]\t[b]\n",
        },
    }) |row| {
        const expected_path = try std.fmt.allocPrint(std.testing.allocator, "reference/{s}", .{row.path});
        defer std.testing.allocator.free(expected_path);
        const candidate_path = try std.fmt.allocPrint(std.testing.allocator, "native/{s}", .{row.path});
        defer std.testing.allocator.free(candidate_path);
        try fixture.write(expected_path, row.expected, 0o644);
        try fixture.write(candidate_path, row.expected, 0o644);
        try support.compare(&fixture, left, right, "comparison", true);
        try fixture.write(candidate_path, row.changed, 0o644);
        try std.testing.expectError(error.NativeDpkgTriggerMismatch, support.compare(
            &fixture, left, right, "comparison", true,
        ));
        try fixture.write(candidate_path, row.expected, 0o644);
    }
    try fixture.write("native/var/lib/debz/native-trigger-authority-v1.json", "{}", 0o644);
    try std.testing.expectError(error.UnexpectedArtifact, support.assertNoActiveEvidence(&fixture, right));
}

test "malformed trigger queue snapshots preserve invalid bytes without normalization" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("native", "amd64");
    defer std.testing.allocator.free(right);
    try fixture.directory("comparison");
    try support.compare(&fixture, left, right, "comparison", true);
    try fixture.write("native/var/lib/dpkg/triggers/Unincorp", "invalid\x00trigger -\n", 0o644);
    try std.testing.expectError(error.NativeDpkgTriggerMismatch, support.compare(
        &fixture, left, right, "comparison", true,
    ));
    const observed = try foundation.captureRealRoot(
        std.testing.allocator, std.testing.io, right, .{}, &.{ foundation.guard, "usr/bin/dpkg-trigger" },
    );
    defer std.testing.allocator.free(observed);
    const again = try foundation.captureRealRoot(
        std.testing.allocator, std.testing.io, right, .{}, &.{ foundation.guard, "usr/bin/dpkg-trigger" },
    );
    defer std.testing.allocator.free(again);
    try std.testing.expectEqualSlices(u8, observed, again);
}
