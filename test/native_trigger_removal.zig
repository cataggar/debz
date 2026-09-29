const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const recovery = @import("native_recovery_scriptless.zig");

const receiver = "removal-trigger-receiver";
const source = "removal-trigger-source";
const trigger = "removal-trigger";

pub fn expectNativeOutcome(case: *support.Scenario, index: usize, operation: []const u8, outcome: []const u8, detail: []const u8) !void {
    if (case.fixture.oracle_only) return;
    const report_path = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{d}-{s}/native.report.json", .{
        case.name, index, operation,
    });
    defer case.fixture.allocator.free(report_path);
    const bytes = try support.read(case.fixture, report_path, 64 * 1024);
    defer case.fixture.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(support.Report, case.fixture.allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.outcome, outcome) or
        !std.mem.eql(u8, parsed.value.detail, detail))
        return error.WrongRemovalTriggerOutcome;
}

fn readRoot(case: *support.Scenario, side: []const u8, path: []const u8) ![]u8 {
    const relative = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, path });
    defer case.fixture.allocator.free(relative);
    return support.read(case.fixture, relative, 16 * 1024 * 1024);
}

fn traceCount(case: *support.Scenario, name: []const u8, expected: usize) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const bytes = try readRoot(case, side, support.trace);
        defer case.fixture.allocator.free(bytes);
        if (std.mem.count(u8, bytes, name) != expected) {
            std.debug.print("{s}/{s}: expected {d} invocations of {s}, trace:\n{s}\n", .{
                case.name, side, expected, name, bytes,
            });
            return error.MissingOrRepeatedRemovalTrigger;
        }
    }
}

fn assertSideStatus(case: *support.Scenario, side: []const u8, name: []const u8, field: []const u8) !void {
    const prefix = try std.fmt.allocPrint(case.fixture.allocator, "Package: {s}\n", .{name});
    defer case.fixture.allocator.free(prefix);
    const bytes = try readRoot(case, side, "var/lib/dpkg/status");
    defer case.fixture.allocator.free(bytes);
    const start = std.mem.indexOf(u8, bytes, prefix) orelse return error.MissingTriggerPackage;
    const end = std.mem.indexOfPos(u8, bytes, start, "\n\n") orelse bytes.len;
    if (std.mem.indexOf(u8, bytes[start..end], field) == null) return error.WrongRemovalTriggerStatus;
}

fn assertStatus(case: *support.Scenario, name: []const u8, field: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        try assertSideStatus(case, side, name, field);
    }
}

fn marker(case: *support.Scenario, fail: bool) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const path = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{
            case.name, side, support.failure,
        });
        defer case.fixture.allocator.free(path);
        if (fail)
            try support.fixtureFile(case.fixture, path, receiver ++ "@1:postinst:triggered\n", 0o644)
        else
            try case.fixture.dir.deleteFile(case.fixture.io, path);
    }
}

fn awaitedRemoval(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    installHelper: *const fn (*foundation.Fixture, *support.Scenario, []const u8) anyerror!void,
) !void {
    const label = "removal-activate-await-refusal";
    const handler = try support.makePackage(fixture, arch, "1", receiver, label, .{
        .declarations = "interest-await " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    const activating = try support.makePackage(fixture, arch, "1", source, label, .{
        .conffile_content = "retained configuration\n",
        .activation = trigger,
        .activation_kind = "postrm",
        .activation_when = "remove",
        .activation_await = true,
    });
    defer fixture.allocator.free(activating);
    var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, true);
    defer case.deinit();
    try case.seed(handler);
    try case.seed(activating);
    try installHelper(fixture, &case, helper);
    const selected = [_]foundation.PackageIdentity{.{ .name = source, .architecture = arch }};
    const input: support.Phase = .{
        .operation = "remove",
        .packages = &selected,
        .triggers = true,
        .defer_triggers = true,
    };
    const removal_index = case.index;
    try case.phase(input, false);
    if (fixture.oracle_only) return;
    try expectNativeOutcome(&case, removal_index, "remove", "applied", "completed");
    try assertStatus(&case, source, "Status: deinstall ok config-files");
    try assertStatus(&case, receiver, "Status: install ok triggers-pending");
    try assertStatus(&case, receiver, "Triggers-Pending: " ++ trigger);
    try traceCount(&case, source ++ "@1:postrm\t", 1);
    try traceCount(&case, receiver ++ "@1:postinst\t", 0);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const queue = try readRoot(&case, side, "var/lib/dpkg/triggers/Unincorp");
        defer fixture.allocator.free(queue);
        if (queue.len != 0) return error.AwaitedRemovalQueueNotIncorporated;
    }
    try case.phase(.{ .operation = "process_triggers", .triggers = true }, false);
    try traceCount(&case, receiver ++ "@1:postinst\t", 1);
    try assertStatus(&case, source, "Status: deinstall ok config-files");
    try case.phase(.{ .operation = "purge", .packages = &selected, .triggers = true }, false);
}

fn awaitedRemovalInterruptions(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    installHelper: *const fn (*foundation.Fixture, *support.Scenario, []const u8) anyerror!void,
) !void {
    if (fixture.oracle_only) return;
    for ([_]struct { name: []const u8, crash: []const u8, unknown_script: bool }{
        .{ .name = "registration", .crash = "after_removal_postrm_return_before_outcome", .unknown_script = true },
        .{ .name = "queue-incorporation", .crash = "after_deferred_trigger_queue_incorporation", .unknown_script = false },
        .{ .name = "status-publication", .crash = "after_deferred_trigger_status_publication", .unknown_script = false },
        .{ .name = "terminal-acknowledgment", .crash = "after_provenance", .unknown_script = false },
    }) |boundary| {
        const label = try std.fmt.allocPrint(fixture.allocator, "removal-activate-await-crash-{s}", .{boundary.name});
        defer fixture.allocator.free(label);
        const handler = try support.makePackage(fixture, arch, "1", receiver, label, .{
            .declarations = "interest-await " ++ trigger ++ "\n",
        });
        defer fixture.allocator.free(handler);
        const activating = try support.makePackage(fixture, arch, "1", source, label, .{
            .conffile_content = "retained configuration\n",
            .activation = trigger,
            .activation_kind = "postrm",
            .activation_when = "remove",
            .activation_await = true,
        });
        defer fixture.allocator.free(activating);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, true);
        defer case.deinit();
        try case.seed(handler);
        try case.seed(activating);
        try installHelper(fixture, &case, helper);
        const selected = [_]foundation.PackageIdentity{.{ .name = source, .architecture = arch }};
        const reference_log = try support.path(fixture.allocator, label, "reference-remove");
        defer fixture.allocator.free(reference_log);
        try fixture.directory(reference_log);
        if (try support.reference(fixture, dpkg, case.reference_root, .{
            .operation = "remove",
            .packages = &selected,
            .triggers = true,
            .defer_triggers = true,
        }, reference_log) != 0) return error.UnexpectedAwaitedRemovalReference;
        const crash_log = try support.path(fixture.allocator, label, "crash");
        defer fixture.allocator.free(crash_log);
        _ = try recovery.invoke(fixture, driver, case.native_root, arch, crash_log, .{
            .operation = "remove",
            .packages = &selected,
            .defer_triggers = true,
            .crash_at = boundary.crash,
        });
        const owner_path = try recovery.rootPath(fixture, case.native_root, "var/lib/debz/root-operation-v1.json");
        defer fixture.allocator.free(owner_path);
        const owner_bytes = try support.read(fixture, owner_path, 1024 * 1024);
        defer fixture.allocator.free(owner_bytes);
        var owner = try recovery.rootDocument(fixture, case.native_root, "var/lib/debz/root-operation-v1.json");
        defer owner.deinit();
        var intent = try recovery.rootDocument(fixture, case.native_root, "var/lib/debz/native-execution-intent-v1.json");
        defer intent.deinit();
        try recovery.same(try recovery.text(owner.value, "state"), if (boundary.unknown_script) "mutating" else if (std.mem.eql(u8, boundary.crash, "after_provenance")) "completed" else "mutating");
        if (!(try recovery.field(owner.value, "mutation_started")).bool)
            return error.AwaitedRemovalLostMutationEvidence;
        try recovery.same(try recovery.text(owner.value, "attempt_id"), try recovery.text(intent.value, "attempt_id"));
        try recovery.same(try recovery.text(owner.value, "program_sha256"), try recovery.text(intent.value, "program_sha256"));
        try recovery.same(try recovery.text(try recovery.field(owner.value, "exact_lock"), "digest_sha256"), try recovery.text(intent.value, "exact_lock_sha256"));
        if (!std.mem.eql(u8, boundary.crash, "after_provenance")) {
            var authority = try recovery.rootDocument(fixture, case.native_root, "var/lib/debz/native-trigger-authority-v1.json");
            defer authority.deinit();
            try recovery.same(
                try recovery.text(owner.value, "program_sha256"),
                try recovery.text(authority.value, "program_sha256"),
            );
            try recovery.same(
                try recovery.text(owner.value, "attempt_id"),
                try recovery.text(authority.value, "attempt_id"),
            );
        }
        const queued = try readRoot(&case, "native", "var/lib/dpkg/triggers/Unincorp");
        defer fixture.allocator.free(queued);
        if (boundary.unknown_script) {
            if (!std.mem.eql(u8, queued, trigger ++ " " ++ source ++ "\n"))
                return error.AwaitedRemovalRegistrationWasNotPersisted;
        } else if (queued.len != 0) {
            return error.AwaitedRemovalQueueNotIncorporated;
        }
        if (std.mem.eql(u8, boundary.name, "queue-incorporation"))
            try assertSideStatus(&case, "native", receiver, "Status: install ok installed");
        if (std.mem.eql(u8, boundary.name, "status-publication") or
            std.mem.eql(u8, boundary.name, "terminal-acknowledgment"))
            try assertSideStatus(&case, "native", receiver, "Status: install ok triggers-pending");
        const before_block = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(before_block);
        for ([_][]const u8{ "process_triggers", "purge" }) |operation_name| {
            const blocked_log = try std.fmt.allocPrint(fixture.allocator, "{s}/blocked-{s}", .{ label, operation_name });
            defer fixture.allocator.free(blocked_log);
            try fixture.directory(blocked_log);
            var blocked = try support.native(fixture, driver, case.native_root, arch, .{
                .operation = operation_name,
                .triggers = true,
                .packages = if (std.mem.eql(u8, operation_name, "purge")) &selected else &.{},
            }, blocked_log);
            defer blocked.deinit();
            if (!std.mem.eql(u8, blocked.value.outcome, "recovery_required"))
                return error.AwaitedRemovalAllowedReplay;
            const retained = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
            defer fixture.allocator.free(retained);
            const owner_after = try support.read(fixture, owner_path, 1024 * 1024);
            defer fixture.allocator.free(owner_after);
            if (!std.mem.eql(u8, before_block, retained) or
                !std.mem.eql(u8, owner_bytes, owner_after))
                return error.AwaitedRemovalReentryChangedRootOrJournal;
        }
        const resume_log = try support.path(fixture.allocator, label, "recover");
        defer fixture.allocator.free(resume_log);
        var resumed = (try recovery.invoke(fixture, driver, case.native_root, arch, resume_log, .{
            .operation = "recover",
            .defer_triggers = true,
        })) orelse return error.AwaitedRemovalRecoveryMissingReport;
        defer resumed.deinit();
        if (boundary.unknown_script) {
            try recovery.same(resumed.value.outcome, "recovery_required");
            try recovery.same(resumed.value.detail, "script_outcome_unknown");
            var retained = try recovery.rootDocument(fixture, case.native_root, "var/lib/debz/root-operation-v1.json");
            defer retained.deinit();
            try recovery.same(try recovery.text(retained.value, "state"), "recovery_required");
            try recovery.same(try recovery.text(retained.value, "phase"), "script");
            try recovery.same(try recovery.text(retained.value, "program_sha256"), try recovery.text(owner.value, "program_sha256"));
            var proof = try recovery.rootDocument(fixture, case.native_root, "var/lib/debz/native-transaction-provenance-v1.json");
            defer proof.deinit();
            try recovery.same(try recovery.text(proof.value, "outcome"), "recovery_required");
            try recovery.same(try recovery.text(proof.value, "attempt_id"), try recovery.text(owner.value, "attempt_id"));
            try recovery.same(try recovery.text(proof.value, "exact_lock_sha256"), try recovery.text(intent.value, "exact_lock_sha256"));
            const recovery_owner = try support.read(fixture, owner_path, 1024 * 1024);
            defer fixture.allocator.free(recovery_owner);
            const recovery_snapshot = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
            defer fixture.allocator.free(recovery_snapshot);
            const blocked_log = try support.path(fixture.allocator, label, "blocked-after-recovery");
            defer fixture.allocator.free(blocked_log);
            try fixture.directory(blocked_log);
            var blocked = try support.native(fixture, driver, case.native_root, arch, .{
                .operation = "process_triggers",
                .triggers = true,
            }, blocked_log);
            defer blocked.deinit();
            try recovery.same(blocked.value.outcome, "recovery_required");
            const retained_owner = try support.read(fixture, owner_path, 1024 * 1024);
            defer fixture.allocator.free(retained_owner);
            const retained_snapshot = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
            defer fixture.allocator.free(retained_snapshot);
            if (!std.mem.eql(u8, recovery_owner, retained_owner) or
                !std.mem.eql(u8, recovery_snapshot, retained_snapshot))
                return error.AwaitedRemovalRecoveryOwnerChangedOnReplay;
            try traceCount(&case, source ++ "@1:postrm\t", 1);
            continue;
        }
        try recovery.same(resumed.value.outcome, "applied");
        var proof = try recovery.rootDocument(fixture, case.native_root, "var/lib/debz/native-transaction-provenance-v1.json");
        defer proof.deinit();
        try recovery.same(try recovery.text(proof.value, "outcome"), "succeeded");
        try recovery.same(try recovery.text(proof.value, "attempt_id"), try recovery.text(owner.value, "attempt_id"));
        try recovery.same(try recovery.text(proof.value, "program_sha256"), try recovery.text(owner.value, "program_sha256"));
        try recovery.same(try recovery.text(proof.value, "exact_lock_sha256"), try recovery.text(intent.value, "exact_lock_sha256"));
        try support.assertNoActiveEvidence(fixture, case.native_root);
        try recovery.rootAbsent(fixture, case.native_root, "var/lib/debz/native-execution-intent-v1.json");
        try recovery.rootAbsent(fixture, case.native_root, "var/lib/debz/root-mutation-v1.json");
        const comparison = try support.path(fixture.allocator, label, "comparison");
        defer fixture.allocator.free(comparison);
        try fixture.directory(comparison);
        try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
        try assertStatus(&case, source, "Status: deinstall ok config-files");
        try assertStatus(&case, receiver, "Status: install ok triggers-pending");
        try traceCount(&case, source ++ "@1:postrm\t", 1);
        try traceCount(&case, receiver ++ "@1:postinst\t", 0);
        const settled = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(settled);
        const proof_path = try recovery.rootPath(fixture, case.native_root, "var/lib/debz/native-transaction-provenance-v1.json");
        defer fixture.allocator.free(proof_path);
        const proof_bytes = try support.read(fixture, proof_path, 16 * 1024 * 1024);
        defer fixture.allocator.free(proof_bytes);
        const repeat_log = try support.path(fixture.allocator, label, "repeat-recovery");
        defer fixture.allocator.free(repeat_log);
        var repeated = (try recovery.invoke(fixture, driver, case.native_root, arch, repeat_log, .{
            .operation = "recover",
            .defer_triggers = true,
        })) orelse return error.AwaitedRemovalRecoveryMissingReport;
        defer repeated.deinit();
        try recovery.same(repeated.value.outcome, "applied");
        const retained = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(retained);
        const retained_proof = try support.read(fixture, proof_path, 16 * 1024 * 1024);
        defer fixture.allocator.free(retained_proof);
        if (!std.mem.eql(u8, settled, retained) or !std.mem.eql(u8, proof_bytes, retained_proof))
            return error.AwaitedRemovalRecoveryRewroteReceipt;
    }
}

pub fn run(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    installHelper: *const fn (*foundation.Fixture, *support.Scenario, []const u8) anyerror!void,
) !void {
    for ([_][]const u8{ "interest-await", "interest-noawait" }) |interest| {
        const label = try std.fmt.allocPrint(fixture.allocator, "removal-{s}-deferred-callback-failure", .{interest});
        defer fixture.allocator.free(label);
        const activator = try support.makePackage(fixture, arch, "1", source, label, .{
            .conffile_content = "retained configuration\n",
            .activation = trigger,
            .activation_kind = "postrm",
            .activation_when = "remove",
            .activation_await = false,
        });
        defer fixture.allocator.free(activator);
        const declaration = try std.fmt.allocPrint(fixture.allocator, "{s} {s}\n", .{ interest, trigger });
        defer fixture.allocator.free(declaration);
        const handler = try support.makePackage(fixture, arch, "1", receiver, label, .{
            .declarations = declaration,
        });
        defer fixture.allocator.free(handler);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, true);
        defer case.deinit();
        try case.seed(handler);
        try case.seed(activator);
        try installHelper(fixture, &case, helper);
        const selected = [_]foundation.PackageIdentity{.{ .name = source, .architecture = arch }};
        try case.phase(.{
            .operation = "remove",
            .packages = &selected,
            .triggers = true,
            .defer_triggers = true,
        }, false);
        try assertStatus(&case, source, "Status: deinstall ok config-files");
        try traceCount(&case, receiver ++ "@1:postinst\t", 0);
        try traceCount(&case, source ++ "@1:postrm\t", 1);
        const removal_call = try std.fmt.allocPrint(fixture.allocator, "{s}@1:postrm\t{s}\tpostrm\t{s}\t1\t6:remove\tpayload=<absent>\n", .{
            source, source, arch,
        });
        defer fixture.allocator.free(removal_call);
        for ([_][]const u8{ "reference", "native" }) |side| {
            const bytes = try readRoot(&case, side, support.trace);
            defer fixture.allocator.free(bytes);
            if (std.mem.indexOf(u8, bytes, removal_call) == null) return error.MissingRemovalActivationCall;
        }
        try marker(&case, true);
        const failure_index = case.index;
        try case.phase(.{ .operation = "process_triggers", .triggers = true }, true);
        try expectNativeOutcome(&case, failure_index, "process_triggers", "trigger_failed", "triggered_postinst");
        try traceCount(&case, receiver ++ "@1:postinst\t", 1);
        try assertStatus(&case, receiver, "Status: install ok half-configured");
        const triggered = try std.fmt.allocPrint(fixture.allocator, "{s}@1:postinst\t{s}\tpostinst\t{s}\t2\t9:triggered\t{d}:{s}\tpayload=data version 1\n", .{
            receiver, receiver, arch, trigger.len, trigger,
        });
        defer fixture.allocator.free(triggered);
        for ([_][]const u8{ "reference", "native" }) |side| {
            const bytes = try readRoot(&case, side, support.trace);
            defer fixture.allocator.free(bytes);
            if (std.mem.indexOf(u8, bytes, triggered) == null) return error.WrongRemovalTriggerInvocation;
        }
        try marker(&case, false);
        const selected_receiver = [_]foundation.PackageIdentity{.{ .name = receiver, .architecture = arch }};
        try case.phase(.{
            .operation = "configure",
            .archives = &.{handler},
            .packages = &selected_receiver,
            .triggers = true,
        }, false);
        try traceCount(&case, receiver ++ "@1:postinst\t", 2);
        try assertStatus(&case, receiver, "Status: install ok installed");
        try case.phase(.{ .operation = "purge", .packages = &selected, .triggers = true }, false);
    }
    try awaitedRemoval(fixture, driver, helper, dpkg, arch, installHelper);
    try awaitedRemovalInterruptions(fixture, driver, helper, dpkg, arch, installHelper);
}
