const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

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

fn awaitedRemovalBlock(
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
    if (fixture.oracle_only) {
        try case.phase(input, false);
        return;
    }
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const destination = try support.path(fixture.allocator, label, "remove-await");
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    if (try support.reference(fixture, dpkg, case.reference_root, input, destination) != 0)
        return error.UnexpectedAwaitedRemovalReference;
    try assertSideStatus(&case, "reference", source, "Status: deinstall ok config-files");
    try assertSideStatus(&case, "reference", receiver, "Triggers-Pending: " ++ trigger);
    const reference_trace = try readRoot(&case, "reference", support.trace);
    defer fixture.allocator.free(reference_trace);
    if (std.mem.count(u8, reference_trace, source ++ "@1:postrm\t") != 1)
        return error.ReferenceRemovalDidNotActivate;
    var result = try support.native(fixture, driver, case.native_root, arch, input, destination);
    defer result.deinit();
    if (!std.mem.eql(u8, result.value.outcome, "refused") or
        !std.mem.eql(u8, result.value.detail, "invalid_transition"))
        return error.UnexpectedAwaitedRemovalOutcome;
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (std.mem.eql(u8, before, after)) return error.AwaitedRemovalDidNotReachMutation;
    try assertStatus(&case, source, "Status: deinstall ok config-files");
    try assertSideStatus(&case, "native", receiver, "Status: install ok installed");
    try traceCount(&case, source ++ "@1:postrm\t", 1);
    try traceCount(&case, receiver ++ "@1:postinst\t", 0);
    const operation_path = try std.fmt.allocPrint(fixture.allocator, "{s}/native/var/lib/debz/root-operation-v1.json", .{label});
    defer fixture.allocator.free(operation_path);
    const authority_path = try std.fmt.allocPrint(fixture.allocator, "{s}/native/var/lib/debz/native-trigger-authority-v1.json", .{label});
    defer fixture.allocator.free(authority_path);
    const operation_bytes = try support.read(fixture, operation_path, 1024 * 1024);
    defer fixture.allocator.free(operation_bytes);
    const authority_bytes = try support.read(fixture, authority_path, 1024 * 1024);
    defer fixture.allocator.free(authority_bytes);
    const Operation = struct {
        state: []const u8,
        phase: []const u8,
        mutation_started: bool,
        program_sha256: []const u8,
    };
    const Authority = struct { program_sha256: []const u8 };
    const operation = try std.json.parseFromSlice(Operation, fixture.allocator, operation_bytes, .{ .ignore_unknown_fields = true });
    defer operation.deinit();
    const authority = try std.json.parseFromSlice(Authority, fixture.allocator, authority_bytes, .{ .ignore_unknown_fields = true });
    defer authority.deinit();
    if (!std.mem.eql(u8, operation.value.state, "mutating") or
        !std.mem.eql(u8, operation.value.phase, "mutation") or
        !operation.value.mutation_started or
        !std.mem.eql(u8, operation.value.program_sha256, authority.value.program_sha256))
        return error.AwaitedRemovalLostRecoveryOwnership;
    const reference = try foundation.capture(fixture.allocator, fixture.io, case.reference_root);
    defer fixture.allocator.free(reference);
    if (std.mem.eql(u8, reference, after)) return error.AwaitedRemovalAccidentallyMatched;
    for ([_][]const u8{ "process_triggers", "purge" }) |operation_name| {
        const next = try std.fmt.allocPrint(fixture.allocator, "{s}/blocked-{s}", .{ label, operation_name });
        defer fixture.allocator.free(next);
        try fixture.directory(next);
        var blocked = try support.native(fixture, driver, case.native_root, arch, .{
            .operation = operation_name,
            .triggers = true,
            .packages = if (std.mem.eql(u8, operation_name, "purge")) &selected else &.{},
        }, next);
        defer blocked.deinit();
        if (!std.mem.eql(u8, blocked.value.outcome, "recovery_required"))
            return error.AwaitedRemovalAllowedReplay;
        const retained = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(retained);
        const operation_after = try support.read(fixture, operation_path, 1024 * 1024);
        defer fixture.allocator.free(operation_after);
        const authority_after = try support.read(fixture, authority_path, 1024 * 1024);
        defer fixture.allocator.free(authority_after);
        if (!std.mem.eql(u8, after, retained) or
            !std.mem.eql(u8, operation_bytes, operation_after) or
            !std.mem.eql(u8, authority_bytes, authority_after))
            return error.AwaitedRemovalReentryChangedRootOrJournal;
    }
    std.debug.print("{s}/remove: dpkg exit 0; native invalid_transition after mutation with retained journal (not parity)\n", .{label});
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
    try awaitedRemovalBlock(fixture, driver, helper, dpkg, arch, installHelper);
}
