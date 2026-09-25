const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");
const root_fs = @import("debz").root_fs;

const operation_path = "var/lib/debz/root-operation-v1.json";
const intent_path = "var/lib/debz/native-execution-intent-v1.json";
const completion_path = "var/lib/debz/root-operation-completion-v1.json";
const provenance_path = "var/lib/debz/native-transaction-provenance-v1.json";
const sentinel_driver = "/not-a-native-lifecycle-driver";

const Input = struct {
    operation: []const u8,
    archive: ?[]const u8 = null,
    crash_at: ?[]const u8 = null,
    rollback_crash: ?[]const u8 = null,
    core_completion_crash: ?[]const u8 = null,
    caller_owned: bool = false,
    isolated_helper: bool = false,
    core_product: bool = false,
    triggers: bool = false,
    deadline_after_ms: ?i64 = null,
    acknowledge: bool = false,
};

const Report = struct {
    outcome: []const u8,
    detail: []const u8 = "",
    attempt_id: ?[]const u8 = null,
};

fn guarded(fixture: *foundation.Fixture, root: []const u8) !void {
    if (root.len <= fixture.path.len or !std.mem.startsWith(u8, root, fixture.path) or
        root[fixture.path.len] != '/') return error.NotDisposableRoot;
    var directory = foundation.guardedRoot(fixture.io, root) catch return error.NotDisposableRoot;
    directory.close(fixture.io);
}

fn diagnostic(err: anyerror) []const u8 {
    return switch (err) {
        error.NotDisposableRoot => "disposable fixture root",
        error.RollbackCrashRequiresRecoveringCaller => "rollback crashes require a recovering helper-bound runtime caller",
        error.DeadlineRequiresHelperBoundCaller => "execution deadlines require a typed helper-bound caller",
        error.RecoveryMustUsePersistedEvidence => "recovery consumes persisted evidence",
        else => @errorName(err),
    };
}

fn preflight(fixture: *foundation.Fixture, root: []const u8, input: Input) !void {
    try guarded(fixture, root);
    if (input.rollback_crash) |seam| {
        const allowed = for ([_][]const u8{
            "during_known_unpack_rollback",
            "after_known_unpack_rollback",
            "after_helper_cleanup_prepared",
            "during_helper_cleanup",
            "after_helper_cleanup_completed",
        }) |point| {
            if (std.mem.eql(u8, seam, point)) break true;
        } else false;
        if (!std.mem.eql(u8, input.operation, "recover") or !input.caller_owned or
            !input.isolated_helper or input.core_product or !allowed)
            return error.RollbackCrashRequiresRecoveringCaller;
    }
    if (input.deadline_after_ms) |duration|
        if (duration < 0 or !input.caller_owned or !input.isolated_helper or input.core_product)
            return error.DeadlineRequiresHelperBoundCaller;
    if (std.mem.eql(u8, input.operation, "recover") and
        (input.archive != null or input.crash_at != null))
        return error.RecoveryMustUsePersistedEvidence;
    if (input.core_completion_crash != null and
        (!std.mem.eql(u8, input.operation, "recover") or !input.core_product))
        return error.CoreCompletionBelongsToCoreRecovery;
}

fn invoke(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    architecture: []const u8,
    destination: []const u8,
    input: Input,
) !?std.json.Parsed(Report) {
    try preflight(fixture, root, input);
    try fixture.directory(destination);
    const request_relative = try support.path(fixture.allocator, destination, "native.request.json");
    const report_relative = try support.path(fixture.allocator, destination, "native.report.json");
    const request = try fixture.absolute(request_relative);
    const report = try fixture.absolute(report_relative);
    try support.absent(fixture, report_relative);
    const payload = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = root,
        .architecture = architecture,
        .operation = input.operation,
        .archives = if (input.archive) |archive| &.{archive} else &.{},
        .packages = &.{},
        .report = report,
        .recovery = true,
        .caller_owned = input.caller_owned,
        .isolated_helper = input.isolated_helper,
        .core_product = input.core_product,
        .triggers = input.triggers,
        .acknowledge_native = input.acknowledge,
        .crash_at = input.rollback_crash orelse input.crash_at,
        .core_completion_crash = input.core_completion_crash,
        .deadline_after_ms = if (input.deadline_after_ms) |duration| @as(?u64, @intCast(duration)) else null,
    }, .{});
    try fixture.write(request_relative, payload, 0o644);
    try fixture.environment.put("DEBZ_NATIVE_LIFECYCLE_REQUEST", request);
    const result = try std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", driver },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    });
    const output = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    try fixture.write(try support.path(fixture.allocator, destination, "native.log"), output, 0o644);
    const crashing = input.crash_at != null or input.rollback_crash != null or input.core_completion_crash != null;
    const expected: u8 = if (crashing) 86 else 0;
    if (result.term != .exited or result.term.exited != expected) {
        std.debug.print("{s}: exit {any}, expected {d}; log:\n{s}\n", .{
            destination, result.term, expected, output[output.len - @min(output.len, 12_000) ..],
        });
        return error.UnexpectedNativeExit;
    }
    if (crashing) {
        try support.absent(fixture, report_relative);
        return null;
    }
    const bytes = try support.read(fixture, report_relative, 64 * 1024);
    return try std.json.parseFromSlice(Report, fixture.allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
}

fn rootRelative(fixture: *foundation.Fixture, root: []const u8, name: []const u8) ![]const u8 {
    try guarded(fixture, root);
    return support.path(fixture.allocator, root[fixture.path.len + 1 ..], name);
}

fn rootBytes(fixture: *foundation.Fixture, root: []const u8, name: []const u8) ![]u8 {
    return support.read(fixture, try rootRelative(fixture, root, name), 16 * 1024 * 1024);
}

fn rootDocument(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !std.json.Parsed(std.json.Value) {
    const bytes = try rootBytes(fixture, root, name);
    return std.json.parseFromSlice(std.json.Value, fixture.allocator, bytes, .{ .allocate = .alloc_always });
}

fn expectText(value: std.json.Value, key: []const u8, expected: []const u8) !void {
    if (value != .object) return error.InvalidEvidence;
    const item = value.object.get(key) orelse return error.MissingEvidenceField;
    if (item != .string or !std.mem.eql(u8, item.string, expected)) return error.UnexpectedEvidence;
}

fn rejected(fixture: *foundation.Fixture, root: []const u8, arch: []const u8, name: []const u8, input: Input, expected: anyerror, message: []const u8) !void {
    const destination = try support.path(fixture.allocator, "refusals", name);
    try std.testing.expectError(expected, invoke(fixture, sentinel_driver, root, arch, destination, input));
    if (!std.mem.eql(u8, diagnostic(expected), message)) return error.WrongPreflightDiagnostic;
    try support.absent(fixture, destination);
    std.debug.print("pre-spawn {s}: {s}; no request or child\n", .{ name, message });
}

fn preSpawnRefusals(fixture: *foundation.Fixture, arch: []const u8) !void {
    const root = try fixture.makeRoot("refusals/native", arch);
    const original = try foundation.capture(fixture.allocator, fixture.io, root);
    try rejected(fixture, "/", arch, "host-recovery", .{ .operation = "recover" }, error.NotDisposableRoot, "disposable fixture root");
    for ([_]struct { name: []const u8, input: Input }{
        .{ .name = "rollback-install", .input = .{
            .operation = "install",
            .caller_owned = true,
            .isolated_helper = true,
            .rollback_crash = "during_known_unpack_rollback",
        } },
        .{ .name = "rollback-core", .input = .{
            .operation = "recover",
            .caller_owned = true,
            .isolated_helper = true,
            .core_product = true,
            .rollback_crash = "during_known_unpack_rollback",
        } },
        .{ .name = "rollback-unowned", .input = .{
            .operation = "recover",
            .rollback_crash = "during_known_unpack_rollback",
        } },
        .{ .name = "rollback-wrong-seam", .input = .{
            .operation = "recover",
            .caller_owned = true,
            .isolated_helper = true,
            .rollback_crash = "after_execution_intent",
        } },
    }) |case| try rejected(fixture, root, arch, case.name, case.input, error.RollbackCrashRequiresRecoveringCaller, "rollback crashes require a recovering helper-bound runtime caller");
    for ([_]struct { name: []const u8, input: Input }{
        .{ .name = "deadline-unowned", .input = .{
            .operation = "recover",
            .deadline_after_ms = 0,
        } },
        .{ .name = "deadline-no-helper", .input = .{
            .operation = "recover",
            .caller_owned = true,
            .deadline_after_ms = 0,
        } },
        .{ .name = "deadline-negative", .input = .{
            .operation = "recover",
            .caller_owned = true,
            .isolated_helper = true,
            .deadline_after_ms = -1,
        } },
        .{ .name = "deadline-core", .input = .{
            .operation = "recover",
            .caller_owned = true,
            .isolated_helper = true,
            .core_product = true,
            .deadline_after_ms = 0,
        } },
    }) |case| try rejected(fixture, root, arch, case.name, case.input, error.DeadlineRequiresHelperBoundCaller, "execution deadlines require a typed helper-bound caller");
    const after = try foundation.capture(fixture.allocator, fixture.io, root);
    if (!std.mem.eql(u8, original, after)) return error.RefusalChangedRoot;
}

fn rollbackSeam(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const package = "rollback-seam";
    var scenario = try support.Scenario.init(fixture, package, driver, dpkg, arch, true);
    defer scenario.deinit();
    const first = try support.makePackage(fixture, arch, "1", package, "rollback-seam/packages", .{
        .full_payload = true,
        .conffile_content = "configuration 1\n",
    });
    const second = try support.makePackage(fixture, arch, "2", package, "rollback-seam/packages", .{
        .full_payload = true,
        .conffile_content = "configuration 2\n",
    });
    try scenario.seed(first);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const mark = try std.fmt.allocPrint(fixture.allocator, "rollback-seam/{s}/{s}", .{ side, support.failure });
        try support.fixtureFile(fixture, mark, package ++ "@1:postrm:upgrade\n" ++ package ++ "@2:postrm:failed-upgrade\n", 0o644);
    }
    var directory = try foundation.guardedRoot(fixture.io, scenario.reference_root);
    const original_link = try (root_fs.Root.init(fixture.io, directory)).entry(
        try root_fs.Path.init("usr/share/rollback-seam/current"),
    );
    directory.close(fixture.io);
    if (original_link.kind != .sym_link) return error.RollbackLinkTypeChanged;
    const started: i64 = @intCast(std.Io.Clock.real.now(fixture.io).nanoseconds);
    try fixture.directory("rollback-seam/reference-upgrade");
    if (try support.reference(fixture, dpkg, scenario.reference_root, .{
        .operation = "upgrade",
        .archives = &.{second},
    }, "rollback-seam/reference-upgrade") != 1) return error.ReferenceUpgradeDidNotFail;
    _ = try invoke(fixture, driver, scenario.native_root, arch, "rollback-seam/crash", .{
        .operation = "upgrade",
        .archive = second,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
        .crash_at = "after_failure_outcome",
    });
    const original_intent = try rootBytes(fixture, scenario.native_root, intent_path);
    var original = try rootDocument(fixture, scenario.native_root, operation_path);
    defer original.deinit();
    try fixture.dir.deleteFile(fixture.io, second[fixture.path.len + 1 ..]);
    try support.absent(fixture, second[fixture.path.len + 1 ..]);
    try support.absent(fixture, try rootRelative(fixture, scenario.native_root, completion_path));
    _ = try invoke(fixture, driver, scenario.native_root, arch, "rollback-seam/rollback-crash", .{
        .operation = "recover",
        .caller_owned = true,
        .isolated_helper = true,
        .rollback_crash = "during_known_unpack_rollback",
    });
    const retained_intent = try rootBytes(fixture, scenario.native_root, intent_path);
    if (!std.mem.eql(u8, original_intent, retained_intent))
        return error.RollbackCrashReplacedExecutionInputs;
    var persisted = try rootDocument(fixture, scenario.native_root, operation_path);
    defer persisted.deinit();
    for ([_][]const u8{ "attempt_id", "request_sha256", "policy_sha256" }) |name| {
        const prior = original.value.object.get(name) orelse return error.MissingOriginalBinding;
        const current = persisted.value.object.get(name) orelse return error.MissingPersistedBinding;
        if (prior != .string or current != .string or !std.mem.eql(u8, prior.string, current.string))
            return error.RollbackCrashReplacedOriginalCaller;
    }
    try support.absent(fixture, try rootRelative(fixture, scenario.native_root, completion_path));
    try support.absent(fixture, try rootRelative(fixture, scenario.native_root, provenance_path));
    var request = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try support.read(fixture, "rollback-seam/rollback-crash/native.request.json", 64 * 1024), .{});
    defer request.deinit();
    if ((request.value.object.get("archives") orelse return error.MissingRecoveryArchives) != .array or
        request.value.object.get("archives").?.array.items.len != 0 or
        (request.value.object.get("packages") orelse return error.MissingRecoveryPackages) != .array or
        request.value.object.get("packages").?.array.items.len != 0 or
        (request.value.object.get("core_product") orelse return error.MissingCoreFlag) != .bool or
        request.value.object.get("core_product").?.bool)
        return error.RollbackCrashReauthorizedCaller;
    try expectText(request.value, "crash_at", "during_known_unpack_rollback");
    var recovered = (try invoke(fixture, driver, scenario.native_root, arch, "rollback-seam/fresh", .{
        .operation = "recover",
        .caller_owned = true,
        .isolated_helper = true,
    })) orelse return error.MissingRollbackRecoveryReport;
    defer recovered.deinit();
    if (!std.mem.eql(u8, recovered.value.outcome, "script_failed") or
        !std.mem.eql(u8, recovered.value.detail, "awaiting_caller_acknowledgment"))
        return error.UnexpectedRollbackRecoveryOutcome;
    const ended: i64 = @intCast(std.Io.Clock.real.now(fixture.io).nanoseconds);
    try fixture.directory("rollback-seam/comparison");
    try support.compareRollback(fixture, scenario.reference_root, scenario.native_root, "rollback-seam/comparison", &.{.{ .path = "usr/share/rollback-seam/current", .original = @intCast(original_link.modified_nanoseconds) }}, started, ended);
    var receipt = try rootDocument(fixture, scenario.native_root, provenance_path);
    defer receipt.deinit();
    try expectText(receipt.value, "outcome", "failed");
    try expectText(receipt.value, "attempt_id", recovered.value.attempt_id orelse return error.UnboundRollbackReport);
    const receipt_before = try rootBytes(fixture, scenario.native_root, provenance_path);
    var acknowledged = (try invoke(fixture, driver, scenario.native_root, arch, "rollback-seam/ack", .{
        .operation = "recover",
        .caller_owned = true,
        .isolated_helper = true,
        .acknowledge = true,
    })) orelse return error.MissingRollbackAcknowledgment;
    defer acknowledged.deinit();
    if (!std.mem.eql(u8, acknowledged.value.outcome, "script_failed"))
        return error.RollbackAcknowledgmentFailed;
    if (!std.mem.eql(u8, receipt_before, try rootBytes(fixture, scenario.native_root, provenance_path)))
        return error.RollbackAcknowledgmentReplacedReceipt;
    try support.absent(fixture, try rootRelative(fixture, scenario.native_root, operation_path));
    try support.absent(fixture, try rootRelative(fixture, scenario.native_root, intent_path));
    std.debug.print("rollback seam: real exit 86, original caller retained, failed recovery matched pinned dpkg and acknowledged\n", .{});
}

fn deadlineZero(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const reference = try fixture.makeRoot("zero/reference", arch);
    const native = try fixture.makeRoot("zero/native", arch);
    try support.copyProgram(fixture, "zero/reference", "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
    try support.copyProgram(fixture, "zero/native", "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
    const archive = try fixture.makePackageWith(arch, "1", .data, .{ .workspace = "zero/packages" });
    try fixture.directory("zero/reference-install");
    if (try support.reference(fixture, dpkg, reference, .{ .operation = "install", .archives = &.{archive} }, "zero/reference-install") != 0) return error.PinnedReferenceInstallFailed;
    _ = try invoke(fixture, driver, native, arch, "zero/crash", .{
        .operation = "install",
        .archive = archive,
        .caller_owned = true,
        .isolated_helper = true,
        .crash_at = "after_execution_intent",
    });
    const record_before = try rootBytes(fixture, native, operation_path);
    const intent_before = try rootBytes(fixture, native, intent_path);
    try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
    try support.absent(fixture, archive[fixture.path.len + 1 ..]);
    const before = try foundation.capture(fixture.allocator, fixture.io, native);
    const raw = try invoke(fixture, driver, native, arch, "zero/expired", .{
        .operation = "recover",
        .caller_owned = true,
        .isolated_helper = true,
        .deadline_after_ms = 0,
    });
    var expired = raw orelse return error.MissingNativeReport;
    defer expired.deinit();
    if (!std.mem.eql(u8, expired.value.outcome, "recovery_required") or
        !std.mem.eql(u8, expired.value.detail, "deadline_exceeded"))
        return error.ZeroDeadlineDidNotExpire;
    const request = try support.read(fixture, "zero/expired/native.request.json", 64 * 1024);
    var parsed = try std.json.parseFromSlice(std.json.Value, fixture.allocator, request, .{});
    defer parsed.deinit();
    const deadline = parsed.value.object.get("deadline_after_ms") orelse return error.MissingZeroDeadline;
    if (deadline != .integer or deadline.integer != 0) return error.ZeroDeadlineNotSerialized;
    for ([_][]const u8{ "caller_owned", "isolated_helper" }) |name| {
        const binding = parsed.value.object.get(name) orelse return error.MissingDeadlineCallerBinding;
        if (binding != .bool or !binding.bool) return error.UnboundZeroDeadline;
    }
    if ((parsed.value.object.get("core_product") orelse return error.MissingCoreFlag) != .bool or
        parsed.value.object.get("core_product").?.bool) return error.CoreCompletionConfusedWithDeadline;
    if ((parsed.value.object.get("core_completion_crash") orelse return error.MissingCoreCrashField) != .null)
        return error.CoreCompletionConfusedWithDeadline;
    const record_after = try rootBytes(fixture, native, operation_path);
    const intent_after = try rootBytes(fixture, native, intent_path);
    if (!std.mem.eql(u8, record_before, record_after) or
        !std.mem.eql(u8, intent_before, intent_after)) return error.ExpiredDeadlineReplacedAuthority;
    const after = try foundation.capture(fixture.allocator, fixture.io, native);
    if (!std.mem.eql(u8, before, after)) return error.ExpiredDeadlineChangedPackageState;
    try support.absent(fixture, try rootRelative(fixture, native, completion_path));
    var recovered = (try invoke(fixture, driver, native, arch, "zero/fresh", .{
        .operation = "recover",
        .caller_owned = true,
        .isolated_helper = true,
        .deadline_after_ms = 30_000,
    })) orelse return error.MissingFreshReport;
    defer recovered.deinit();
    if (!std.mem.eql(u8, recovered.value.outcome, "applied")) return error.FreshRecoveryDidNotComplete;
    try fixture.directory("zero/comparison");
    try foundation.compare(fixture.*, reference, native, "zero/comparison");
    var receipt = try rootDocument(fixture, native, provenance_path);
    defer receipt.deinit();
    try expectText(receipt.value, "outcome", "succeeded");
    try expectText(receipt.value, "attempt_id", recovered.value.attempt_id orelse return error.UnboundReport);
    try support.absent(fixture, try rootRelative(fixture, native, completion_path));
    const receipt_before = try rootBytes(fixture, native, provenance_path);
    var acknowledged = (try invoke(fixture, driver, native, arch, "zero/ack", .{
        .operation = "recover",
        .caller_owned = true,
        .isolated_helper = true,
        .deadline_after_ms = 30_000,
        .acknowledge = true,
    })) orelse return error.MissingAcknowledgmentReport;
    defer acknowledged.deinit();
    if (!std.mem.eql(u8, acknowledged.value.outcome, "applied"))
        return error.AcknowledgmentFailed;
    const receipt_after = try rootBytes(fixture, native, provenance_path);
    if (!std.mem.eql(u8, receipt_before, receipt_after)) return error.AcknowledgmentReplacedReceipt;
    try support.absent(fixture, try rootRelative(fixture, native, operation_path));
    try support.absent(fixture, try rootRelative(fixture, native, intent_path));
    std.debug.print("zero deadline: real crash, serialized 0, immutable expired authority, and pinned-dpkg fresh recovery passed\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    if (!std.mem.eql(u8, args.next() orelse return error.MissingReferencePath, "--reference-dpkg"))
        return error.PinnedReferenceRequired;
    const pinned = args.next() orelse return error.MissingReferencePath;
    if (args.next() != null) return error.InvalidArguments;
    const reference = try support.prerequisites(init, allocator, pinned);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed during final-gap acceptance: {s}\n", .{@errorName(err)});
    try preSpawnRefusals(&fixture, reference.architecture);
    try rollbackSeam(&fixture, driver, reference.executable, reference.architecture);
    try deadlineZero(&fixture, driver, reference.executable, reference.architecture);
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
