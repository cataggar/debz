const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");
const root_fs = @import("debz").root_fs;

const receiver = "debz-no-handler-receiver";
const second_receiver = receiver ++ "-second";
const scripted_receiver = "debz-no-handler-z-scripted";
const trigger = "debz-no-handler";
const namespace = "var/lib/debz/";

pub const Report = struct {
    outcome: []const u8,
    detail: []const u8 = "",
    attempt_id: ?[]const u8 = null,
    program_sha256: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
};

pub const Invocation = struct {
    operation: []const u8,
    archives: []const []const u8 = &.{},
    packages: []const foundation.PackageIdentity = &.{},
    crash_at: ?[]const u8 = null,
    triggers: bool = true,
    defer_triggers: bool = false,
    caller_owned: bool = false,
    isolated_helper: bool = false,
    core_product: bool = false,
    policy: []const u8 = "keep_existing",
};

pub fn rootPath(fixture: *foundation.Fixture, root: []const u8, name: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, root, fixture.path) or root.len <= fixture.path.len or
        root[fixture.path.len] != '/') return error.InvalidFixtureRoot;
    _ = try root_fs.Path.initPackage(name);
    return support.path(fixture.allocator, root[fixture.path.len + 1 ..], name);
}

pub fn rootBytes(fixture: *foundation.Fixture, root: []const u8, name: []const u8) ![]u8 {
    const path = try rootPath(fixture, root, name);
    defer fixture.allocator.free(path);
    return support.read(fixture, path, 16 * 1024 * 1024);
}

pub fn rootDocument(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !std.json.Parsed(std.json.Value) {
    const bytes = try rootBytes(fixture, root, name);
    defer fixture.allocator.free(bytes);
    return std.json.parseFromSlice(std.json.Value, fixture.allocator, bytes, .{ .allocate = .alloc_always });
}

pub fn rootAbsent(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !void {
    const path = try rootPath(fixture, root, name);
    defer fixture.allocator.free(path);
    try support.absent(fixture, path);
}

pub fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidRecoveryEvidence;
    return value.object.get(name) orelse error.MissingRecoveryEvidence;
}

pub fn text(value: std.json.Value, name: []const u8) ![]const u8 {
    const item = try field(value, name);
    if (item != .string) return error.InvalidRecoveryEvidence;
    return item.string;
}

pub fn same(actual: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, actual, expected)) {
        std.debug.print("expected {s}, got {s}\n", .{ expected, actual });
        return error.RecoveryEvidenceMismatch;
    }
}

pub fn invoke(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    arch: []const u8,
    destination: []const u8,
    input: Invocation,
) !?std.json.Parsed(Report) {
    var guarded = try foundation.guardedRoot(fixture.io, root);
    guarded.close(fixture.io);
    if (std.mem.eql(u8, input.operation, "recover") and
        (input.archives.len != 0 or input.packages.len != 0 or input.crash_at != null))
        return error.RecoveryMustUsePersistedEvidence;
    if (input.isolated_helper and !input.caller_owned) return error.IsolatedHelperRequiresCaller;
    try fixture.directory(destination);
    const request = try support.path(fixture.allocator, destination, "native.request.json");
    defer fixture.allocator.free(request);
    const response = try support.path(fixture.allocator, destination, "native.report.json");
    defer fixture.allocator.free(response);
    try support.absent(fixture, response);
    const request_absolute = try fixture.absolute(request);
    defer fixture.allocator.free(request_absolute);
    const response_absolute = try fixture.absolute(response);
    defer fixture.allocator.free(response_absolute);
    const payload = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = root,
        .architecture = arch,
        .operation = input.operation,
        .archives = input.archives,
        .packages = input.packages,
        .report = response_absolute,
        .recovery = true,
        .triggers = input.triggers,
        .defer_triggers = input.defer_triggers,
        .caller_owned = input.caller_owned,
        .isolated_helper = input.isolated_helper,
        .core_product = input.core_product,
        .policy = input.policy,
        .crash_at = input.crash_at,
    }, .{});
    defer fixture.allocator.free(payload);
    try fixture.write(request, payload, 0o644);
    try fixture.environment.put("DEBZ_NATIVE_LIFECYCLE_REQUEST", request_absolute);
    const log = try support.path(fixture.allocator, destination, "native.log");
    defer fixture.allocator.free(log);
    const result = try std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", driver },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    });
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const output = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    defer fixture.allocator.free(output);
    try fixture.write(log, output, 0o644);
    const exit: u8 = if (input.crash_at != null) 86 else 0;
    if (result.term != .exited or result.term.exited != exit) {
        std.debug.print("{s}: exit {any}, expected {d}; fixture {s}/{s}:\n{s}\n", .{
            destination, result.term, exit, fixture.path, log, output[output.len - @min(output.len, 12_000) ..],
        });
        return error.UnexpectedNativeProcessExit;
    }
    if (input.crash_at != null) {
        try support.absent(fixture, response);
        return null;
    }
    const bytes = try support.read(fixture, response, 64 * 1024);
    defer fixture.allocator.free(bytes);
    const report = try std.json.parseFromSlice(Report, fixture.allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    for ([_][]const u8{ "applied", "script_failed", "recovery_required", "refused" }) |outcome|
        if (std.mem.eql(u8, report.value.outcome, outcome)) return report;
    var invalid = report;
    invalid.deinit();
    return error.UnexpectedNativeOutcome;
}

fn statusPending(fixture: *foundation.Fixture, root: []const u8) !bool {
    const status = try rootBytes(fixture, root, "var/lib/dpkg/status");
    defer fixture.allocator.free(status);
    var stanzas = std.mem.splitSequence(u8, status, "\n\n");
    while (stanzas.next()) |stanza| {
        if (!std.mem.startsWith(u8, stanza, "Package: " ++ receiver ++ "\n")) continue;
        return std.mem.indexOf(u8, stanza, "\nTriggers-Pending: " ++ trigger ++ "\n") != null or
            std.mem.endsWith(u8, stanza, "\nTriggers-Pending: " ++ trigger);
    }
    return error.MissingScriptlessReceiver;
}

fn checkAuthority(fixture: *foundation.Fixture, root: []const u8, before_completion: bool) !void {
    try rootAbsent(fixture, root, namespace ++ "native-lifecycle-script-v1.json");
    var authority = try rootDocument(fixture, root, namespace ++ "native-trigger-authority-v1.json");
    defer authority.deinit();
    const handlers = try field(authority.value, "handlers");
    const callers = try field(authority.value, "callers");
    if (handlers != .array or callers != .array) return error.InvalidTriggerAuthority;
    var found: usize = 0;
    for (handlers.array.items) |handler| {
        if (!std.mem.eql(u8, try text(try field(handler, "package"), "name"), receiver)) continue;
        found += 1;
        if (try field(handler, "postinst_sha256") != .null)
            return error.ScriptlessHandlerAcquiredScript;
    }
    for (callers.array.items) |caller|
        if (std.mem.eql(u8, try text(try field(caller, "package"), "name"), receiver))
            return error.ScriptlessHandlerRan;
    if (found != 1 or (try statusPending(fixture, root)) != before_completion)
        return error.WrongScriptlessTriggerProgress;
}

fn checkRetainedScripts(fixture: *foundation.Fixture, root: []const u8, proof: std.json.Value) !void {
    const files = try field(proof, "evidence_files");
    if (files != .array) return error.InvalidRecoveryEvidence;
    var scripted_trigger_count: usize = 0;
    for (files.array.items) |entry| {
        if (!std.mem.eql(u8, try text(entry, "kind"), "script_outcome")) continue;
        const path = try text(entry, "path");
        if (!std.mem.startsWith(u8, path, namespace ++ "native-receipts-v1/"))
            return error.UnboundRetainedScript;
        var script = try rootDocument(fixture, root, path);
        defer script.deinit();
        const package = try text(script.value, "package");
        if (std.mem.eql(u8, package, receiver) or std.mem.eql(u8, package, second_receiver))
            return error.ScriptlessHandlerRan;
        if (!std.mem.eql(u8, package, scripted_receiver)) continue;
        const arguments = try field(script.value, "arguments");
        if (arguments != .array or arguments.array.items.len == 0 or arguments.array.items[0] != .string)
            return error.InvalidRecoveryEvidence;
        if (std.mem.eql(u8, arguments.array.items[0].string, "triggered")) scripted_trigger_count += 1;
    }
    if (scripted_trigger_count != 1) return error.ScriptedHandlerTriggerCountChanged;
    try rootAbsent(fixture, root, "var/lib/dpkg/info/" ++ receiver ++ ".postinst");
    try rootAbsent(fixture, root, "var/lib/dpkg/info/" ++ second_receiver ++ ".postinst");
}

fn runCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, new: bool, boundary: []const u8, drift: bool) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "no-handler-{s}-{s}{s}", .{
        if (new) "new" else "installed", boundary, if (drift) "-drift" else "",
    });
    defer fixture.allocator.free(name);
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    const receiver_archive = try support.makePackage(fixture, arch, "1", receiver, try support.path(fixture.allocator, name, "receiver"), .{
        .declarations = "interest-await " ++ trigger ++ "\n",
        .no_scripts = true,
    });
    defer fixture.allocator.free(receiver_archive);
    const second_archive = try support.makePackage(fixture, arch, "1", second_receiver, try support.path(fixture.allocator, name, "second"), .{
        .declarations = "interest-await " ++ trigger ++ "\n",
        .no_scripts = true,
    });
    defer fixture.allocator.free(second_archive);
    const scripted_archive = try support.makePackage(fixture, arch, "1", scripted_receiver, try support.path(fixture.allocator, name, "scripted"), .{
        .declarations = "interest-await " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(scripted_archive);
    const source_archive = try support.makePackage(fixture, arch, "1", "debz-no-handler-source", try support.path(fixture.allocator, name, "source"), .{
        .declarations = "activate-await " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(source_archive);
    if (!new) {
        try case.seed(receiver_archive);
        try case.seed(second_archive);
        try case.seed(scripted_archive);
    }
    const archives: []const []const u8 = if (new)
        &.{ receiver_archive, second_archive, scripted_archive, source_archive }
    else
        &.{source_archive};
    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "install",
        .archives = archives,
        .triggers = true,
    }, reference_log) != 0) return error.ReferenceInstallFailed;
    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = "install", .archives = archives, .crash_at = boundary,
    })) |value| {
        var invalid = value;
        invalid.deinit();
        return error.MissingCrash;
    }
    for (archives) |archive| {
        try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
        try support.absent(fixture, archive[fixture.path.len + 1 ..]);
    }
    try checkAuthority(fixture, case.native_root, std.mem.eql(u8, boundary, "before_scriptless_trigger_completion"));
    if (drift) {
        const path = try rootPath(fixture, case.native_root, "var/lib/dpkg/info/" ++ receiver ++ ".postinst");
        defer fixture.allocator.free(path);
        try support.fixtureFile(fixture, path, "#!/bin/sh\nexit 0\n", 0o755);
    }
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recover_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recover_log);
    var report = (try invoke(fixture, driver, case.native_root, arch, recover_log, .{ .operation = "recover" })) orelse
        return error.MissingRecoveryReport;
    defer report.deinit();
    if (drift) {
        if (!std.mem.eql(u8, report.value.outcome, "recovery_required") and
            !std.mem.eql(u8, report.value.outcome, "refused"))
            return error.DriftWasAccepted;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.BlockedRecoveryMutatedRoot;
        return;
    }
    try same(report.value.outcome, "applied");
    const comparison = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(comparison);
    try fixture.directory(comparison);
    try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
    const proof_path = report.value.provenance_path orelse return error.MissingRecoveryProof;
    if (!std.mem.startsWith(u8, proof_path, namespace))
        return error.UnboundRecoveryProof;
    var proof = try rootDocument(fixture, case.native_root, proof_path);
    defer proof.deinit();
    try same(try text(proof.value, "attempt_id"), report.value.attempt_id orelse return error.MissingRecoveryProof);
    try same(try text(proof.value, "program_sha256"), report.value.program_sha256 orelse return error.MissingRecoveryProof);
    try same(try text(proof.value, "install_root"), case.native_root);
    try checkRetainedScripts(fixture, case.native_root, proof.value);
    for ([_][]const u8{
        "root-operation-v1.json", "root-mutation-v1.json",
        "native-lifecycle-script-v1.json", "native-trigger-authority-v1.json",
    }) |file| {
        const path = try std.fmt.allocPrint(fixture.allocator, "{s}{s}", .{ namespace, file });
        defer fixture.allocator.free(path);
        try rootAbsent(fixture, case.native_root, path);
    }
    const proof_before = try rootBytes(fixture, case.native_root, proof_path);
    defer fixture.allocator.free(proof_before);
    const settled = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(settled);
    const repeat_log = try support.path(fixture.allocator, name, "recover-again");
    defer fixture.allocator.free(repeat_log);
    var repeated = (try invoke(fixture, driver, case.native_root, arch, repeat_log, .{ .operation = "recover" })) orelse
        return error.MissingRecoveryReport;
    defer repeated.deinit();
    try same(repeated.value.outcome, "applied");
    const proof_after = try rootBytes(fixture, case.native_root, proof_path);
    defer fixture.allocator.free(proof_after);
    if (!std.mem.eql(u8, proof_before, proof_after)) return error.RepeatedRecoveryReplacedProof;
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, settled, after)) return error.RepeatedRecoveryMutatedRoot;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    const driver = arguments.next() orelse return error.MissingNativeDriver;
    var pinned: ?[]const u8 = null;
    while (arguments.next()) |argument| {
        if (!std.mem.eql(u8, argument, "--reference-dpkg") or pinned != null)
            return error.InvalidArguments;
        pinned = arguments.next() orelse return error.MissingReferencePath;
    }
    const reference = try support.prerequisites(init, allocator, pinned);
    defer allocator.free(reference.architecture);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed after scriptless failure: {s}\n", .{@errorName(err)});
    for ([_]bool{ false, true }) |new| {
        for ([_]struct { boundary: []const u8, drift: bool }{
            .{ .boundary = "before_scriptless_trigger_completion", .drift = false },
            .{ .boundary = "after_scriptless_trigger_completion", .drift = false },
            .{ .boundary = "before_scriptless_trigger_completion", .drift = true },
        }) |entry| {
            try runCase(&fixture, driver, reference.executable, reference.architecture, new, entry.boundary, entry.drift);
            std.debug.print("scriptless {s}/{s}/drift={}: recovered or blocked\n", .{ if (new) "new" else "installed", entry.boundary, entry.drift });
        }
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
