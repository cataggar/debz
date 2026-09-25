const std = @import("std");
const linux = std.os.linux;
const debz = @import("debz");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const oracle = @import("native_recovery_oracle.zig");
const projected = @import("native_recovery_projected_workflows.zig");
const options = @import("native_test_options");

const family_schema = "io.github.cataggar.debz.package-family.request.v2";
const family_result_schema = "io.github.cataggar.debz.package-family.result.v2";
const refusal_root = "disposable fixture root";
const refusal_planning = "requires a family request";

pub const FamilyRequest = struct {
    schema: []const u8 = family_schema,
    version: u32 = 2,
    operation: []const u8,
    root: []const u8,
    architecture: []const u8,
    foreign_architectures: []const []const u8 = &.{},
    sources: []const []const u8 = &.{},
    keyrings: []const []const u8 = &.{},
    cache: []const u8,
    state: []const u8,
    package: ?[]const u8 = null,
    lock_input: ?[]const u8 = null,
    lock_output: ?[]const u8 = null,
    conffile: []const u8 = "keep_existing",
    recommends: bool = false,
    allow_downgrade: bool = false,
};

pub const Invocation = struct {
    family_execution: ?FamilyRequest = null,
    family_verification: ?FamilyRequest = null,
    verification_expect_failure: bool = true,
    verification_completion: ?std.json.Value = null,
    family_update_planning: bool = false,
    capture_evidence: bool = false,
    ordinary_plan: bool = false,
    ordinary_operation: []const u8 = "install",
    ordinary_mode: ?[]const u8 = null,
    selectors: []const Selector = &.{},
    cache_path: ?[]const u8 = null,
    state_path: ?[]const u8 = null,
    sources: []const []const u8 = &.{},
    keyrings: []const []const u8 = &.{},
    lock_input: ?[]const u8 = null,
    lock_output: ?[]const u8 = null,
    conffile: []const u8 = "keep_existing",
    recommends: bool = false,
    force: []const []const u8 = &.{},
    orchestration_id: ?[32]u8 = null,
    root_attempt_id: ?[32]u8 = null,
    defer_recovery_clear: bool = false,
    owner_evidence: ?[]const u8 = null,
    acknowledgment: ?[]const u8 = null,
    owned_verification: ?OwnedVerification = null,
    reconciliation_claim: ?std.json.Value = null,
    reconciliation_owner_output: ?[]const u8 = null,
    completion_crash: ?[]const u8 = null,
};

pub const OwnedVerification = struct {
    lock_path: []const u8,
    state: []const u8,
    outcome: []const u8 = "succeeded",
    expected_error: ?[]const u8 = null,
};

pub const Selector = struct {
    name: []const u8,
    architecture: ?[]const u8 = null,
};

pub const Response = struct {
    report: std.json.Parsed(std.json.Value),
    evidence: ?std.json.Parsed(std.json.Value) = null,

    pub fn deinit(self: *Response) void {
        self.report.deinit();
        if (self.evidence) |*evidence| evidence.deinit();
    }
};

pub fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidFamilyDocument;
    return value.object.get(name) orelse error.MissingFamilyField;
}

pub fn string(value: std.json.Value, name: []const u8) ![]const u8 {
    const item = try field(value, name);
    if (item != .string) return error.InvalidFamilyDocument;
    return item.string;
}

pub fn same(actual: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, actual, expected)) {
        std.debug.print("expected {s}, observed {s}\n", .{ expected, actual });
        return error.UnexpectedFamilyResult;
    }
}

pub fn parse(fixture: *foundation.Fixture, relative: []const u8, limit: usize) !std.json.Parsed(std.json.Value) {
    const bytes = try support.read(fixture, relative, limit);
    defer fixture.allocator.free(bytes);
    return std.json.parseFromSlice(std.json.Value, fixture.allocator, bytes, .{ .allocate = .alloc_always });
}

fn preflight(fixture: *foundation.Fixture, root: []const u8, invocation: Invocation) !void {
    if (root.len <= fixture.path.len or !std.mem.startsWith(u8, root, fixture.path) or root[fixture.path.len] != '/') {
        std.debug.print("{s}: {s}\n", .{ preflightDiagnostic(error.NotDisposableRoot), root });
        return error.NotDisposableRoot;
    }
    var guarded = foundation.guardedRoot(fixture.io, root) catch {
        std.debug.print("{s}: {s}\n", .{ preflightDiagnostic(error.NotDisposableRoot), root });
        return error.NotDisposableRoot;
    };
    guarded.close(fixture.io);
    if (invocation.family_update_planning and invocation.family_execution == null) {
        std.debug.print("{s}\n", .{preflightDiagnostic(error.FamilyRequestRequired)});
        return error.FamilyRequestRequired;
    }
    if (invocation.family_execution) |request|
        if (!std.mem.eql(u8, request.root, root)) return error.InvalidFamilyRoot;
    if (invocation.family_verification) |request|
        if (!std.mem.eql(u8, request.root, root)) return error.InvalidFamilyRoot;
    if (invocation.family_execution != null and invocation.family_verification != null)
        return error.ConflictingFamilyMethods;
}

fn preflightDiagnostic(err: anyerror) []const u8 {
    return switch (err) {
        error.NotDisposableRoot => refusal_root,
        error.FamilyRequestRequired => refusal_planning,
        else => @errorName(err),
    };
}

pub fn workflow(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    arch: []const u8,
    destination: []const u8,
    invocation: Invocation,
) !Response {
    return (try runWorkflow(fixture, driver, root, arch, destination, invocation)) orelse
        error.UnexpectedFamilyProcessExit;
}

pub fn workflowCrash(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    arch: []const u8,
    destination: []const u8,
    invocation: Invocation,
) !void {
    if (invocation.completion_crash == null) return error.MissingCompletionCrash;
    if (try runWorkflow(fixture, driver, root, arch, destination, invocation)) |response| {
        var unexpected = response;
        unexpected.deinit();
        return error.UnexpectedFamilyReport;
    }
}

fn runWorkflow(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    arch: []const u8,
    destination: []const u8,
    invocation: Invocation,
) !?Response {
    try preflight(fixture, root, invocation);
    try fixture.directory(destination);
    const request_relative = try support.path(fixture.allocator, destination, "workflow.request.json");
    defer fixture.allocator.free(request_relative);
    const report_relative = try support.path(fixture.allocator, destination, "workflow.report.json");
    defer fixture.allocator.free(report_relative);
    const evidence_relative = try support.path(fixture.allocator, destination, "native-evidence.json");
    defer fixture.allocator.free(evidence_relative);
    const log_relative = try support.path(fixture.allocator, destination, "workflow.log");
    defer fixture.allocator.free(log_relative);
    try support.absent(fixture, report_relative);
    try support.absent(fixture, evidence_relative);
    const request_path = try fixture.absolute(request_relative);
    defer fixture.allocator.free(request_path);
    const report_path = try fixture.absolute(report_relative);
    defer fixture.allocator.free(report_path);
    const evidence_path = if (invocation.capture_evidence) try fixture.absolute(evidence_relative) else null;
    defer if (evidence_path) |path| fixture.allocator.free(path);
    const cache = try support.path(fixture.allocator, fixture.path, "unused-cache");
    defer fixture.allocator.free(cache);
    const state = try support.path(fixture.allocator, fixture.path, "unused-state");
    defer fixture.allocator.free(state);
    const payload = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .workflow = .{
            .operation = invocation.ordinary_operation,
            .mode = invocation.ordinary_mode orelse if (invocation.ordinary_plan) "plan_only" else "recover",
            .selectors = if (invocation.selectors.len != 0) invocation.selectors else if (invocation.ordinary_plan) &.{Selector{ .name = "alpha" }} else &.{},
            .options = .{
                .install_root = root,
                .architecture = arch,
                .cache_path = invocation.cache_path orelse cache,
                .state_path = invocation.state_path orelse state,
                .source_paths = invocation.sources,
                .keyring_paths = invocation.keyrings,
                .lock_input_path = invocation.lock_input,
                .lock_output_path = invocation.lock_output,
                .conffile = invocation.conffile,
                .recommends = invocation.recommends,
                .force = invocation.force,
                .assume_yes = true,
                .noninteractive = true,
            },
            .orchestration_id = invocation.orchestration_id,
            .root_attempt_id = invocation.root_attempt_id,
            .defer_recovery_clear = invocation.defer_recovery_clear,
            .reconciliation_claim = invocation.reconciliation_claim,
        },
        .report = report_path,
        .completion_crash = invocation.completion_crash,
        .owner_evidence = invocation.owner_evidence,
        .acknowledgment = invocation.acknowledgment,
        .owned_verification = invocation.owned_verification,
        .reconciliation_owner_output = invocation.reconciliation_owner_output,
        .family_verification = if (invocation.family_verification) |request| .{
            .request = request,
            .expect_failure = invocation.verification_expect_failure,
            .completion = invocation.verification_completion,
        } else null,
        .family_execution = invocation.family_execution,
        .family_update_planning = invocation.family_update_planning,
        .native_evidence_output = evidence_path,
    }, .{});
    defer fixture.allocator.free(payload);
    try fixture.write(request_relative, payload, 0o644);
    try fixture.environment.put("DEBZ_NATIVE_WORKFLOW_REQUEST", request_path);

    const result = std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", driver },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    }) catch |err| {
        const note = try std.fmt.allocPrint(fixture.allocator, "native workflow driver failed: {s}\n", .{@errorName(err)});
        defer fixture.allocator.free(note);
        try fixture.write(log_relative, note, 0o644);
        std.debug.print("{s}: driver launch failed: {s}\n", .{ destination, @errorName(err) });
        return err;
    };
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const log = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    defer fixture.allocator.free(log);
    try fixture.write(log_relative, log, 0o644);
    const expected_exit: u8 = if (invocation.completion_crash != null) 86 else 0;
    if (result.term != .exited or result.term.exited != expected_exit) {
        std.debug.print("{s}: exit {any}, expected {d}; {s}/{s}\n{s}\n", .{
            destination, result.term, expected_exit, fixture.path, log_relative, log[log.len - @min(log.len, 12_000) ..],
        });
        return error.UnexpectedFamilyProcessExit;
    }
    if (invocation.completion_crash != null) {
        try support.absent(fixture, report_relative);
        try support.absent(fixture, evidence_relative);
        return null;
    }
    var report = try parse(fixture, report_relative, 64 * 1024);
    errdefer report.deinit();
    const evidence = if (invocation.capture_evidence) try parse(fixture, evidence_relative, 1024 * 1024) else null;
    if (!invocation.capture_evidence) try support.absent(fixture, evidence_relative);
    return .{ .report = report, .evidence = evidence };
}

fn expectFamily(report: std.json.Value, operation: []const u8, succeeded: bool) !void {
    try same(try string(report, "schema"), family_result_schema);
    try std.testing.expectEqual(@as(i64, 2), (try field(report, "version")).integer);
    try same(try string(report, "operation"), operation);
    try std.testing.expectEqual(succeeded, (try field(report, "succeeded")).bool);
}

fn familyRequest(fixture: *foundation.Fixture, root: []const u8, arch: []const u8, operation: []const u8) !FamilyRequest {
    return .{
        .operation = operation,
        .root = root,
        .architecture = arch,
        .cache = try fixture.absolute("unused-family-cache"),
        .state = try fixture.absolute("unused-family-state"),
    };
}

fn repositoryFixture(fixture: *foundation.Fixture, name: []const u8) ![]u8 {
    const path = try std.fs.path.join(fixture.allocator, &.{ options.repository, "src/fixtures/batch_workflow", name });
    defer fixture.allocator.free(path);
    var file = try std.Io.Dir.cwd().openFile(fixture.io, path, .{});
    defer file.close(fixture.io);
    var reader = file.reader(fixture.io, &.{});
    return reader.interface.allocRemaining(fixture.allocator, .limited(4096));
}

fn transport(fixture: *foundation.Fixture, driver: []const u8, arch: []const u8) !void {
    const root = try fixture.makeRoot("family/native", arch);
    defer fixture.allocator.free(root);
    const status = "Package: zeta\nVersion: 2\nArchitecture: arm64\nStatus: deinstall ok config-files\n\n" ++
        "Package: beta\nVersion: 3\nArchitecture: amd64\nStatus: install reinstreq half-configured\n\n" ++
        "Package: alpha\nVersion: 1\nArchitecture: amd64\nStatus: hold ok installed\n";
    try fixture.write("family/native/var/lib/dpkg/status", status, 0o644);
    const before = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(before);
    const inspect = try familyRequest(fixture, root, arch, "inspect");
    var inspected = try workflow(fixture, driver, root, arch, "family/inspection", .{
        .family_execution = inspect,
        .capture_evidence = true,
    });
    defer inspected.deinit();
    try expectFamily(inspected.report.value, "inspect", true);
    try same(try string(inspected.report.value, "exit_status"), "success");
    const evidence = inspected.evidence.?.value;
    const actual = try oracle.validateDiagnosticInspection(inspected.report.value, evidence, root);
    try std.testing.expect((try field(actual, "status_database_present")).bool);
    try std.testing.expect(!(try field(actual, "native_active_evidence")).bool);
    const packages = (try field(actual, "packages")).array.items;
    try std.testing.expectEqual(@as(usize, 3), packages.len);
    try same(try string(packages[0], "name"), "alpha");
    try same(try string(packages[1], "name"), "beta");
    const partial = try field(packages[1], "status");
    try same(try string(partial, "error_state"), "reinst_required");
    try same(try string(partial, "current"), "half_configured");
    try same(try string(packages[2], "name"), "zeta");
    try std.testing.expectEqual(.null, try field(evidence, "native_completion"));
    try std.testing.expectEqual(.null, try field(evidence, "native_install"));
    try support.absent(fixture, "unused-family-cache");
    try support.absent(fixture, "unused-family-state");
    const after = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);

    const report_bytes = try support.read(fixture, "family/inspection/workflow.report.json", 64 * 1024);
    defer fixture.allocator.free(report_bytes);
    const evidence_bytes = try support.read(fixture, "family/inspection/native-evidence.json", 1024 * 1024);
    defer fixture.allocator.free(evidence_bytes);
    for ([_]struct { original: []const u8, changed: []const u8 }{
        .{ .original = "\"changed\":false", .changed = "\"changed\":true" },
        .{ .original = "\"lock_path\":null", .changed = "\"lock_path\":\"/invented/lock\"" },
        .{ .original = "\"provenance_path\":null", .changed = "\"provenance_path\":\"/invented/receipt\"" },
        .{ .original = "\"operation\":\"inspect\"", .changed = "\"operation\":\"create\"" },
    }) |mutation| {
        const bytes = try std.mem.replaceOwned(u8, fixture.allocator, report_bytes, mutation.original, mutation.changed);
        defer fixture.allocator.free(bytes);
        if (std.mem.eql(u8, bytes, report_bytes)) return error.UnappliedInspectionMutation;
        var changed = try std.json.parseFromSlice(std.json.Value, fixture.allocator, bytes, .{});
        defer changed.deinit();
        try std.testing.expectError(error.InvalidDiagnosticInspection, oracle.validateDiagnosticInspection(changed.value, evidence, root));
    }
    for ([_]struct { original: []const u8, changed: []const u8 }{
        .{ .original = "\"native_install\":null", .changed = "\"native_install\":{}" },
        .{ .original = "\"native_completion\":null", .changed = "\"native_completion\":{}" },
        .{ .original = "\"diagnostic_only\":true", .changed = "\"diagnostic_only\":false" },
    }) |mutation| {
        const bytes = try std.mem.replaceOwned(u8, fixture.allocator, evidence_bytes, mutation.original, mutation.changed);
        defer fixture.allocator.free(bytes);
        if (std.mem.eql(u8, bytes, evidence_bytes)) return error.UnappliedInspectionMutation;
        var changed = try std.json.parseFromSlice(std.json.Value, fixture.allocator, bytes, .{});
        defer changed.deinit();
        try std.testing.expectError(error.InvalidDiagnosticInspection, oracle.validateDiagnosticInspection(inspected.report.value, changed.value, root));
    }
    const encoded_root = try std.json.Stringify.valueAlloc(fixture.allocator, root, .{});
    defer fixture.allocator.free(encoded_root);
    const root_field = try std.fmt.allocPrint(fixture.allocator, "\"root\":{s}", .{encoded_root});
    defer fixture.allocator.free(root_field);
    const changed_bytes = try std.mem.replaceOwned(u8, fixture.allocator, evidence_bytes, root_field, "\"root\":\"/invented/root\"");
    defer fixture.allocator.free(changed_bytes);
    if (std.mem.eql(u8, changed_bytes, evidence_bytes)) return error.UnappliedInspectionMutation;
    var changed_root = try std.json.parseFromSlice(std.json.Value, fixture.allocator, changed_bytes, .{});
    defer changed_root.deinit();
    try std.testing.expectError(error.InvalidDiagnosticInspection, oracle.validateDiagnosticInspection(inspected.report.value, changed_root.value, root));

    var recovered = try workflow(fixture, driver, root, arch, "family/recover", .{
        .family_execution = try familyRequest(fixture, root, arch, "recover"),
        .capture_evidence = true,
    });
    defer recovered.deinit();
    try expectFamily(recovered.report.value, "recover", true);
    try std.testing.expectEqual(.null, try field(recovered.evidence.?.value, "native_completion"));
    const after_recover = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(after_recover);
    try std.testing.expectEqualSlices(u8, before, after_recover);

    var verification = try familyRequest(fixture, root, arch, "create");
    verification.sources = &.{try fixture.absolute("family/missing.sources")};
    verification.keyrings = &.{try fixture.absolute("family/missing.keyring")};
    verification.package = "alpha";
    verification.lock_input = try fixture.absolute("family/missing.lock");
    var uncompleted = try workflow(fixture, driver, root, arch, "family/verification", .{
        .family_verification = verification,
    });
    defer uncompleted.deinit();
    try std.testing.expect(!(try field(uncompleted.report.value, "verified")).bool);
    try same(try string(uncompleted.report.value, "error"), "FileNotFound");
    const request = try parse(fixture, "family/verification/workflow.request.json", 64 * 1024);
    defer request.deinit();
    const check = try field(request.value, "family_verification");
    const retained = try field(check, "request");
    for ([_][]const u8{ "schema", "operation", "root", "architecture", "cache", "state", "package", "lock_input" }, [_][]const u8{ verification.schema, verification.operation, verification.root, verification.architecture, verification.cache, verification.state, verification.package.?, verification.lock_input.? }) |name, expected|
        try same(try string(retained, name), expected);
    try std.testing.expectEqual(@as(i64, 2), (try field(retained, "version")).integer);
    try same((try field(retained, "sources")).array.items[0].string, verification.sources[0]);
    try same((try field(retained, "keyrings")).array.items[0].string, verification.keyrings[0]);
    try std.testing.expect((try field(check, "expect_failure")).bool);
    for ([_][]const u8{ "completion_crash", "owned_verification", "native_evidence_output", "family_execution" }) |name|
        try std.testing.expectEqual(.null, try field(request.value, name));
    try support.absent(fixture, "family/verification/native-evidence.json");

    const execution = try parse(fixture, "family/recover/workflow.request.json", 64 * 1024);
    defer execution.deinit();
    try same(try string(try field(execution.value, "family_execution"), "operation"), "recover");
    try same(try string(try field(execution.value, "family_execution"), "root"), root);
    try std.testing.expectEqual(.null, try field(execution.value, "family_verification"));
    try std.testing.expectEqual(.null, try field(execution.value, "completion_crash"));
    try same(try string(execution.value, "native_evidence_output"), try fixture.absolute("family/recover/native-evidence.json"));
    try std.testing.expect(!std.mem.eql(u8, try string(execution.value, "report"), try string(execution.value, "native_evidence_output")));
    std.debug.print("family: real inspect/recover/verification transport and produced-evidence refusal passed\n", .{});
}

fn planning(fixture: *foundation.Fixture, driver: []const u8) !void {
    const root = try fixture.makeRoot("planning/native", "amd64");
    defer fixture.allocator.free(root);
    try fixture.write("planning/native/var/lib/dpkg/status", "Package: alpha\nVersion: 0\nArchitecture: amd64\nStatus: install ok installed\n\n" ++
        "Package: shared\nVersion: 1\nArchitecture: amd64\nStatus: install ok installed\n", 0o644);
    const before = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(before);
    for ([_][]const u8{ "InRelease", "Packages", "keyring.gpg" }, [_][]const u8{
        "planning/repo/dists/stable/InRelease",
        "planning/repo/dists/stable/main/binary-amd64/Packages",
        "planning/keyring.gpg",
    }) |asset, path| {
        const bytes = try repositoryFixture(fixture, asset);
        defer fixture.allocator.free(bytes);
        try fixture.write(path, bytes, 0o644);
    }
    const repo = try fixture.absolute("planning/repo");
    const keyring = try fixture.absolute("planning/keyring.gpg");
    const source = try fixture.absolute("planning/sources.list");
    const source_text = try std.fmt.allocPrint(fixture.allocator, "deb [arch=amd64 signed-by={s}] file://{s} stable main\n", .{ keyring, repo });
    try fixture.write("planning/sources.list", source_text, 0o644);
    for ([_]?[]const u8{ "alpha:amd64=1", null }, [_][]const u8{ "selected", "all" }) |package, label| {
        const lock_relative = try std.fmt.allocPrint(fixture.allocator, "planning/{s}.lock.json", .{label});
        const lock = try fixture.absolute(lock_relative);
        var request = try familyRequest(fixture, root, "amd64", "resolve_lock");
        request.sources = try fixture.allocator.dupe([]const u8, &.{source});
        request.keyrings = try fixture.allocator.dupe([]const u8, &.{keyring});
        request.package = package;
        request.lock_output = lock;
        const destination = try std.fmt.allocPrint(fixture.allocator, "planning/{s}", .{label});
        var planned = try workflow(fixture, driver, root, "amd64", destination, .{
            .family_execution = request,
            .family_update_planning = true,
            .capture_evidence = true,
        });
        defer planned.deinit();
        try expectFamily(planned.report.value, "resolve_lock", true);
        try same(try string(planned.report.value, "lock_path"), lock);
        try std.testing.expect(!(try field(planned.report.value, "changed")).bool);
        try std.testing.expectEqual(.null, try field(planned.report.value, "provenance_path"));
        for ([_][]const u8{ "native_install", "native_completion" }) |key|
            try std.testing.expectEqual(.null, try field(planned.evidence.?.value, key));
        var locked = try parse(fixture, lock_relative, 1024 * 1024);
        defer locked.deinit();
        try std.testing.expect((try field(locked.value, "packages")).array.items.len >= 2);
        const sent = try parse(fixture, try support.path(fixture.allocator, destination, "workflow.request.json"), 64 * 1024);
        defer sent.deinit();
        try std.testing.expect((try field(sent.value, "family_update_planning")).bool);
        const retained = try field(sent.value, "family_execution");
        try same(try string(retained, "operation"), "resolve_lock");
        if (package) |name| try same(try string(retained, "package"), name) else try std.testing.expectEqual(.null, try field(retained, "package"));
        try std.testing.expectEqual(.null, try field(sent.value, "completion_crash"));
        try std.testing.expectEqual(.null, try field(sent.value, "family_verification"));
    }
    var ordinary = try familyRequest(fixture, root, "amd64", "resolve_lock");
    ordinary.sources = &.{source};
    ordinary.keyrings = &.{keyring};
    ordinary.lock_output = try fixture.absolute("planning/ordinary.lock.json");
    var refused = try workflow(fixture, driver, root, "amd64", "planning/ordinary", .{ .family_execution = ordinary });
    defer refused.deinit();
    try expectFamily(refused.report.value, "resolve_lock", false);
    try same(try string(try field(refused.report.value, "diagnostic"), "id"), "invalid_request");
    try support.absent(fixture, "planning/ordinary.lock.json");
    const core_lock = try fixture.absolute("planning/core.lock.json");
    var core_plan = try workflow(fixture, driver, root, "amd64", "planning/core-plan", .{
        .ordinary_plan = true,
        .sources = &.{source},
        .keyrings = &.{keyring},
        .lock_output = core_lock,
        .capture_evidence = true,
    });
    defer core_plan.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(core_plan.report.value, "exit_status")).integer);
    try std.testing.expectEqual(.null, try field(core_plan.evidence.?.value, "native_completion"));
    try std.testing.expectEqual(.null, try field(core_plan.evidence.?.value, "native_install"));
    var core_result = try parse(fixture, "planning/core-plan/workflow.request.json", 64 * 1024);
    defer core_result.deinit();
    try same(try string(core_result.value, "native_evidence_output"), try fixture.absolute("planning/core-plan/native-evidence.json"));
    try std.testing.expect(!std.mem.eql(u8, try string(core_result.value, "report"), try string(core_result.value, "native_evidence_output")));
    var core_lock_document = try parse(fixture, "planning/core.lock.json", 1024 * 1024);
    core_lock_document.deinit();
    const after = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    std.debug.print("family: selected and upgrade-all update planning used real signed repository and bound locks\n", .{});
}

fn archive(fixture: *foundation.Fixture, arch: []const u8, name: []const u8, version: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(fixture.allocator, "executed/repository/pool/main/{s}_{s}_{s}.deb", .{ name, version, arch });
    defer fixture.allocator.free(path);
    return fixture.absolute(path);
}

fn signedRequest(
    fixture: *foundation.Fixture,
    root: []const u8,
    arch: []const u8,
    operation: []const u8,
    package: ?[]const u8,
    source: []const u8,
    keyring: []const u8,
    lock: []const u8,
) !FamilyRequest {
    var request = try familyRequest(fixture, root, arch, operation);
    request.sources = try fixture.allocator.dupe([]const u8, &.{source});
    request.keyrings = try fixture.allocator.dupe([]const u8, &.{keyring});
    request.cache = try fixture.absolute("executed/cache");
    request.state = try fixture.absolute("executed/state");
    request.package = package;
    if (std.mem.eql(u8, operation, "resolve_lock")) request.lock_output = lock else request.lock_input = lock;
    return request;
}

fn completed(
    fixture: *foundation.Fixture,
    root: []const u8,
    result: Response,
    operation: []const u8,
    lock: []const u8,
    install_expected: bool,
) !std.json.Value {
    try expectFamily(result.report.value, operation, true);
    try std.testing.expect((try field(result.report.value, "changed")).bool);
    try same(try string(result.report.value, "exit_status"), "success");
    try same(try string(result.report.value, "lock_path"), lock);
    const receipt_relative = try support.path(fixture.allocator, root[fixture.path.len + 1 ..], debz.native_provenance.document_path);
    const provenance = try fixture.absolute(receipt_relative);
    try same(try string(result.report.value, "provenance_path"), provenance);
    var receipt = try parse(fixture, receipt_relative, 16 * 1024 * 1024);
    defer receipt.deinit();
    const completion_relative = try support.path(fixture.allocator, root[fixture.path.len + 1 ..], debz.root_operation_completion.document_path);
    var document = try parse(fixture, completion_relative, 64 * 1024);
    defer document.deinit();
    const lock_relative = lock[fixture.path.len + 1 ..];
    var locked = try parse(fixture, lock_relative, 1024 * 1024);
    defer locked.deinit();
    const evidence = result.evidence.?.value;
    const returned = try field(evidence, "native_completion");
    if (returned != .object) return error.MissingExecutedCompletion;
    try same(try string(returned, "outcome"), "succeeded");
    try same(try string(returned, "settlement"), "cleared");
    try same(try string(returned, "operation"), try string(document.value, "operation"));
    try same(try string(receipt.value, "outcome"), "succeeded");
    try same(try string(document.value, "surface"), "package_transaction");
    for ([_][]const u8{
        "attempt_id",                "lock_sha256",              "caller_request_sha256", "caller_policy_sha256",
        "transaction_digest_sha256", "completion_digest_sha256", "program_sha256",
    }, [_][]const u8{
        try string(receipt.value, "attempt_id"),
        try string(locked.value, "digest_sha256"),
        try string(document.value, "request_sha256"),
        try string(document.value, "policy_sha256"),
        try string(receipt.value, "digest_sha256"),
        try string(document.value, "digest_sha256"),
        try string(receipt.value, "program_sha256"),
    }) |name, expected| {
        const digest = try hexEvidence(try field(returned, name));
        try same(&digest, expected);
    }
    try std.testing.expectEqual(install_expected, (try field(evidence, "native_install")) != .null);
    if (install_expected) {
        const install = try field(evidence, "native_install");
        const digest = try hexEvidence(try field(install, "lock_sha256"));
        try same(&digest, try string(locked.value, "digest_sha256"));
        const count = try field(install, "package_count");
        try std.testing.expectEqual(@as(i64, @intCast((try field(locked.value, "packages")).array.items.len)), count.integer);
    }
    try support.absent(fixture, "executed/state/transaction-result.json");
    const root_relative = root[fixture.path.len + 1 ..];
    for ([_][]const u8{ "var/lib/debz/root-operation-v1.json", "var/lib/debz/native-execution-intent-v1.json" }) |name|
        try support.absent(fixture, try support.path(fixture.allocator, root_relative, name));
    return returned;
}

fn assertExecutionWire(fixture: *foundation.Fixture, destination: []const u8, request: FamilyRequest) !void {
    const path = try support.path(fixture.allocator, destination, "workflow.request.json");
    var sent = try parse(fixture, path, 64 * 1024);
    defer sent.deinit();
    const original = try field(sent.value, "family_execution");
    try same(try string(original, "operation"), request.operation);
    try same(try string(original, "root"), request.root);
    try same(try string(original, "architecture"), request.architecture);
    try same((try field(original, "sources")).array.items[0].string, request.sources[0]);
    try same((try field(original, "keyrings")).array.items[0].string, request.keyrings[0]);
    try same(try string(original, "lock_input"), request.lock_input.?);
    try std.testing.expectEqual(.null, try field(sent.value, "family_verification"));
    try std.testing.expectEqual(.null, try field(sent.value, "completion_crash"));
    const evidence = try string(sent.value, "native_evidence_output");
    try same(evidence, try fixture.absolute(try support.path(fixture.allocator, destination, "native-evidence.json")));
    try std.testing.expect(!std.mem.eql(u8, evidence, try string(sent.value, "report")));
}

fn hexEvidence(value: std.json.Value) ![64]u8 {
    var bytes: [32]u8 = undefined;
    if (value == .string and value.string.len == bytes.len) {
        @memcpy(&bytes, value.string);
    } else if (value == .array and value.array.items.len == bytes.len) {
        for (value.array.items, &bytes) |item, *byte| {
            if (item != .integer or item.integer < 0 or item.integer > 255)
                return error.InvalidCompletionDigest;
            byte.* = @intCast(item.integer);
        }
    } else return error.InvalidCompletionDigest;
    return std.fmt.bytesToHex(bytes, .lower);
}

fn refusedVerification(
    fixture: *foundation.Fixture,
    driver: []const u8,
    request: FamilyRequest,
    destination: []const u8,
    completion: ?std.json.Value,
    expected_error: ?[]const u8,
) !void {
    const root_before = try projected.rootInventory(fixture, request.root, true);
    const root_relative = request.root[fixture.path.len + 1 ..];
    const before = foundation.capture(fixture.allocator, fixture.io, request.root) catch |err| switch (err) {
        error.InvalidDeb822 => null,
        else => return err,
    };
    const status_path = try support.path(fixture.allocator, root_relative, "var/lib/dpkg/status");
    const receipt_path = try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path);
    const completion_path = try support.path(fixture.allocator, root_relative, debz.root_operation_completion.document_path);
    const status = try support.read(fixture, status_path, 1024 * 1024);
    const receipt = try support.read(fixture, receipt_path, 16 * 1024 * 1024);
    const document = try support.read(fixture, completion_path, 64 * 1024);
    var refused = try workflow(fixture, driver, request.root, request.architecture, destination, .{
        .family_verification = request,
        .verification_completion = completion,
    });
    defer refused.deinit();
    try std.testing.expect(!(try field(refused.report.value, "verified")).bool);
    if (expected_error) |name| try same(try string(refused.report.value, "error"), name);
    try support.absent(fixture, try support.path(fixture.allocator, destination, "native-evidence.json"));
    try std.testing.expectEqualSlices(u8, status, try support.read(fixture, status_path, 1024 * 1024));
    try std.testing.expectEqualSlices(u8, receipt, try support.read(fixture, receipt_path, 16 * 1024 * 1024));
    try std.testing.expectEqualSlices(u8, document, try support.read(fixture, completion_path, 64 * 1024));
    if (before) |snapshot| try std.testing.expectEqualSlices(u8, snapshot, try foundation.capture(fixture.allocator, fixture.io, request.root));
    try std.testing.expectEqualSlices(u8, root_before, try projected.rootInventory(fixture, request.root, true));
}

fn assertFamilySummary(
    fixture: *foundation.Fixture,
    driver: []const u8,
    request: FamilyRequest,
    completion: std.json.Value,
    baseline: []const u8,
    destination: []const u8,
) !void {
    const before = try projected.rootInventory(fixture, request.root, true);
    var verified = try workflow(fixture, driver, request.root, request.architecture, destination, .{
        .family_verification = request,
        .verification_expect_failure = false,
        .verification_completion = completion,
    });
    defer verified.deinit();
    try std.testing.expectEqualSlices(u8, baseline, try support.read(fixture, try support.path(fixture.allocator, destination, "workflow.report.json"), 64 * 1024));
    try std.testing.expectEqualSlices(u8, before, try projected.rootInventory(fixture, request.root, true));
}

fn verificationRefusals(
    fixture: *foundation.Fixture,
    driver: []const u8,
    request: FamilyRequest,
    completion: std.json.Value,
    summary: []const u8,
    prefix: []const u8,
) !void {
    for ([_][]const u8{
        "attempt_id",                "lock_sha256",              "caller_request_sha256", "caller_policy_sha256",
        "transaction_digest_sha256", "completion_digest_sha256", "program_sha256",
    }) |name| {
        const encoded = try std.json.Stringify.valueAlloc(fixture.allocator, completion, .{});
        var altered = try std.json.parseFromSlice(std.json.Value, fixture.allocator, encoded, .{ .allocate = .alloc_always });
        defer altered.deinit();
        const digest = altered.value.object.getPtr(name) orelse return error.MissingExecutedCompletion;
        if (digest.* == .array) {
            digest.array.items[0].integer ^= 1;
        } else if (digest.* == .string) {
            const bytes = try fixture.allocator.dupe(u8, digest.string);
            bytes[0] ^= 1;
            digest.* = .{ .string = bytes };
        } else return error.InvalidCompletionDigest;
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/refuse-result-{s}", .{ prefix, name });
        try refusedVerification(fixture, driver, request, destination, altered.value, "NativeFamilyCompletionMismatch");
        try assertFamilySummary(fixture, driver, request, completion, summary, try std.fmt.allocPrint(fixture.allocator, "{s}-verified-again", .{destination}));
    }
    for ([_]struct { name: []const u8, replacement: []const u8, expected: []const u8 }{
        .{ .name = "outcome", .replacement = "failed", .expected = "InvalidNativeFamilyCompletion" },
        .{ .name = "settlement", .replacement = "retained", .expected = "InvalidNativeFamilyCompletion" },
        .{ .name = "operation", .replacement = "upgrade", .expected = "NativeFamilyCompletionMismatch" },
    }) |change| {
        const encoded = try std.json.Stringify.valueAlloc(fixture.allocator, completion, .{});
        var altered = try std.json.parseFromSlice(std.json.Value, fixture.allocator, encoded, .{ .allocate = .alloc_always });
        defer altered.deinit();
        const member = altered.value.object.getPtr(change.name) orelse return error.MissingExecutedCompletion;
        member.* = .{ .string = change.replacement };
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/refuse-result-{s}", .{ prefix, change.name });
        try refusedVerification(fixture, driver, request, destination, altered.value, change.expected);
        try assertFamilySummary(fixture, driver, request, completion, summary, try std.fmt.allocPrint(fixture.allocator, "{s}-verified-again", .{destination}));
    }
    for ([_]struct { label: []const u8, name: []const u8 }{
        .{ .label = "package", .name = "another-package" },
        .{ .label = "operation", .name = "update" },
        .{ .label = "conffile", .name = "use_package_version" },
    }) |change| {
        var wrong = request;
        if (std.mem.eql(u8, change.label, "package")) wrong.package = change.name;
        if (std.mem.eql(u8, change.label, "operation")) wrong.operation = change.name;
        if (std.mem.eql(u8, change.label, "conffile")) wrong.conffile = change.name;
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/refuse-request-{s}", .{ prefix, change.label });
        try refusedVerification(fixture, driver, wrong, destination, null, "NativeFamilyRequestMismatch");
        try assertFamilySummary(fixture, driver, request, completion, summary, try std.fmt.allocPrint(fixture.allocator, "{s}-verified-again", .{destination}));
    }
    var wrong_policy = request;
    wrong_policy.recommends = true;
    try refusedVerification(fixture, driver, wrong_policy, try support.path(fixture.allocator, prefix, "refuse-request-recommends"), null, "NativeFamilyRequestMismatch");
    try assertFamilySummary(fixture, driver, request, completion, summary, try support.path(fixture.allocator, prefix, "refuse-request-recommends-verified-again"));
    var downgrade = request;
    downgrade.allow_downgrade = true;
    try refusedVerification(fixture, driver, downgrade, try support.path(fixture.allocator, prefix, "refuse-request-allow-downgrade"), null, "NativeFamilyRequestMismatch");
    try assertFamilySummary(fixture, driver, request, completion, summary, try support.path(fixture.allocator, prefix, "refuse-request-allow-downgrade-verified-again"));
    var foreign = request;
    foreign.foreign_architectures = &.{if (std.mem.eql(u8, request.architecture, "arm64")) "amd64" else "arm64"};
    try refusedVerification(fixture, driver, foreign, try support.path(fixture.allocator, prefix, "refuse-request-foreign-architectures"), null, "NativeFamilyRequestMismatch");
    try assertFamilySummary(fixture, driver, request, completion, summary, try support.path(fixture.allocator, prefix, "refuse-request-foreign-architectures-verified-again"));
    for ([_]struct { label: []const u8, relative: []const u8 }{
        .{ .label = "receipt", .relative = debz.native_provenance.document_path },
        .{ .label = "completion", .relative = debz.root_operation_completion.document_path },
        .{ .label = "database", .relative = "var/lib/dpkg/status" },
    }) |damaged| {
        const path = try support.path(fixture.allocator, request.root[fixture.path.len + 1 ..], damaged.relative);
        const original = try support.read(fixture, path, 16 * 1024 * 1024);
        try fixture.write(path, "invalid completed evidence\n", 0o644);
        defer fixture.write(path, original, 0o644) catch {};
        try refusedVerification(fixture, driver, request, try std.fmt.allocPrint(fixture.allocator, "{s}/refuse-damaged-{s}", .{ prefix, damaged.label }), null, null);
        try fixture.write(path, original, 0o644);
        try assertFamilySummary(fixture, driver, request, completion, summary, try std.fmt.allocPrint(fixture.allocator, "{s}/refuse-damaged-{s}-verified-again", .{ prefix, damaged.label }));
    }
    const original_lock = try support.read(fixture, request.lock_input.?[fixture.path.len + 1 ..], 1024 * 1024);
    try fixture.write(request.lock_input.?[fixture.path.len + 1 ..], "invalid completed evidence\n", 0o644);
    try refusedVerification(fixture, driver, request, try support.path(fixture.allocator, prefix, "refuse-damaged-lock"), null, null);
    try fixture.write(request.lock_input.?[fixture.path.len + 1 ..], original_lock, 0o644);
    try assertFamilySummary(fixture, driver, request, completion, summary, try support.path(fixture.allocator, prefix, "refuse-damaged-lock-verified-again"));
    const operation = try support.path(fixture.allocator, request.root[fixture.path.len + 1 ..], "var/lib/debz/root-operation-v1.json");
    try fixture.write(operation, "unsettled operation\n", 0o644);
    try refusedVerification(fixture, driver, request, try support.path(fixture.allocator, prefix, "refuse-unsettled"), null, null);
    try fixture.dir.deleteFile(fixture.io, operation);
    try assertFamilySummary(fixture, driver, request, completion, summary, try support.path(fixture.allocator, prefix, "refuse-unsettled-verified-again"));
    var verified = try workflow(fixture, driver, request.root, request.architecture, try support.path(fixture.allocator, prefix, "verified-after-refusals"), .{
        .family_verification = request,
        .verification_expect_failure = false,
        .verification_completion = completion,
    });
    defer verified.deinit();
    try same(try string(verified.report.value, "final_verification_status"), "exact_match");
}

fn seededScenario(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    name: []const u8,
    upgrade: bool,
) !support.Scenario {
    var scenario = try support.Scenario.init(fixture, name, driver, reference, arch, true);
    errdefer scenario.deinit();
    try scenario.seed(try archive(fixture, arch, "native-helper-target", "1.0-1"));
    try scenario.seed(try archive(fixture, arch, "essential-core", "1.0-1"));
    if (upgrade) try scenario.seed(try archive(fixture, arch, "fixture-upgrade", "1.0-1"));
    var helper_file = try std.Io.Dir.cwd().openFile(fixture.io, helper, .{});
    defer helper_file.close(fixture.io);
    var reader = helper_file.reader(fixture.io, &.{});
    const bytes = try reader.interface.allocRemaining(fixture.allocator, .limited(32 * 1024 * 1024));
    const target = try std.fmt.allocPrint(fixture.allocator, "{s}/usr/bin/dpkg-trigger", .{scenario.native_root[fixture.path.len + 1 ..]});
    try fixture.write(target, bytes, 0o755);
    return scenario;
}

fn inspectInstalledFamily(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    arch: []const u8,
    label: []const u8,
    package_name: []const u8,
    installed: bool,
    missing_helper: bool,
) !void {
    const before = try projected.rootInventory(fixture, root, true);
    var request = try familyRequest(fixture, root, arch, "inspect");
    request.cache = try fixture.absolute(try std.fmt.allocPrint(fixture.allocator, "{s}-inspect-cache", .{label}));
    request.state = try fixture.absolute(try std.fmt.allocPrint(fixture.allocator, "{s}-inspect-state", .{label}));
    var inspected = try workflow(fixture, driver, root, arch, label, .{
        .family_execution = request,
        .capture_evidence = true,
    });
    defer inspected.deinit();
    try expectFamily(inspected.report.value, "inspect", true);
    const observed = try oracle.validateDiagnosticInspection(inspected.report.value, inspected.evidence.?.value, root);
    try std.testing.expect(!(try field(observed, "native_active_evidence")).bool);
    try std.testing.expect((try field(observed, "status_database_present")).bool);
    try std.testing.expectEqual(.null, try field(observed, "observed_operation"));
    try std.testing.expectEqual(.null, try field(inspected.evidence.?.value, "native_completion"));
    var found = false;
    var found_helper = false;
    for ((try field(observed, "packages")).array.items) |package| {
        if (std.mem.eql(u8, try string(package, "name"), package_name)) {
            found = true;
            const status = try string(try field(package, "status"), "current");
            try std.testing.expectEqual(installed, std.mem.eql(u8, status, "installed"));
        }
        if (std.mem.eql(u8, try string(package, "name"), "native-helper-target")) found_helper = true;
        if (missing_helper) try same(try string(package, "name"), "essential-core");
    }
    try std.testing.expect(found);
    if (missing_helper or std.mem.eql(u8, label, "executed/inspect-initial")) {
        try std.testing.expectEqual(@as(usize, if (missing_helper) 1 else 2), (try field(observed, "packages")).array.items.len);
        try std.testing.expectEqual(!missing_helper, found_helper);
    }
    try std.testing.expectEqualSlices(u8, before, try projected.rootInventory(fixture, root, true));
    try support.absent(fixture, request.cache[fixture.path.len + 1 ..]);
    try support.absent(fixture, request.state[fixture.path.len + 1 ..]);
}

fn archiveExecution(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    python: []const u8,
) !void {
    try fixture.directory("executed");
    const generator = try std.fs.path.join(fixture.allocator, &.{ options.repository, "tools/generate-integration-repository.py" });
    const repository = try fixture.absolute("executed/repository");
    try fixture.run(&.{
        python, generator, "--output", repository, "--suite", "debian-stable", "--architecture", arch,
    }, "executed/generate.log", 120);
    const keyring = try fixture.absolute("executed/repository/fixture-keyring.gpg");
    const source = try fixture.absolute("executed/workflow.sources");
    const source_text = try std.fmt.allocPrint(fixture.allocator, "Types: deb\nURIs: file://{s}\nSuites: debian-stable\nComponents: main\nArchitectures: {s}\nSigned-By: {s}\n", .{ repository, arch, keyring });
    try fixture.write("executed/workflow.sources", source_text, 0o644);
    var scenario = try seededScenario(fixture, driver, helper, reference, arch, "executed", false);
    defer scenario.deinit();
    try inspectInstalledFamily(fixture, driver, scenario.native_root, arch, "executed/inspect-initial", "essential-core", true, false);
    const lock = try fixture.absolute("executed/lock.json");
    var first_completion: ?std.json.Parsed(std.json.Value) = null;
    defer if (first_completion) |*value| value.deinit();
    for ([_]struct {
        label: []const u8,
        operation: []const u8,
        package: []const u8,
        archives: []const []const u8,
        install_evidence: bool,
    }{
        .{ .label = "create", .operation = "create", .package = "scenario-main", .archives = &.{ "base-dep", "scenario-main" }, .install_evidence = true },
        .{ .label = "customize", .operation = "customize", .package = "conffile-pkg", .archives = &.{"conffile-pkg"}, .install_evidence = true },
    }) |case| {
        const planned = try signedRequest(fixture, scenario.native_root, arch, "resolve_lock", case.package, source, keyring, lock);
        const plan_name = try std.fmt.allocPrint(fixture.allocator, "executed/{s}-plan", .{case.label});
        var plan = try workflow(fixture, driver, scenario.native_root, arch, plan_name, .{
            .family_execution = planned,
            .capture_evidence = true,
        });
        defer plan.deinit();
        try expectFamily(plan.report.value, "resolve_lock", true);
        try std.testing.expect(!(try field(plan.report.value, "changed")).bool);
        const request = try signedRequest(fixture, scenario.native_root, arch, case.operation, case.package, source, keyring, lock);
        const execution_name = try std.fmt.allocPrint(fixture.allocator, "executed/{s}-execute", .{case.label});
        var executed = try workflow(fixture, driver, scenario.native_root, arch, execution_name, .{
            .family_execution = request,
            .capture_evidence = true,
        });
        defer executed.deinit();
        const returned = try completed(fixture, scenario.native_root, executed, case.operation, lock, case.install_evidence);
        try assertExecutionWire(fixture, execution_name, request);
        const before_verification = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
        var verified = try workflow(fixture, driver, scenario.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify", .{case.label}), .{
            .family_verification = request,
            .verification_expect_failure = false,
        });
        defer verified.deinit();
        try same(try string(verified.report.value, "operation"), "install");
        var with_result = try workflow(fixture, driver, scenario.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify-result", .{case.label}), .{
            .family_verification = request,
            .verification_expect_failure = false,
            .verification_completion = returned,
        });
        defer with_result.deinit();
        const original_summary = try support.read(fixture, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify/workflow.report.json", .{case.label}), 64 * 1024);
        const returned_summary = try support.read(fixture, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify-result/workflow.report.json", .{case.label}), 64 * 1024);
        try std.testing.expectEqualSlices(u8, original_summary, returned_summary);
        try same(try string(with_result.report.value, "transaction_digest_sha256"), try string(verified.report.value, "transaction_digest_sha256"));
        try same(try string(with_result.report.value, "completion_digest_sha256"), try string(verified.report.value, "completion_digest_sha256"));
        if (std.mem.eql(u8, case.operation, "create")) {
            var equivalent = request;
            equivalent.operation = "customize";
            var relabeled = try workflow(fixture, driver, scenario.native_root, arch, "executed/create-as-customize-verification", .{
                .family_verification = equivalent,
                .verification_expect_failure = false,
            });
            defer relabeled.deinit();
            const equivalent_summary = try support.read(fixture, "executed/create-as-customize-verification/workflow.report.json", 64 * 1024);
            try std.testing.expectEqualSlices(u8, original_summary, equivalent_summary);
            try verificationRefusals(fixture, driver, request, returned, original_summary, "executed");
            first_completion = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try std.json.Stringify.valueAlloc(fixture.allocator, returned, .{}), .{ .allocate = .alloc_always });
        } else {
            try refusedVerification(fixture, driver, request, "executed/refuse-previous-attempt", first_completion.?.value, "NativeFamilyCompletionMismatch");
        }
        var held = try parse(fixture, "executed/lock.json", 1024 * 1024);
        defer held.deinit();
        try same(try string(verified.report.value, "lock_sha256"), try string(held.value, "digest_sha256"));
        const after_verification = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
        try std.testing.expectEqualSlices(u8, before_verification, after_verification);
        try support.absent(fixture, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify/native-evidence.json", .{case.label}));
        var list: std.ArrayList([]const u8) = .empty;
        for (case.archives) |name| try list.append(fixture.allocator, try archive(fixture, arch, name, "1.0-1"));
        const reference_name = try std.fmt.allocPrint(fixture.allocator, "executed/{s}-reference", .{case.label});
        try fixture.directory(reference_name);
        if (try support.reference(fixture, reference, scenario.reference_root, .{ .operation = "install", .archives = list.items, .triggers = true }, reference_name) != 0)
            return error.ReferenceFamilyInstallFailed;
        const comparison = try std.fmt.allocPrint(fixture.allocator, "executed/{s}-comparison", .{case.label});
        try fixture.directory(comparison);
        try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
        if (std.mem.eql(u8, case.operation, "create")) {
            const lock_file = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], "var/lib/debz/root-operation.lock");
            var holder = try fixture.dir.openFile(fixture.io, lock_file, .{});
            defer holder.close(fixture.io);
            if (linux.errno(linux.flock(holder.handle, 2 | 4)) != .SUCCESS) return error.FamilyInspectionLockSetupFailed;
            defer _ = linux.flock(holder.handle, 8);
            try inspectInstalledFamily(fixture, driver, scenario.native_root, arch, "executed/inspect-while-root-lock-held", "scenario-main", true, false);
        }
        std.debug.print("family {s}: signed archives, native completion, verified receipt and dpkg state passed\n", .{case.label});
    }
    const failed_plan_request = try signedRequest(fixture, scenario.native_root, arch, "resolve_lock", "fail-script", source, keyring, lock);
    var failed_plan = try workflow(fixture, driver, scenario.native_root, arch, "executed/same-root-failure-plan", .{
        .family_execution = failed_plan_request,
        .capture_evidence = true,
    });
    defer failed_plan.deinit();
    try expectFamily(failed_plan.report.value, "resolve_lock", true);
    const failed_request = try signedRequest(fixture, scenario.native_root, arch, "customize", "fail-script", source, keyring, lock);
    var failed = try workflow(fixture, driver, scenario.native_root, arch, "executed/same-root-failure", .{
        .family_execution = failed_request,
        .capture_evidence = true,
    });
    defer failed.deinit();
    try expectFamily(failed.report.value, "customize", false);
    try same(try string(failed.report.value, "exit_status"), "transaction");
    try std.testing.expect((try field(failed.report.value, "changed")).bool);
    try std.testing.expect((try field(try field(failed.report.value, "diagnostic"), "recoverable")).bool);
    const same_root_receipt = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], debz.native_provenance.document_path);
    var failed_receipt = try parse(fixture, same_root_receipt, 16 * 1024 * 1024);
    defer failed_receipt.deinit();
    try same(try string(failed_receipt.value, "outcome"), "failed");
    const failed_returned = try field(failed.evidence.?.value, "native_completion");
    try same(try string(failed_returned, "outcome"), "failed");
    try same(try string(failed_returned, "settlement"), "cleared");
    const receipt_before_recovery = try support.read(fixture, same_root_receipt, 16 * 1024 * 1024);
    const reference_failure = "executed/same-root-failure-reference";
    try fixture.directory(reference_failure);
    if (try support.reference(fixture, reference, scenario.reference_root, .{
        .operation = "install",
        .archives = &.{try archive(fixture, arch, "fail-script", "1.0-1")},
        .triggers = true,
    }, reference_failure) != 1) return error.ReferenceSameRootFailureMissing;
    try fixture.directory("executed/same-root-failure-comparison");
    try support.compare(fixture, scenario.reference_root, scenario.native_root, "executed/same-root-failure-comparison", true);
    const before_recovery = try projected.rootInventory(fixture, scenario.native_root, false);
    var clean = try workflow(fixture, driver, scenario.native_root, arch, "executed/same-root-clean-recovery", .{
        .family_execution = try familyRequest(fixture, scenario.native_root, arch, "recover"),
        .capture_evidence = true,
    });
    defer clean.deinit();
    try expectFamily(clean.report.value, "recover", true);
    try std.testing.expect(!(try field(clean.report.value, "changed")).bool);
    try std.testing.expectEqual(.null, try field(clean.report.value, "lock_path"));
    try std.testing.expectEqual(.null, try field(clean.report.value, "provenance_path"));
    try std.testing.expectEqual(.null, try field(clean.evidence.?.value, "native_completion"));
    try std.testing.expectEqualSlices(u8, before_recovery, try projected.rootInventory(fixture, scenario.native_root, false));
    try std.testing.expectEqualSlices(u8, receipt_before_recovery, try support.read(fixture, same_root_receipt, 16 * 1024 * 1024));
    try support.compare(fixture, scenario.reference_root, scenario.native_root, "executed/same-root-failure-comparison", true);
    try inspectInstalledFamily(fixture, driver, scenario.native_root, arch, "executed/inspect-failed-same-root", "fail-script", false, false);
    for ([_]bool{ true, false }) |selected| {
        const label: []const u8 = if (selected) "update-selected" else "update-all";
        var update = try seededScenario(fixture, driver, helper, reference, arch, label, true);
        defer update.deinit();
        const package: ?[]const u8 = if (selected) try std.fmt.allocPrint(fixture.allocator, "fixture-upgrade:{s}", .{arch}) else null;
        const update_lock = try fixture.absolute(try std.fmt.allocPrint(fixture.allocator, "executed/{s}.lock.json", .{label}));
        var install_plan = try workflow(fixture, driver, update.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-install-plan", .{label}), .{
            .family_execution = try signedRequest(fixture, update.native_root, arch, "resolve_lock", "fixture-upgrade", source, keyring, update_lock),
            .capture_evidence = true,
        });
        defer install_plan.deinit();
        try expectFamily(install_plan.report.value, "resolve_lock", true);
        const install_lock = try parse(fixture, update_lock[fixture.path.len + 1 ..], 1024 * 1024);
        defer install_lock.deinit();
        const before_plan = try foundation.capture(fixture.allocator, fixture.io, update.native_root);
        const premature = try signedRequest(fixture, update.native_root, arch, "update", package, source, keyring, update_lock);
        var rejected = try workflow(fixture, driver, update.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-reject-install-lock", .{label}), .{
            .family_execution = premature,
            .capture_evidence = true,
        });
        defer rejected.deinit();
        try expectFamily(rejected.report.value, "update", false);
        try same(try string(rejected.report.value, "exit_status"), "planning");
        if (std.ascii.indexOfIgnoreCase(try string(try field(rejected.report.value, "diagnostic"), "message"), "semantic request") == null)
            return error.MissingUpdateSemanticRequestDiagnostic;
        try std.testing.expect(!(try field(rejected.report.value, "changed")).bool);
        try std.testing.expectEqual(.null, try field(rejected.evidence.?.value, "native_install"));
        try std.testing.expectEqual(.null, try field(rejected.evidence.?.value, "native_completion"));
        try std.testing.expectEqualSlices(u8, before_plan, try foundation.capture(fixture.allocator, fixture.io, update.native_root));
        const planned = try signedRequest(fixture, update.native_root, arch, "resolve_lock", package, source, keyring, update_lock);
        var plan = try workflow(fixture, driver, update.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-plan", .{label}), .{
            .family_execution = planned,
            .family_update_planning = true,
            .capture_evidence = true,
        });
        defer plan.deinit();
        try expectFamily(plan.report.value, "resolve_lock", true);
        try std.testing.expect(!(try field(plan.report.value, "changed")).bool);
        try std.testing.expectEqual(.null, try field(plan.evidence.?.value, "native_install"));
        try std.testing.expectEqual(.null, try field(plan.evidence.?.value, "native_completion"));
        var update_lock_document = try parse(fixture, update_lock[fixture.path.len + 1 ..], 1024 * 1024);
        defer update_lock_document.deinit();
        try std.testing.expectEqual(@as(i64, 3), (try field(update_lock_document.value, "version")).integer);
        try std.testing.expect(!std.mem.eql(u8, try string(install_lock.value, "request_sha256"), try string(update_lock_document.value, "request_sha256")));
        try std.testing.expectEqualSlices(u8, before_plan, try foundation.capture(fixture.allocator, fixture.io, update.native_root));
        const requested = try signedRequest(fixture, update.native_root, arch, "update", package, source, keyring, update_lock);
        for ([_]struct { label: []const u8, operation: []const u8, package: ?[]const u8, recommends: bool }{
            .{ .label = "install-operation", .operation = "create", .package = "fixture-upgrade", .recommends = false },
            .{ .label = "update-selector", .operation = "update", .package = "essential-core", .recommends = false },
            .{ .label = "update-policy", .operation = "update", .package = package, .recommends = true },
        }) |change| {
            var wrong = requested;
            wrong.operation = change.operation;
            wrong.package = change.package;
            wrong.recommends = change.recommends;
            const destination = try std.fmt.allocPrint(fixture.allocator, "executed/{s}-reject-{s}", .{ label, change.label });
            var refusal = try workflow(fixture, driver, update.native_root, arch, destination, .{
                .family_execution = wrong,
                .capture_evidence = true,
            });
            defer refusal.deinit();
            try expectFamily(refusal.report.value, wrong.operation, false);
            try same(try string(refusal.report.value, "exit_status"), "planning");
            try std.testing.expect(!(try field(refusal.report.value, "changed")).bool);
            try std.testing.expectEqual(.null, try field(refusal.evidence.?.value, "native_install"));
            try std.testing.expectEqual(.null, try field(refusal.evidence.?.value, "native_completion"));
            try std.testing.expectEqualSlices(u8, before_plan, try foundation.capture(fixture.allocator, fixture.io, update.native_root));
        }
        var result = try workflow(fixture, driver, update.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-execute", .{label}), .{
            .family_execution = requested,
            .capture_evidence = true,
        });
        defer result.deinit();
        const returned = try completed(fixture, update.native_root, result, "update", update_lock, false);
        try assertExecutionWire(fixture, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-execute", .{label}), requested);
        const before_verification = try foundation.capture(fixture.allocator, fixture.io, update.native_root);
        const before_evidence = try projected.rootInventory(fixture, update.native_root, true);
        var verified = try workflow(fixture, driver, update.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify", .{label}), .{
            .family_verification = requested,
            .verification_expect_failure = false,
            .verification_completion = returned,
        });
        defer verified.deinit();
        try same(try string(verified.report.value, "operation"), if (selected) "upgrade" else "upgrade-all");
        try same(try string(verified.report.value, "schema"), "io.github.cataggar.debz.transaction-result-summary.v2");
        try same(try string(verified.report.value, "backend"), "native");
        try same(try string(verified.report.value, "final_verification_status"), "exact_match");
        var verified_lock = try parse(fixture, update_lock[fixture.path.len + 1 ..], 1024 * 1024);
        defer verified_lock.deinit();
        const update_root = update.native_root[fixture.path.len + 1 ..];
        var verified_receipt = try parse(fixture, try support.path(fixture.allocator, update_root, debz.native_provenance.document_path), 16 * 1024 * 1024);
        defer verified_receipt.deinit();
        var verified_completion = try parse(fixture, try support.path(fixture.allocator, update_root, debz.root_operation_completion.document_path), 64 * 1024);
        defer verified_completion.deinit();
        try std.testing.expectEqual(@as(usize, 24), verified.report.value.object.count());
        try std.testing.expectEqual(@as(i64, 2), (try field(verified.report.value, "api_version")).integer);
        try same(try string(verified.report.value, "target_architecture"), arch);
        try same(try string(verified.report.value, "install_root"), update.native_root);
        try same(try string(verified.report.value, "transaction_schema"), try string(verified_receipt.value, "schema"));
        try same(try string(verified.report.value, "completion_schema"), try string(verified_completion.value, "schema"));
        try std.testing.expectEqual(@as(i64, 2), (try field(verified.report.value, "transaction_schema_version")).integer);
        try std.testing.expectEqual(@as(i64, 2), (try field(verified.report.value, "completion_schema_version")).integer);
        for ([_]struct { name: []const u8, expected: []const u8 }{
            .{ .name = "lock_sha256", .expected = try string(verified_lock.value, "digest_sha256") },
            .{ .name = "request_sha256", .expected = try string(verified_lock.value, "request_sha256") },
            .{ .name = "solver_policy_sha256", .expected = try string(verified_lock.value, "policy_sha256") },
            .{ .name = "transaction_digest_sha256", .expected = try string(verified_receipt.value, "digest_sha256") },
            .{ .name = "completion_digest_sha256", .expected = try string(verified_completion.value, "digest_sha256") },
            .{ .name = "caller_request_sha256", .expected = try string(verified_completion.value, "request_sha256") },
            .{ .name = "caller_policy_sha256", .expected = try string(verified_completion.value, "policy_sha256") },
            .{ .name = "program_sha256", .expected = try string(verified_receipt.value, "program_sha256") },
        }) |binding| try same(try string(verified.report.value, binding.name), binding.expected);
        try std.testing.expectEqual(@as(i64, @intCast((try field(verified_lock.value, "packages")).array.items.len)), (try field(verified.report.value, "package_count")).integer);
        for ([_][]const u8{ "lock_evidence", "receipt_evidence", "final_verification_status" }) |status_field|
            try same(try string(verified.report.value, status_field), "exact_match");
        try same(try string(verified.report.value, "root_operation_status"), "cleared");
        try same(try string(verified.report.value, "outcome"), "succeeded");
        const summary = try support.read(fixture, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify/workflow.report.json", .{label}), 64 * 1024);
        var without_result = try workflow(fixture, driver, update.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify-without-result", .{label}), .{
            .family_verification = requested,
            .verification_expect_failure = false,
        });
        defer without_result.deinit();
        try std.testing.expectEqualSlices(u8, summary, try support.read(fixture, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify-without-result/workflow.report.json", .{label}), 64 * 1024));
        var wrong_install = requested;
        wrong_install.operation = "create";
        wrong_install.package = "fixture-upgrade";
        try refusedVerification(fixture, driver, wrong_install, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify-as-install", .{label}), null, "NativeFamilyRequestMismatch");
        try assertFamilySummary(fixture, driver, requested, returned, summary, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-verify-after-refusal", .{label}));
        const after_verification = try foundation.capture(fixture.allocator, fixture.io, update.native_root);
        try std.testing.expectEqualSlices(u8, before_verification, after_verification);
        try std.testing.expectEqualSlices(u8, before_evidence, try projected.rootInventory(fixture, update.native_root, true));
        const reference_name = try std.fmt.allocPrint(fixture.allocator, "executed/{s}-reference", .{label});
        try fixture.directory(reference_name);
        const v2 = try archive(fixture, arch, "fixture-upgrade", "2.0-1");
        if (try support.reference(fixture, reference, update.reference_root, .{ .operation = "install", .archives = &.{v2}, .triggers = true }, reference_name) != 0)
            return error.ReferenceFamilyUpdateFailed;
        const comparison = try std.fmt.allocPrint(fixture.allocator, "executed/{s}-comparison", .{label});
        try fixture.directory(comparison);
        try support.compare(fixture, update.reference_root, update.native_root, comparison, true);
        const receipt_relative = try support.path(fixture.allocator, update.native_root[fixture.path.len + 1 ..], debz.native_provenance.document_path);
        const receipt_bytes = try support.read(fixture, receipt_relative, 16 * 1024 * 1024);
        var unchanged_plan = try workflow(fixture, driver, update.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-unchanged-plan", .{label}), .{
            .family_execution = planned,
            .family_update_planning = true,
            .capture_evidence = true,
        });
        defer unchanged_plan.deinit();
        try expectFamily(unchanged_plan.report.value, "resolve_lock", true);
        var unchanged = try workflow(fixture, driver, update.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "executed/{s}-unchanged-update", .{label}), .{
            .family_execution = requested,
            .capture_evidence = true,
        });
        defer unchanged.deinit();
        try expectFamily(unchanged.report.value, "update", true);
        try std.testing.expect(!(try field(unchanged.report.value, "changed")).bool);
        try std.testing.expectEqual(.null, try field(unchanged.report.value, "provenance_path"));
        try std.testing.expectEqual(.null, try field(unchanged.evidence.?.value, "native_install"));
        try std.testing.expectEqual(.null, try field(unchanged.evidence.?.value, "native_completion"));
        try std.testing.expectEqualSlices(u8, receipt_bytes, try support.read(fixture, receipt_relative, 16 * 1024 * 1024));
        try support.compare(fixture, update.reference_root, update.native_root, comparison, true);
        std.debug.print("family {s}: archive-backed update, completion and pinned dpkg state passed\n", .{label});
    }
    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);
    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, true);
}

fn interruptedFamilyRecovery(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
    foreign_completion: std.json.Value,
    update: bool,
) !void {
    const name: []const u8 = if (update) "executed/interrupted-update" else "executed/interrupted-create";
    var scenario = try seededScenario(fixture, driver, helper, reference, arch, name, update);
    defer scenario.deinit();
    const cache_relative = try support.path(fixture.allocator, name, "cache");
    const state_relative = try support.path(fixture.allocator, name, "state");
    const lock_relative = try support.path(fixture.allocator, name, "lock.json");
    const cache = try fixture.absolute(cache_relative);
    const state = try fixture.absolute(state_relative);
    const lock = try fixture.absolute(lock_relative);
    const package = if (update) try std.fmt.allocPrint(fixture.allocator, "fixture-upgrade:{s}", .{arch}) else "scenario-main";
    const selectors: []const Selector = if (update)
        &.{.{ .name = "fixture-upgrade", .architecture = arch }}
    else
        &.{.{ .name = "scenario-main" }};
    const operation = if (update) "upgrade" else "install";
    if (update) {
        var family_plan = try signedRequest(fixture, scenario.native_root, arch, "resolve_lock", package, source, keyring, lock);
        family_plan.cache = cache;
        family_plan.state = state;
        var plan = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "plan"), .{
            .family_execution = family_plan,
            .family_update_planning = true,
            .capture_evidence = true,
        });
        defer plan.deinit();
        try expectFamily(plan.report.value, "resolve_lock", true);
        try std.testing.expectEqual(.null, try field(plan.evidence.?.value, "native_completion"));
    } else {
        var plan = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "plan"), .{
            .ordinary_mode = "plan_only",
            .selectors = selectors,
            .sources = &.{source},
            .keyrings = &.{keyring},
            .cache_path = cache,
            .state_path = state,
            .lock_output = lock,
            .capture_evidence = true,
        });
        defer plan.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(plan.report.value, "exit_status")).integer);
        try std.testing.expectEqual(.null, try field(plan.evidence.?.value, "native_completion"));
    }
    const original_lock = try support.read(fixture, lock_relative, 1024 * 1024);
    var request = try signedRequest(fixture, scenario.native_root, arch, if (update) "update" else "create", package, source, keyring, lock);
    request.cache = cache;
    request.state = state;
    try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "crash"), .{
        .ordinary_operation = operation,
        .ordinary_mode = "execute",
        .selectors = selectors,
        .sources = &.{source},
        .keyrings = &.{keyring},
        .cache_path = cache,
        .state_path = state,
        .lock_input = lock,
        .capture_evidence = true,
        .completion_crash = "after_native_receipt",
    });
    const root_relative = scenario.native_root[fixture.path.len + 1 ..];
    const operation_path = try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-v1.json");
    const pending = try support.read(fixture, operation_path, 64 * 1024);
    const pending_state = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
    const pending_evidence = try projected.rootInventory(fixture, scenario.native_root, true);
    var unverified = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "pending-verification"), .{
        .family_verification = request,
    });
    defer unverified.deinit();
    try std.testing.expect(!(try field(unverified.report.value, "verified")).bool);
    try std.testing.expectEqualSlices(u8, pending, try support.read(fixture, operation_path, 64 * 1024));
    try std.testing.expectEqualSlices(u8, pending_state, try foundation.capture(fixture.allocator, fixture.io, scenario.native_root));
    try std.testing.expectEqualSlices(u8, pending_evidence, try projected.rootInventory(fixture, scenario.native_root, true));
    var recovery = try familyRequest(fixture, scenario.native_root, arch, "recover");
    recovery.cache = try fixture.absolute(try support.path(fixture.allocator, name, "unused-cache"));
    recovery.state = try fixture.absolute(try support.path(fixture.allocator, name, "unused-state"));
    for ([_][]const u8{ "sources", "keyrings", "lock_input", "lock_output", "package" }) |field_name| {
        var wrong = recovery;
        if (std.mem.eql(u8, field_name, "sources")) wrong.sources = &.{source};
        if (std.mem.eql(u8, field_name, "keyrings")) wrong.keyrings = &.{keyring};
        if (std.mem.eql(u8, field_name, "lock_input")) wrong.lock_input = lock;
        if (std.mem.eql(u8, field_name, "lock_output")) wrong.lock_output = lock;
        if (std.mem.eql(u8, field_name, "package")) wrong.package = package;
        var refused = try workflow(fixture, driver, scenario.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "{s}/reject-{s}", .{ name, field_name }), .{
            .family_execution = wrong,
            .capture_evidence = true,
        });
        defer refused.deinit();
        try expectFamily(refused.report.value, "recover", false);
        try same(try string(refused.report.value, "exit_status"), "usage");
        try std.testing.expect(!(try field(refused.report.value, "changed")).bool);
        try std.testing.expectEqual(.null, try field(refused.report.value, "provenance_path"));
        try std.testing.expectEqualSlices(u8, pending, try support.read(fixture, operation_path, 64 * 1024));
        try std.testing.expectEqualSlices(u8, pending_evidence, try projected.rootInventory(fixture, scenario.native_root, true));
    }
    const evicted_cache = try support.path(fixture.allocator, name, "evicted-cache");
    try fixture.dir.rename(cache_relative, fixture.dir, evicted_cache, fixture.io);
    const evicted_lock = try support.path(fixture.allocator, name, "retained.lock");
    try fixture.dir.rename(lock_relative, fixture.dir, evicted_lock, fixture.io);
    var recovered = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "recover"), .{
        .family_execution = recovery,
        .capture_evidence = true,
    });
    defer recovered.deinit();
    try expectFamily(recovered.report.value, "recover", true);
    try std.testing.expect((try field(recovered.report.value, "changed")).bool);
    try std.testing.expectEqual(.null, try field(recovered.report.value, "lock_path"));
    try support.absent(fixture, lock_relative);
    try support.absent(fixture, try support.path(fixture.allocator, name, "cache"));
    try support.absent(fixture, try support.path(fixture.allocator, name, "unused-cache"));
    try support.absent(fixture, try support.path(fixture.allocator, name, "unused-state"));
    try std.testing.expectEqual(.null, try field(recovered.evidence.?.value, "native_install"));
    const returned = try field(recovered.evidence.?.value, "native_completion");
    try same(try string(returned, "outcome"), "succeeded");
    try same(try string(returned, "settlement"), "cleared");
    try same(try string(returned, "operation"), if (update) "upgrade" else "install");
    var receipt = try parse(fixture, try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path), 16 * 1024 * 1024);
    defer receipt.deinit();
    var completion = try parse(fixture, try support.path(fixture.allocator, root_relative, debz.root_operation_completion.document_path), 64 * 1024);
    defer completion.deinit();
    const transaction_digest = try hexEvidence(try field(returned, "transaction_digest_sha256"));
    try same(&transaction_digest, try string(receipt.value, "digest_sha256"));
    const completion_digest = try hexEvidence(try field(returned, "completion_digest_sha256"));
    try same(&completion_digest, try string(completion.value, "digest_sha256"));
    var locked = try parse(fixture, evicted_lock, 1024 * 1024);
    defer locked.deinit();
    for ([_]struct { name: []const u8, expected: []const u8 }{
        .{ .name = "attempt_id", .expected = try string(receipt.value, "attempt_id") },
        .{ .name = "lock_sha256", .expected = try string(locked.value, "digest_sha256") },
        .{ .name = "caller_request_sha256", .expected = try string(completion.value, "request_sha256") },
        .{ .name = "caller_policy_sha256", .expected = try string(completion.value, "policy_sha256") },
        .{ .name = "transaction_digest_sha256", .expected = try string(receipt.value, "digest_sha256") },
        .{ .name = "completion_digest_sha256", .expected = try string(completion.value, "digest_sha256") },
        .{ .name = "program_sha256", .expected = try string(receipt.value, "program_sha256") },
    }) |binding| {
        const actual = try hexEvidence(try field(returned, binding.name));
        try same(&actual, binding.expected);
    }
    try support.absent(fixture, operation_path);
    try fixture.dir.rename(evicted_lock, fixture.dir, lock_relative, fixture.io);
    try std.testing.expectEqualSlices(u8, original_lock, try support.read(fixture, lock_relative, 1024 * 1024));
    const before_verification = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
    const before_evidence = try projected.rootInventory(fixture, scenario.native_root, true);
    var verified = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "verified"), .{
        .family_verification = request,
        .verification_expect_failure = false,
        .verification_completion = returned,
    });
    defer verified.deinit();
    try same(try string(verified.report.value, "final_verification_status"), "exact_match");
    const first_summary = try support.read(fixture, try support.path(fixture.allocator, name, "verified/workflow.report.json"), 64 * 1024);
    try refusedVerification(fixture, driver, request, try support.path(fixture.allocator, name, "foreign-completion"), foreign_completion, "NativeFamilyCompletionMismatch");
    var verified_again = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "verified-again"), .{
        .family_verification = request,
        .verification_expect_failure = false,
    });
    defer verified_again.deinit();
    try std.testing.expectEqualSlices(u8, first_summary, try support.read(fixture, try support.path(fixture.allocator, name, "verified-again/workflow.report.json"), 64 * 1024));
    try std.testing.expectEqualSlices(u8, before_verification, try foundation.capture(fixture.allocator, fixture.io, scenario.native_root));
    try std.testing.expectEqualSlices(u8, before_evidence, try projected.rootInventory(fixture, scenario.native_root, true));
    const archives: []const []const u8 = if (update)
        &.{try archive(fixture, arch, "fixture-upgrade", "2.0-1")}
    else
        &.{ try archive(fixture, arch, "base-dep", "1.0-1"), try archive(fixture, arch, "scenario-main", "1.0-1") };
    const reference_name = try support.path(fixture.allocator, name, "reference-execute");
    try fixture.directory(reference_name);
    if (try support.reference(fixture, reference, scenario.reference_root, .{ .operation = "install", .archives = archives, .triggers = true }, reference_name) != 0)
        return error.ReferenceFamilyRecoveryFailed;
    const comparison = try support.path(fixture.allocator, name, "comparison");
    try fixture.directory(comparison);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    std.debug.print("family interrupted {s}: real receipt crash, cache/lock eviction, original verified completion and dpkg parity passed\n", .{if (update) "update" else "create"});
}

fn ordinaryWorkflow(
    fixture: *foundation.Fixture,
    driver: []const u8,
    scenario: *support.Scenario,
    name: []const u8,
    operation: []const u8,
    mode: []const u8,
    selectors: []const Selector,
    source: []const u8,
    keyring: []const u8,
    lock: []const u8,
) !Response {
    const recovering = std.mem.eql(u8, mode, "recover");
    return workflow(fixture, driver, scenario.native_root, scenario.architecture, name, .{
        .ordinary_operation = operation,
        .ordinary_mode = mode,
        .selectors = selectors,
        .sources = if (recovering) &.{} else &.{source},
        .keyrings = if (recovering) &.{} else &.{keyring},
        .lock_input = if (std.mem.eql(u8, mode, "execute")) lock else null,
        .lock_output = if (std.mem.eql(u8, mode, "plan_only")) lock else null,
        .cache_path = try fixture.absolute(try support.path(fixture.allocator, scenario.name, if (recovering) "unused-cache" else "cache")),
        .state_path = try fixture.absolute(try support.path(fixture.allocator, scenario.name, if (recovering) "unused-state" else "state")),
        .capture_evidence = true,
    });
}

fn ordinaryCompletion(
    fixture: *foundation.Fixture,
    root: []const u8,
    result: Response,
    lock: []const u8,
    outcome: []const u8,
) !void {
    try std.testing.expectEqual(@as(i64, if (std.mem.eql(u8, outcome, "failed")) 7 else 0), (try field(result.report.value, "exit_status")).integer);
    try std.testing.expect((try field(result.report.value, "changed")).bool);
    var locked = try parse(fixture, lock[fixture.path.len + 1 ..], 1024 * 1024);
    defer locked.deinit();
    const root_relative = root[fixture.path.len + 1 ..];
    var receipt = try parse(fixture, try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path), 16 * 1024 * 1024);
    defer receipt.deinit();
    var completion = try parse(fixture, try support.path(fixture.allocator, root_relative, debz.root_operation_completion.document_path), 64 * 1024);
    defer completion.deinit();
    try same(try string(receipt.value, "outcome"), outcome);
    try same(try string(receipt.value, "exact_lock_sha256"), try string(locked.value, "digest_sha256"));
    try same(try string(completion.value, "attempt_id"), try string(receipt.value, "attempt_id"));
    try same(try string(try field(completion.value, "transaction_provenance"), "document_sha256"), try string(receipt.value, "digest_sha256"));
    try same(try string(try field(completion.value, "journal"), "status"), "absent");
    const returned = try field(result.evidence.?.value, "native_completion");
    try same(try string(returned, "outcome"), outcome);
    try same(try string(returned, "operation"), try string(completion.value, "operation"));
    for ([_]struct { name: []const u8, expected: []const u8 }{
        .{ .name = "attempt_id", .expected = try string(receipt.value, "attempt_id") },
        .{ .name = "lock_sha256", .expected = try string(locked.value, "digest_sha256") },
        .{ .name = "caller_request_sha256", .expected = try string(completion.value, "request_sha256") },
        .{ .name = "caller_policy_sha256", .expected = try string(completion.value, "policy_sha256") },
        .{ .name = "transaction_digest_sha256", .expected = try string(receipt.value, "digest_sha256") },
        .{ .name = "completion_digest_sha256", .expected = try string(completion.value, "digest_sha256") },
        .{ .name = "program_sha256", .expected = try string(receipt.value, "program_sha256") },
    }) |binding| {
        const digest = try hexEvidence(try field(returned, binding.name));
        try same(&digest, binding.expected);
    }
    for ([_][]const u8{ "root-operation-v1.json", "native-execution-intent-v1.json" }) |document|
        try support.absent(fixture, try support.path(fixture.allocator, root_relative, try support.path(fixture.allocator, "var/lib/debz", document)));
}

fn ordinaryFamilyTimeline(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
) !void {
    const name = "executed/workflow-family-ordinary-timeline";
    var scenario = try seededScenario(fixture, driver, helper, reference, arch, name, false);
    defer scenario.deinit();
    const root = scenario.native_root;
    const lock = try fixture.absolute(try support.path(fixture.allocator, name, "lock.json"));
    const cache = try fixture.absolute(try support.path(fixture.allocator, name, "cache"));
    const state = try fixture.absolute(try support.path(fixture.allocator, name, "state"));
    const selected: []const Selector = &.{.{ .name = "scenario-main" }};
    var plan = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "plan"), "install", "plan_only", selected, source, keyring, lock);
    defer plan.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(plan.report.value, "exit_status")).integer);
    try std.testing.expectEqual(.null, try field(plan.evidence.?.value, "native_completion"));
    var original = try signedRequest(fixture, root, arch, "create", "scenario-main", source, keyring, lock);
    original.cache = cache;
    original.state = state;
    const before_execution = try projected.rootInventory(fixture, root, true);
    var not_completed = try workflow(fixture, driver, root, arch, try support.path(fixture.allocator, name, "verify-before-execution"), .{ .family_verification = original });
    defer not_completed.deinit();
    try std.testing.expect(!(try field(not_completed.report.value, "verified")).bool);
    try std.testing.expectEqualSlices(u8, before_execution, try projected.rootInventory(fixture, root, true));
    var installed = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "install"), "install", "execute", selected, source, keyring, lock);
    defer installed.deinit();
    try ordinaryCompletion(fixture, root, installed, lock, "succeeded");
    try fixture.directory(try support.path(fixture.allocator, name, "reference-install"));
    if (try support.reference(fixture, reference, scenario.reference_root, .{
        .operation = "install",
        .archives = &.{ try archive(fixture, arch, "base-dep", "1.0-1"), try archive(fixture, arch, "scenario-main", "1.0-1") },
        .triggers = true,
    }, try support.path(fixture.allocator, name, "reference-install")) != 0) return error.ReferenceOrdinaryFamilyInstallFailed;
    const comparison = try support.path(fixture.allocator, name, "comparison");
    try fixture.directory(comparison);
    try support.compare(fixture, scenario.reference_root, root, comparison, true);
    const first_completion = try field(installed.evidence.?.value, "native_completion");
    const verified_path = try support.path(fixture.allocator, name, "verify-first");
    var first = try workflow(fixture, driver, root, arch, verified_path, .{
        .family_verification = original,
        .verification_expect_failure = false,
        .verification_completion = first_completion,
    });
    defer first.deinit();
    try same(try string(first.report.value, "final_verification_status"), "exact_match");
    const summary = try support.read(fixture, try support.path(fixture.allocator, verified_path, "workflow.report.json"), 64 * 1024);
    try assertFamilySummary(fixture, driver, original, first_completion, summary, try support.path(fixture.allocator, name, "verify-first-again"));
    const before_without_result = try projected.rootInventory(fixture, root, true);
    const no_result_path = try support.path(fixture.allocator, name, "verify-first-without-result");
    var no_result = try workflow(fixture, driver, root, arch, no_result_path, .{
        .family_verification = original,
        .verification_expect_failure = false,
    });
    defer no_result.deinit();
    try std.testing.expectEqualSlices(u8, summary, try support.read(fixture, try support.path(fixture.allocator, no_result_path, "workflow.report.json"), 64 * 1024));
    var equivalent = original;
    equivalent.operation = "customize";
    const equivalent_path = try support.path(fixture.allocator, name, "verify-create-as-customize");
    var equivalent_proof = try workflow(fixture, driver, root, arch, equivalent_path, .{
        .family_verification = equivalent,
        .verification_expect_failure = false,
    });
    defer equivalent_proof.deinit();
    try std.testing.expectEqualSlices(u8, summary, try support.read(fixture, try support.path(fixture.allocator, equivalent_path, "workflow.report.json"), 64 * 1024));
    try std.testing.expectEqualSlices(u8, before_without_result, try projected.rootInventory(fixture, root, true));
    try verificationRefusals(fixture, driver, original, first_completion, summary, name);
    try assertFamilySummary(fixture, driver, original, first_completion, summary, try support.path(fixture.allocator, name, "verify-final"));
    var failure_plan = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "plan-failure"), "install", "plan_only", &.{.{ .name = "fail-script" }}, source, keyring, lock);
    defer failure_plan.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(failure_plan.report.value, "exit_status")).integer);
    var failed = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "failed-install"), "install", "execute", &.{.{ .name = "fail-script" }}, source, keyring, lock);
    defer failed.deinit();
    try ordinaryCompletion(fixture, root, failed, lock, "failed");
    var failed_family = original;
    failed_family.package = "fail-script";
    const returned = try field(failed.evidence.?.value, "native_completion");
    try same(try string(returned, "outcome"), "failed");
    var relabeled = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try std.json.Stringify.valueAlloc(fixture.allocator, returned, .{}), .{ .allocate = .alloc_always });
    defer relabeled.deinit();
    relabeled.value.object.getPtr("outcome").?.* = .{ .string = "succeeded" };
    try refusedVerification(fixture, driver, failed_family, try support.path(fixture.allocator, name, "verify-failed-result"), returned, null);
    try refusedVerification(fixture, driver, failed_family, try support.path(fixture.allocator, name, "verify-relabeled-failure"), relabeled.value, null);
    try refusedVerification(fixture, driver, failed_family, try support.path(fixture.allocator, name, "verify-failed-without-result"), null, null);
    try fixture.directory(try support.path(fixture.allocator, name, "reference-failure"));
    if (try support.reference(fixture, reference, scenario.reference_root, .{
        .operation = "install",
        .archives = &.{try archive(fixture, arch, "fail-script", "1.0-1")},
        .triggers = true,
    }, try support.path(fixture.allocator, name, "reference-failure")) != 1) return error.ReferenceOrdinaryFamilyFailureMissing;
    try support.compare(fixture, scenario.reference_root, root, comparison, true);
    const root_relative = root[fixture.path.len + 1 ..];
    const receipt_path = try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path);
    const receipt_before = try support.read(fixture, receipt_path, 16 * 1024 * 1024);
    var recovered = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "clean-recovery"), "install", "recover", &.{.{ .name = "fail-script" }}, source, keyring, lock);
    defer recovered.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(recovered.report.value, "exit_status")).integer);
    try std.testing.expect(!(try field(recovered.report.value, "changed")).bool);
    try std.testing.expectEqual(.null, try field(recovered.evidence.?.value, "native_completion"));
    try std.testing.expectEqualSlices(u8, receipt_before, try support.read(fixture, receipt_path, 16 * 1024 * 1024));
    try support.compare(fixture, scenario.reference_root, root, comparison, true);
    std.debug.print("ordinary-to-FAMILY same-root timeline: signed success, full verification refusals, failed install and clean recovery matched pinned dpkg\n", .{});
}

fn publicResultCommand(
    fixture: *foundation.Fixture,
    cli: []const u8,
    destination: []const u8,
    args: []const []const u8,
    expected_exit: u8,
) !?std.json.Parsed(std.json.Value) {
    try fixture.directory(destination);
    var command: std.ArrayList([]const u8) = .empty;
    defer command.deinit(fixture.allocator);
    try command.appendSlice(fixture.allocator, &.{ "/usr/bin/timeout", "--kill-after=2s", "30s", cli, "transaction-result" });
    try command.appendSlice(fixture.allocator, args);
    const result = try std.process.run(fixture.allocator, fixture.io, .{
        .argv = command.items,
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(35), .clock = .awake } },
    });
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    try fixture.write(try support.path(fixture.allocator, destination, "stdout.json"), result.stdout, 0o644);
    try fixture.write(try support.path(fixture.allocator, destination, "stderr.log"), result.stderr, 0o644);
    if (result.term != .exited or result.term.exited != expected_exit) {
        std.debug.print("public result {s}: exited {any}, expected {d}; stdout {s}; stderr {s}\n", .{ destination, result.term, expected_exit, result.stdout, result.stderr });
        return error.UnexpectedPublicResultExit;
    }
    if (expected_exit != 0) {
        try std.testing.expectEqual(@as(usize, 0), result.stdout.len);
        return null;
    }
    try std.testing.expectEqual(@as(usize, 0), result.stderr.len);
    var parsed = try std.json.parseFromSlice(std.json.Value, fixture.allocator, result.stdout, .{ .allocate = .alloc_always });
    errdefer parsed.deinit();
    const canonical = try std.json.Stringify.valueAlloc(fixture.allocator, parsed.value, .{});
    const with_newline = try std.mem.concat(fixture.allocator, u8, &.{ canonical, "\n" });
    try std.testing.expectEqualSlices(u8, with_newline, result.stdout);
    return parsed;
}

fn publicVerify(
    fixture: *foundation.Fixture,
    cli: []const u8,
    root: []const u8,
    lock: []const u8,
    arch: []const u8,
    destination: []const u8,
    success: bool,
) !void {
    const root_evidence = try projected.evidenceInventory(fixture, root, true);
    const status = try support.path(fixture.allocator, root[fixture.path.len + 1 ..], "var/lib/dpkg/status");
    const status_before = try support.read(fixture, status, 1024 * 1024);
    const dpkg_before = foundation.capture(fixture.allocator, fixture.io, root) catch |err| switch (err) {
        error.InvalidDeb822 => null,
        else => return err,
    };
    var proof = try publicResultCommand(fixture, cli, destination, &.{
        "verify",       "--transaction-backend", "native",         "--install-root", root,
        "--lock-input", lock,                    "--architecture", arch,             "--json",
    }, if (success) 0 else 7);
    defer if (proof) |*parsed| parsed.deinit();
    try std.testing.expectEqualSlices(u8, root_evidence, try projected.evidenceInventory(fixture, root, true));
    try std.testing.expectEqualSlices(u8, status_before, try support.read(fixture, status, 1024 * 1024));
    if (dpkg_before) |snapshot| try std.testing.expectEqualSlices(u8, snapshot, try foundation.capture(fixture.allocator, fixture.io, root));
    if (proof) |parsed| {
        var locked = try parse(fixture, lock[fixture.path.len + 1 ..], 1024 * 1024);
        defer locked.deinit();
        const relative = root[fixture.path.len + 1 ..];
        var receipt = try parse(fixture, try support.path(fixture.allocator, relative, debz.native_provenance.document_path), 16 * 1024 * 1024);
        defer receipt.deinit();
        var completion = try parse(fixture, try support.path(fixture.allocator, relative, debz.root_operation_completion.document_path), 64 * 1024);
        defer completion.deinit();
        try std.testing.expectEqual(@as(usize, 24), parsed.value.object.count());
        try same(try string(parsed.value, "schema"), "io.github.cataggar.debz.transaction-result-summary.v2");
        try std.testing.expectEqual(@as(i64, 2), (try field(parsed.value, "api_version")).integer);
        try same(try string(parsed.value, "backend"), "native");
        try same(try string(parsed.value, "transaction_schema"), try string(receipt.value, "schema"));
        try std.testing.expectEqual(@as(i64, 2), (try field(parsed.value, "transaction_schema_version")).integer);
        try same(try string(parsed.value, "completion_schema"), try string(completion.value, "schema"));
        try std.testing.expectEqual(@as(i64, 2), (try field(parsed.value, "completion_schema_version")).integer);
        try same(try string(parsed.value, "target_architecture"), arch);
        try same(try string(parsed.value, "install_root"), root);
        try same(try string(parsed.value, "operation"), try string(completion.value, "operation"));
        try same(try string(parsed.value, "lock_sha256"), try string(locked.value, "digest_sha256"));
        try same(try string(parsed.value, "request_sha256"), try string(locked.value, "request_sha256"));
        try same(try string(parsed.value, "solver_policy_sha256"), try string(locked.value, "policy_sha256"));
        try same(try string(parsed.value, "transaction_digest_sha256"), try string(receipt.value, "digest_sha256"));
        try same(try string(parsed.value, "completion_digest_sha256"), try string(completion.value, "digest_sha256"));
        try same(try string(parsed.value, "caller_request_sha256"), try string(completion.value, "request_sha256"));
        try same(try string(parsed.value, "caller_policy_sha256"), try string(completion.value, "policy_sha256"));
        try same(try string(parsed.value, "program_sha256"), try string(receipt.value, "program_sha256"));
        try std.testing.expectEqual(@as(i64, @intCast((try field(locked.value, "packages")).array.items.len)), (try field(parsed.value, "package_count")).integer);
        for ([_][]const u8{ "lock_evidence", "receipt_evidence", "final_verification_status" }) |status_field|
            try same(try string(parsed.value, status_field), "exact_match");
        try same(try string(parsed.value, "root_operation_status"), "cleared");
        try same(try string(parsed.value, "outcome"), "succeeded");
    }
}

fn ownedResultProof(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    arch: []const u8,
    label: []const u8,
    lock: []const u8,
    owner: []const u8,
    selected: []const Selector,
    operation: []const u8,
    recommends: bool,
    expected_error: ?[]const u8,
) !void {
    const before = try projected.evidenceInventory(fixture, root, true);
    var response = try workflow(fixture, driver, root, arch, label, .{
        .ordinary_operation = operation,
        .ordinary_mode = "recover",
        .selectors = selected,
        .cache_path = try fixture.absolute("executed/workflow-owned-success/unused-cache"),
        .state_path = try fixture.absolute("executed/workflow-owned-success/unused-state"),
        .orchestration_id = @splat(17),
        .recommends = recommends,
        .owner_evidence = owner,
        .owned_verification = .{ .lock_path = lock, .state = "released", .expected_error = expected_error },
    });
    defer response.deinit();
    try std.testing.expectEqual(expected_error == null, (try field(response.report.value, "verified")).bool);
    if (expected_error == null) try same(try string(response.report.value, "outcome"), "succeeded");
    try std.testing.expectEqualSlices(u8, before, try projected.evidenceInventory(fixture, root, true));
}

fn batchWorkflow(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
    cli: []const u8,
) !void {
    var scenario = try seededScenario(fixture, driver, helper, reference, arch, "executed/workflow-batch", false);
    defer scenario.deinit();
    const lock = try fixture.absolute("executed/workflow-batch/lock.json");
    const selected: []const Selector = &.{ .{ .name = "scenario-main" }, .{ .name = "conffile-pkg" } };
    const reversed: []const Selector = &.{ .{ .name = "conffile-pkg" }, .{ .name = "scenario-main" } };
    var planned = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-batch/plan-install", "install", "plan_only", selected, source, keyring, lock);
    defer planned.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(planned.report.value, "exit_status")).integer);
    const items = (try field(planned.report.value, "items")).array.items;
    try std.testing.expectEqual(@as(usize, 3), items.len);
    for ([_][]const u8{ "scenario-main", "conffile-pkg", "base-dep" }) |package| {
        var found = false;
        for (items) |item| if (std.mem.eql(u8, try string(item, "package"), package)) {
            found = true;
            break;
        };
        try std.testing.expect(found);
    }
    var install_lock = try parse(fixture, lock[fixture.path.len + 1 ..], 1024 * 1024);
    defer install_lock.deinit();
    try std.testing.expectEqual(@as(i64, 3), (try field(install_lock.value, "version")).integer);
    try std.testing.expectEqual(.null, try field(planned.evidence.?.value, "native_completion"));
    var installed = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-batch/install", "install", "execute", reversed, source, keyring, lock);
    defer installed.deinit();
    try ordinaryCompletion(fixture, scenario.native_root, installed, lock, "succeeded");
    const reference_install = "executed/workflow-batch/reference-install";
    try fixture.directory(reference_install);
    const archives: []const []const u8 = &.{
        try archive(fixture, arch, "base-dep", "1.0-1"),
        try archive(fixture, arch, "scenario-main", "1.0-1"),
        try archive(fixture, arch, "conffile-pkg", "1.0-1"),
    };
    if (try support.reference(fixture, reference, scenario.reference_root, .{ .operation = "install", .archives = archives, .triggers = true }, reference_install) != 0)
        return error.ReferenceBatchInstallFailed;
    try fixture.directory("executed/workflow-batch/compare-install");
    try support.compare(fixture, scenario.reference_root, scenario.native_root, "executed/workflow-batch/compare-install", true);
    var capability = (try publicResultCommand(fixture, cli, "executed/workflow-batch/capabilities", &.{
        "capabilities", "--transaction-backend", "native", "--json",
    }, 0)) orelse return error.MissingResultCapabilities;
    defer capability.deinit();
    try std.testing.expectEqual(@as(usize, 13), capability.value.object.count());
    try same(try string(capability.value, "schema"), "io.github.cataggar.debz.transaction-result-capability.v1");
    try std.testing.expectEqual(@as(i64, 1), (try field(capability.value, "api_version")).integer);
    try same(try string(capability.value, "backend"), "native");
    try same(try string(capability.value, "capability"), "native-transaction-result-v1");
    try same(try string(capability.value, "summary_schema"), "io.github.cataggar.debz.transaction-result-summary.v2");
    try std.testing.expectEqual(@as(i64, 2), (try field(capability.value, "summary_api_version")).integer);
    for ([_]struct { key: []const u8, expected: []const u8 }{
        .{ .key = "transaction_schema", .expected = "https://debz.dev/schema/native-transaction-provenance-v2" },
        .{ .key = "completion_schema", .expected = "https://debz.dev/schema/root-operation-completion-v2" },
        .{ .key = "lock_schema", .expected = "https://debz.dev/schema/exact-closure-lock-v3" },
    }) |binding| try same(try string(capability.value, binding.key), binding.expected);
    for ([_][]const u8{ "transaction_schema_version", "completion_schema_version" }) |version|
        try std.testing.expectEqual(@as(i64, 2), (try field(capability.value, version)).integer);
    try std.testing.expectEqual(@as(i64, 3), (try field(capability.value, "lock_schema_version")).integer);
    try std.testing.expect((try field(capability.value, "read_only")).bool);
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-batch/verify-install", true);
    try publicVerify(fixture, cli, scenario.native_root, lock, if (std.mem.eql(u8, arch, "arm64")) "amd64" else "arm64", "executed/workflow-batch/verify-wrong-architecture", false);
    const lock_path = lock[fixture.path.len + 1 ..];
    const original_lock = try support.read(fixture, lock_path, 1024 * 1024);
    var different = try parse(fixture, lock_path, 1024 * 1024);
    defer different.deinit();
    _ = different.value.object.swapRemove("digest_sha256");
    different.value.object.getPtr("request_sha256").?.* = .{ .string = "0000000000000000000000000000000000000000000000000000000000000000" };
    const changed_lock = try std.json.Stringify.valueAlloc(fixture.allocator, different.value, .{});
    var changed_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(changed_lock, &changed_digest, .{});
    const changed_digest_hex = std.fmt.bytesToHex(changed_digest, .lower);
    try different.value.object.put(fixture.allocator, "digest_sha256", .{ .string = try fixture.allocator.dupe(u8, &changed_digest_hex) });
    try fixture.write(lock_path, try std.json.Stringify.valueAlloc(fixture.allocator, different.value, .{}), 0o644);
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-batch/verify-other-valid-lock", false);
    try fixture.write(lock_path, original_lock, 0o644);
    const root_relative = scenario.native_root[fixture.path.len + 1 ..];
    const record_path = try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-v1.json");
    try fixture.write(record_path, "unsettled operation\n", 0o644);
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-batch/verify-unsettled", false);
    try fixture.dir.deleteFile(fixture.io, record_path);
    const receipt_file = try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path);
    var receipt_document = try parse(fixture, receipt_file, 16 * 1024 * 1024);
    defer receipt_document.deinit();
    var program_path: ?[]const u8 = null;
    for ((try field(receipt_document.value, "evidence_files")).array.items) |entry| {
        if (std.mem.eql(u8, try string(entry, "kind"), "program")) {
            program_path = try support.path(fixture.allocator, root_relative, try string(entry, "path"));
            break;
        }
    }
    for ([_]struct { name: []const u8, path: []const u8 }{
        .{ .name = "program", .path = program_path orelse return error.MissingPublicResultProgram },
        .{ .name = "receipt", .path = receipt_file },
        .{ .name = "completion", .path = try support.path(fixture.allocator, root_relative, debz.root_operation_completion.document_path) },
        .{ .name = "database", .path = try support.path(fixture.allocator, root_relative, "var/lib/dpkg/status") },
    }) |damaged| {
        const original = try support.read(fixture, damaged.path, 16 * 1024 * 1024);
        try fixture.write(damaged.path, "invalid completed evidence\n", 0o644);
        try publicVerify(fixture, cli, scenario.native_root, lock, arch, try std.fmt.allocPrint(fixture.allocator, "executed/workflow-batch/verify-damaged-{s}", .{damaged.name}), false);
        try fixture.write(damaged.path, original, 0o644);
    }
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-batch/verify-after-refusals", true);
    const receipt_path = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], debz.native_provenance.document_path);
    const receipt_before = try support.read(fixture, receipt_path, 16 * 1024 * 1024);
    var no_op_plan = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-batch/plan-unchanged", "upgrade_all", "plan_only", &.{}, source, keyring, lock);
    defer no_op_plan.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(no_op_plan.report.value, "exit_status")).integer);
    var no_op = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-batch/unchanged", "upgrade_all", "execute", &.{}, source, keyring, lock);
    defer no_op.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(no_op.report.value, "exit_status")).integer);
    try std.testing.expect(!(try field(no_op.report.value, "changed")).bool);
    try std.testing.expectEqual(.null, try field(no_op.evidence.?.value, "native_completion"));
    try std.testing.expectEqualSlices(u8, receipt_before, try support.read(fixture, receipt_path, 16 * 1024 * 1024));
    try support.compare(fixture, scenario.reference_root, scenario.native_root, "executed/workflow-batch/compare-install", true);
    var remove_plan = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-batch/plan-remove", "remove", "plan_only", selected, source, keyring, lock);
    defer remove_plan.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(remove_plan.report.value, "exit_status")).integer);
    var removed = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-batch/remove", "remove", "execute", selected, source, keyring, lock);
    defer removed.deinit();
    try ordinaryCompletion(fixture, scenario.native_root, removed, lock, "succeeded");
    const reference_remove = "executed/workflow-batch/reference-remove";
    try fixture.directory(reference_remove);
    if (try support.reference(fixture, reference, scenario.reference_root, .{
        .operation = "remove",
        .packages = &.{ .{ .name = "scenario-main", .architecture = arch }, .{ .name = "conffile-pkg", .architecture = arch } },
        .triggers = true,
    }, reference_remove) != 0) return error.ReferenceBatchRemovalFailed;
    try fixture.directory("executed/workflow-batch/compare-remove");
    try support.compare(fixture, scenario.reference_root, scenario.native_root, "executed/workflow-batch/compare-remove", true);
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-batch/verify-remove", true);
    std.debug.print("ordinary workflow batch: real reversed multi-selector install, unchanged upgrade-all and removal matched pinned dpkg\n", .{});
}

fn ownedSuccess(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
    cli: []const u8,
) !void {
    const name = "executed/workflow-owned-success";
    var scenario = try seededScenario(fixture, driver, helper, reference, arch, name, false);
    defer scenario.deinit();
    const selected: []const Selector = &.{ .{ .name = "scenario-main" }, .{ .name = "conffile-pkg" } };
    const lock = try fixture.absolute("executed/workflow-owned-success/lock.json");
    const cache = try fixture.absolute("executed/workflow-owned-success/cache");
    const state = try fixture.absolute("executed/workflow-owned-success/state");
    var planned = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-owned-success/plan", "install", "plan_only", selected, source, keyring, lock);
    defer planned.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(planned.report.value, "exit_status")).integer);
    const owner_path = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], "var/lib/debz/root-operation-deferred-ack-v1.json");
    var reserved = try workflow(fixture, driver, scenario.native_root, arch, "executed/workflow-owned-success/reserve", .{
        .ordinary_mode = "reserve",
        .selectors = selected,
        .sources = &.{source},
        .keyrings = &.{keyring},
        .cache_path = cache,
        .state_path = state,
        .lock_input = lock,
        .orchestration_id = @splat(17),
        .root_attempt_id = @splat(34),
        .capture_evidence = true,
    });
    defer reserved.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(reserved.report.value, "exit_status")).integer);
    var bound = try parse(fixture, owner_path, 64 * 1024);
    defer bound.deinit();
    try same(try string(bound.value, "state"), "bound");
    try same(try string(bound.value, "attempt_id"), "2222222222222222222222222222222222222222222222222222222222222222");
    const bound_path = try fixture.absolute("executed/workflow-owned-success/bound.owner.json");
    try fixture.write("executed/workflow-owned-success/bound.owner.json", try support.read(fixture, owner_path, 64 * 1024), 0o644);
    const record = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], "var/lib/debz/root-operation-v1.json");
    const reserved_bytes = try support.read(fixture, record, 64 * 1024);
    var wrong = try workflow(fixture, driver, scenario.native_root, arch, "executed/workflow-owned-success/wrong-request", .{
        .ordinary_mode = "execute",
        .selectors = &.{.{ .name = "different" }},
        .sources = &.{source},
        .keyrings = &.{keyring},
        .cache_path = cache,
        .state_path = state,
        .lock_input = lock,
        .orchestration_id = @splat(17),
        .owner_evidence = bound_path,
        .capture_evidence = true,
    });
    defer wrong.deinit();
    try std.testing.expectEqual(@as(i64, 8), (try field(wrong.report.value, "exit_status")).integer);
    try std.testing.expectEqual(.null, try field(wrong.evidence.?.value, "native_completion"));
    try std.testing.expectEqualSlices(u8, reserved_bytes, try support.read(fixture, record, 64 * 1024));
    var executed = try workflow(fixture, driver, scenario.native_root, arch, "executed/workflow-owned-success/execute", .{
        .ordinary_mode = "execute",
        .selectors = &.{ .{ .name = "conffile-pkg" }, .{ .name = "scenario-main" } },
        .sources = &.{source},
        .keyrings = &.{keyring},
        .cache_path = cache,
        .state_path = state,
        .lock_input = lock,
        .orchestration_id = @splat(17),
        .owner_evidence = bound_path,
        .capture_evidence = true,
    });
    defer executed.deinit();
    try ordinaryCompletion(fixture, scenario.native_root, executed, lock, "succeeded");
    try same(try string(try field(executed.evidence.?.value, "native_completion"), "settlement"), "retained");
    const reference_name = "executed/workflow-owned-success/reference-execute";
    try fixture.directory(reference_name);
    if (try support.reference(fixture, reference, scenario.reference_root, .{
        .operation = "install",
        .archives = &.{
            try archive(fixture, arch, "base-dep", "1.0-1"),
            try archive(fixture, arch, "scenario-main", "1.0-1"),
            try archive(fixture, arch, "conffile-pkg", "1.0-1"),
        },
        .triggers = true,
    }, reference_name) != 0) return error.ReferenceOwnedInstallFailed;
    try fixture.directory("executed/workflow-owned-success/comparison");
    try support.compare(fixture, scenario.reference_root, scenario.native_root, "executed/workflow-owned-success/comparison", true);
    const released_bytes = try support.read(fixture, owner_path, 64 * 1024);
    const released_path = try fixture.absolute("executed/workflow-owned-success/released.owner.json");
    try fixture.write("executed/workflow-owned-success/released.owner.json", released_bytes, 0o644);
    var released = try parse(fixture, owner_path, 64 * 1024);
    defer released.deinit();
    try same(try string(released.value, "state"), "released");
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-owned-success/verify-owner-retained", false);
    var forbidden = try workflow(fixture, driver, scenario.native_root, arch, "executed/workflow-owned-success/family-cannot-finalize", .{
        .family_execution = try familyRequest(fixture, scenario.native_root, arch, "recover"),
        .capture_evidence = true,
    });
    defer forbidden.deinit();
    try expectFamily(forbidden.report.value, "recover", false);
    try same(try string(forbidden.report.value, "exit_status"), "recovery");
    try std.testing.expectEqualSlices(u8, released_bytes, try support.read(fixture, owner_path, 64 * 1024));
    const before_proof = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
    for ([_]struct { name: []const u8, state: []const u8, expected_error: ?[]const u8 }{
        .{ .name = "verified", .state = "released", .expected_error = null },
        .{ .name = "wrong-state", .state = "pending", .expected_error = "PendingOwnerRequired" },
    }) |case| {
        var proof = try workflow(fixture, driver, scenario.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "{s}/{s}", .{ name, case.name }), .{
            .ordinary_mode = "recover",
            .selectors = selected,
            .cache_path = try fixture.absolute("executed/workflow-owned-success/unused-cache"),
            .state_path = try fixture.absolute("executed/workflow-owned-success/unused-state"),
            .orchestration_id = @splat(17),
            .owner_evidence = released_path,
            .owned_verification = .{ .lock_path = lock, .state = case.state, .expected_error = case.expected_error },
        });
        defer proof.deinit();
        try std.testing.expectEqual(case.expected_error == null, (try field(proof.report.value, "verified")).bool);
        if (case.expected_error == null) try same(try string(proof.report.value, "outcome"), "succeeded");
        try std.testing.expectEqualSlices(u8, before_proof, try foundation.capture(fixture.allocator, fixture.io, scenario.native_root));
        try std.testing.expectEqualSlices(u8, released_bytes, try support.read(fixture, owner_path, 64 * 1024));
    }
    try ownedResultProof(fixture, driver, scenario.native_root, arch, "executed/workflow-owned-success/verify-released-again", lock, released_path, selected, "install", false, null);
    try ownedResultProof(fixture, driver, scenario.native_root, arch, "executed/workflow-owned-success/verify-bound-as-released", lock, bound_path, selected, "install", false, "ReleasedOwnerRequired");
    for ([_]struct { label: []const u8, operation: []const u8, selectors: []const Selector, recommends: bool }{
        .{ .label = "wrong-operation", .operation = "remove", .selectors = selected, .recommends = false },
        .{ .label = "wrong-selector", .operation = "install", .selectors = &.{.{ .name = "different" }}, .recommends = false },
        .{ .label = "wrong-policy", .operation = "install", .selectors = selected, .recommends = true },
    }) |item| try ownedResultProof(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, try std.fmt.allocPrint(fixture.allocator, "verify-{s}", .{item.label})), lock, released_path, item.selectors, item.operation, item.recommends, "InvalidCompletion");
    try fixture.write(record, reserved_bytes, 0o644);
    try ownedResultProof(fixture, driver, scenario.native_root, arch, "executed/workflow-owned-success/verify-unfinished-record", lock, released_path, selected, "install", false, "InvalidCompletion");
    try fixture.dir.deleteFile(fixture.io, record);
    for ([_]struct { label: []const u8, relative: []const u8 }{
        .{ .label = "intent", .relative = "native-execution-intent-v1.json" },
        .{ .label = "script", .relative = "native-lifecycle-script-v1.json" },
        .{ .label = "progress", .relative = "native-execution-progress-v1.log" },
        .{ .label = "staging", .relative = ".debz-native-foreign" },
    }) |item| {
        const active = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], try support.path(fixture.allocator, "var/lib/debz", item.relative));
        try support.absent(fixture, active);
        try fixture.write(active, "{}\n", 0o644);
        try ownedResultProof(fixture, driver, scenario.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "{s}/verify-active-{s}", .{ name, item.label }), lock, released_path, selected, "install", false, "OperationNotSettled");
        try fixture.dir.deleteFile(fixture.io, active);
    }
    const receipt_path = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], debz.native_provenance.document_path);
    const completion_path = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], debz.root_operation_completion.document_path);
    for ([_]struct { label: []const u8, path: []const u8, expected_error: []const u8 }{
        .{ .label = "completion", .path = completion_path, .expected_error = "NonCanonicalDocument" },
        .{ .label = "receipt", .path = receipt_path, .expected_error = "MissingField" },
    }) |item| {
        const original = try support.read(fixture, item.path, 16 * 1024 * 1024);
        try fixture.write(item.path, "{}\n", 0o644);
        try ownedResultProof(fixture, driver, scenario.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "{s}/verify-damaged-{s}", .{ name, item.label }), lock, released_path, selected, "install", false, item.expected_error);
        try fixture.write(item.path, original, 0o644);
    }
    const receipt_before = try support.read(fixture, receipt_path, 16 * 1024 * 1024);
    for ([_][]const u8{ "finalize", "finalize-again" }) |label| {
        var finalized = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, label), .{
            .ordinary_mode = "recover",
            .selectors = selected,
            .cache_path = try fixture.absolute("executed/workflow-owned-success/unused-cache"),
            .state_path = try fixture.absolute("executed/workflow-owned-success/unused-state"),
            .orchestration_id = @splat(17),
            .owner_evidence = released_path,
            .acknowledgment = "ownership",
        });
        defer finalized.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(finalized.report.value, "exit_status")).integer);
    }
    try support.absent(fixture, owner_path);
    try ownedResultProof(fixture, driver, scenario.native_root, arch, "executed/workflow-owned-success/verify-finalized-as-released", lock, released_path, selected, "install", false, "ReleasedOwnerRequired");
    try std.testing.expectEqualSlices(u8, receipt_before, try support.read(fixture, receipt_path, 16 * 1024 * 1024));
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-owned-success/verify-owner-cleared", true);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, "executed/workflow-owned-success/comparison", true);
    std.debug.print("ordinary owned workflow: exact reserve, foreign request refusal, retained receipt, owner verification and finalization matched dpkg\n", .{});
}

fn reconciliation(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
) !void {
    for ([_]bool{ true, false }) |pre_mutation| for ([_]bool{ true, false }) |before_publish| {
        const label = try std.fmt.allocPrint(fixture.allocator, "executed/reconciliation-{s}-{s}", .{
            if (pre_mutation) "pre" else "post",
            if (before_publish) "before" else "after",
        });
        var scenario = try seededScenario(fixture, driver, helper, reference, arch, label, false);
        defer scenario.deinit();
        const lock_relative = try support.path(fixture.allocator, label, "lock.json");
        const lock = try fixture.absolute(lock_relative);
        var planned = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, label, "plan"), "upgrade_all", "plan_only", &.{}, source, keyring, lock);
        defer planned.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(planned.report.value, "exit_status")).integer);
        var lock_document = try parse(fixture, lock_relative, 1024 * 1024);
        defer lock_document.deinit();
        var lock_digest: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&lock_digest, try string(lock_document.value, "digest_sha256"));
        const json = if (pre_mutation)
            try std.json.Stringify.valueAlloc(fixture.allocator, .{ .pre_mutation = .{
                .exact_lock_sha256 = lock_digest,
                .outer_generation = @as(u64, 1),
                .outer_state_sha256 = @as([32]u8, @splat(31)),
                .profile_sha256 = @as([32]u8, @splat(32)),
                .profile_reference_sha256 = @as([32]u8, @splat(33)),
            } }, .{})
        else
            try std.json.Stringify.valueAlloc(fixture.allocator, .{ .post_mutation = .{
                .exact_lock_sha256 = lock_digest,
                .evidence_sha256 = @as([32]u8, @splat(34)),
            } }, .{});
        var claim = try std.json.parseFromSlice(std.json.Value, fixture.allocator, json, .{ .allocate = .alloc_always });
        defer claim.deinit();
        const owner_relative = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], "var/lib/debz/root-operation-deferred-ack-v1.json");
        const proof_relative = try support.path(fixture.allocator, label, "trusted-reconciliation.owner.json");
        const proof = try fixture.absolute(proof_relative);
        const before = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
        const crash_at: []const u8 = if (before_publish) "before_reconciliation_marker_publish" else "after_reconciliation_marker_publish";
        try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, label, "claim-crash"), .{
            .ordinary_operation = "upgrade_all",
            .ordinary_mode = "recover",
            .orchestration_id = @splat(17),
            .reconciliation_claim = claim.value,
            .reconciliation_owner_output = proof,
            .completion_crash = crash_at,
        });
        var expected = try parse(fixture, proof_relative, 64 * 1024);
        defer expected.deinit();
        try same(try string(expected.value, "state"), if (pre_mutation) "pre_mutation_reconciliation_claim" else "released");
        const proof_bytes = try support.read(fixture, proof_relative, 64 * 1024);
        if (before_publish) {
            try support.absent(fixture, owner_relative);
            const claim_evidence = try projected.evidenceInventory(fixture, scenario.native_root, true);
            var wrong_claim = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, label, "changed-request"), .{
                .ordinary_operation = "remove",
                .ordinary_mode = "recover",
                .selectors = &.{.{ .name = "different" }},
                .orchestration_id = @splat(17),
                .reconciliation_claim = claim.value,
                .owner_evidence = proof,
            });
            defer wrong_claim.deinit();
            try std.testing.expectEqual(@as(i64, 8), (try field(wrong_claim.report.value, "exit_status")).integer);
            try support.absent(fixture, owner_relative);
            try std.testing.expectEqualSlices(u8, proof_bytes, try support.read(fixture, proof_relative, 64 * 1024));
            try std.testing.expectEqualSlices(u8, claim_evidence, try projected.evidenceInventory(fixture, scenario.native_root, true));
            var claim_report = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, label, "publish-claim"), .{
                .ordinary_operation = "upgrade_all",
                .ordinary_mode = "recover",
                .orchestration_id = @splat(17),
                .reconciliation_claim = claim.value,
                .owner_evidence = proof,
            });
            defer claim_report.deinit();
            try std.testing.expectEqual(@as(i64, 0), (try field(claim_report.report.value, "exit_status")).integer);
        }
        try std.testing.expectEqualSlices(u8, proof_bytes, try support.read(fixture, owner_relative, 64 * 1024));
        var repeat = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, label, "repeat-claim"), .{
            .ordinary_operation = "upgrade_all",
            .ordinary_mode = "recover",
            .orchestration_id = @splat(17),
            .reconciliation_claim = claim.value,
            .owner_evidence = proof,
        });
        defer repeat.deinit();
        try std.testing.expectEqual(@as(i64, 8), (try field(repeat.report.value, "exit_status")).integer);
        try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, label, "finalize-crash"), .{
            .ordinary_operation = "upgrade_all",
            .ordinary_mode = "recover",
            .orchestration_id = @splat(17),
            .owner_evidence = proof,
            .acknowledgment = "ownership",
            .completion_crash = if (before_publish) "before_ownership_marker_clear" else "after_ownership_marker_clear",
        });
        for ([_][]const u8{ "finalize", "finalize-again" }) |phase| {
            var finished = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, label, phase), .{
                .ordinary_operation = "upgrade_all",
                .ordinary_mode = "recover",
                .orchestration_id = @splat(17),
                .owner_evidence = proof,
                .acknowledgment = "ownership",
            });
            defer finished.deinit();
            try std.testing.expectEqual(@as(i64, 0), (try field(finished.report.value, "exit_status")).integer);
        }
        try support.absent(fixture, owner_relative);
        for ([_][]const u8{ debz.native_provenance.document_path, debz.root_operation_completion.document_path, "var/lib/debz/root-operation-v1.json", "var/lib/debz/native-execution-intent-v1.json" }) |path|
            try support.absent(fixture, try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], path));
        try std.testing.expectEqualSlices(u8, before, try foundation.capture(fixture.allocator, fixture.io, scenario.native_root));
        const comparison = try support.path(fixture.allocator, label, "comparison");
        try fixture.directory(comparison);
        try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
        std.debug.print("ordinary reconciliation {s}: actual claim/finalize crashes preserved exact exclusion and dpkg root\n", .{label});
    };
}

fn ordinaryRecoveryBoundaries(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
    cli: []const u8,
) !void {
    for ([_][]const u8{
        "after_native_receipt",       "after_completed_record",    "after_owed_provenance_document",
        "after_provenance_published", "after_native_acknowledged",
    }) |boundary| {
        const name = try std.fmt.allocPrint(fixture.allocator, "executed/workflow-{s}", .{boundary});
        var scenario = try seededScenario(fixture, driver, helper, reference, arch, name, false);
        defer scenario.deinit();
        const selected: []const Selector = &.{ .{ .name = "scenario-main" }, .{ .name = "conffile-pkg" } };
        const reversed: []const Selector = &.{ .{ .name = "conffile-pkg" }, .{ .name = "scenario-main" } };
        const lock = try fixture.absolute(try support.path(fixture.allocator, name, "lock.json"));
        const cache = try fixture.absolute(try support.path(fixture.allocator, name, "cache"));
        const state = try fixture.absolute(try support.path(fixture.allocator, name, "state"));
        var plan = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "plan"), "install", "plan_only", selected, source, keyring, lock);
        defer plan.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(plan.report.value, "exit_status")).integer);
        try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "crash"), .{
            .ordinary_mode = "execute",
            .selectors = selected,
            .cache_path = cache,
            .state_path = state,
            .sources = &.{source},
            .keyrings = &.{keyring},
            .lock_input = lock,
            .completion_crash = boundary,
            .capture_evidence = true,
        });
        const operation_path = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], "var/lib/debz/root-operation-v1.json");
        const pending = try support.read(fixture, operation_path, 64 * 1024);
        const before = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
        if (std.mem.eql(u8, boundary, "after_native_receipt")) {
            const before_evidence = try projected.evidenceInventory(fixture, scenario.native_root, true);
            var deferred = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "deferred-without-owner"), .{
                .ordinary_mode = "recover",
                .selectors = reversed,
                .cache_path = try fixture.absolute(try support.path(fixture.allocator, name, "unused-cache")),
                .state_path = try fixture.absolute(try support.path(fixture.allocator, name, "unused-state")),
                .defer_recovery_clear = true,
            });
            defer deferred.deinit();
            try std.testing.expectEqual(@as(i64, 2), (try field(deferred.report.value, "exit_status")).integer);
            for ([_]struct { label: []const u8, operation: []const u8 = "install", selectors: []const Selector = reversed, recommends: bool = false, conffile: []const u8 = "keep_existing" }{
                .{ .label = "wrong-operation", .operation = "remove", .selectors = reversed },
                .{ .label = "wrong-selector", .operation = "install", .selectors = &.{.{ .name = "different" }} },
                .{ .label = "wrong-recommends", .recommends = true },
                .{ .label = "wrong-conffile", .conffile = "use_package_version" },
            }) |wrong| {
                var refused = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, wrong.label), .{
                    .ordinary_operation = wrong.operation,
                    .ordinary_mode = "recover",
                    .selectors = wrong.selectors,
                    .cache_path = try fixture.absolute(try support.path(fixture.allocator, name, "unused-cache")),
                    .state_path = try fixture.absolute(try support.path(fixture.allocator, name, "unused-state")),
                    .recommends = wrong.recommends,
                    .conffile = wrong.conffile,
                });
                defer refused.deinit();
                try std.testing.expectEqual(@as(i64, 8), (try field(refused.report.value, "exit_status")).integer);
                try std.testing.expectEqualSlices(u8, pending, try support.read(fixture, operation_path, 64 * 1024));
                try std.testing.expectEqualSlices(u8, before_evidence, try projected.evidenceInventory(fixture, scenario.native_root, true));
            }
            for ([_][]const u8{ "lock", "source", "keyring", "force" }) |replacement| {
                var refused = try workflow(fixture, driver, scenario.native_root, arch, try std.fmt.allocPrint(fixture.allocator, "{s}/replacement-{s}", .{ name, replacement }), .{
                    .ordinary_mode = "recover",
                    .selectors = reversed,
                    .cache_path = try fixture.absolute(try support.path(fixture.allocator, name, "unused-cache")),
                    .state_path = try fixture.absolute(try support.path(fixture.allocator, name, "unused-state")),
                    .lock_input = if (std.mem.eql(u8, replacement, "lock")) lock else null,
                    .sources = if (std.mem.eql(u8, replacement, "source")) &.{source} else &.{},
                    .keyrings = if (std.mem.eql(u8, replacement, "keyring")) &.{keyring} else &.{},
                    .force = if (std.mem.eql(u8, replacement, "force")) &.{"overwrite"} else &.{},
                });
                defer refused.deinit();
                try std.testing.expectEqual(@as(i64, 2), (try field(refused.report.value, "exit_status")).integer);
                try std.testing.expectEqualSlices(u8, pending, try support.read(fixture, operation_path, 64 * 1024));
                try std.testing.expectEqualSlices(u8, before_evidence, try projected.evidenceInventory(fixture, scenario.native_root, true));
            }
            try std.testing.expectEqualSlices(u8, pending, try support.read(fixture, operation_path, 64 * 1024));
        }
        var recovered = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "recover"), "install", "recover", reversed, source, keyring, lock);
        defer recovered.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(recovered.report.value, "exit_status")).integer);
        try std.testing.expect((try field(recovered.report.value, "changed")).bool);
        try std.testing.expectEqualSlices(u8, before, try foundation.capture(fixture.allocator, fixture.io, scenario.native_root));
        const root_relative = scenario.native_root[fixture.path.len + 1 ..];
        var receipt = try parse(fixture, try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path), 16 * 1024 * 1024);
        defer receipt.deinit();
        var completion = try parse(fixture, try support.path(fixture.allocator, root_relative, debz.root_operation_completion.document_path), 64 * 1024);
        defer completion.deinit();
        var locked = try parse(fixture, lock[fixture.path.len + 1 ..], 1024 * 1024);
        defer locked.deinit();
        try same(try string(receipt.value, "outcome"), "succeeded");
        try same(try string(receipt.value, "exact_lock_sha256"), try string(locked.value, "digest_sha256"));
        try same(try string(try field(completion.value, "transaction_provenance"), "document_sha256"), try string(receipt.value, "digest_sha256"));
        try support.absent(fixture, operation_path);
        try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-recovered"), true);
        const reference_name = try support.path(fixture.allocator, name, "reference-execute");
        try fixture.directory(reference_name);
        if (try support.reference(fixture, reference, scenario.reference_root, .{
            .operation = "install",
            .archives = &.{
                try archive(fixture, arch, "base-dep", "1.0-1"),
                try archive(fixture, arch, "scenario-main", "1.0-1"),
                try archive(fixture, arch, "conffile-pkg", "1.0-1"),
            },
            .triggers = true,
        }, reference_name) != 0) return error.ReferenceOrdinaryRecoveryFailed;
        const comparison = try support.path(fixture.allocator, name, "comparison");
        try fixture.directory(comparison);
        try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
        const receipt_bytes = try support.read(fixture, try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path), 16 * 1024 * 1024);
        var repeated = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "recover-again"), "install", "recover", reversed, source, keyring, lock);
        defer repeated.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(repeated.report.value, "exit_status")).integer);
        try std.testing.expect(!(try field(repeated.report.value, "changed")).bool);
        try std.testing.expectEqualSlices(u8, receipt_bytes, try support.read(fixture, try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path), 16 * 1024 * 1024));
        try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
        std.debug.print("ordinary workflow {s}: real crash, original-request recovery and pinned dpkg parity passed\n", .{boundary});
    }
}

fn ordinaryKnownFailure(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
    cli: []const u8,
) !void {
    const name = "executed/workflow-known-failure";
    var scenario = try seededScenario(fixture, driver, helper, reference, arch, name, false);
    defer scenario.deinit();
    const selectors: []const Selector = &.{ .{ .name = "scenario-main" }, .{ .name = "fail-script" } };
    const lock = try fixture.absolute("executed/workflow-known-failure/lock.json");
    var plan = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-known-failure/plan", "install", "plan_only", selectors, source, keyring, lock);
    defer plan.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(plan.report.value, "exit_status")).integer);
    var result = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-known-failure/execute", "install", "execute", selectors, source, keyring, lock);
    defer result.deinit();
    try ordinaryCompletion(fixture, scenario.native_root, result, lock, "failed");
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-known-failure/verify-failed", false);
    if (try referenceSingleFailure(fixture, reference, scenario.reference_root, arch, name) != 1) return error.ReferenceKnownFailureMissing;
    const comparison = try support.path(fixture.allocator, name, "comparison");
    try fixture.directory(comparison);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    const receipt_path = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], debz.native_provenance.document_path);
    const receipt = try support.read(fixture, receipt_path, 16 * 1024 * 1024);
    var recovered = try ordinaryWorkflow(fixture, driver, &scenario, "executed/workflow-known-failure/recover", "install", "recover", selectors, source, keyring, lock);
    defer recovered.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(recovered.report.value, "exit_status")).integer);
    try std.testing.expect(!(try field(recovered.report.value, "changed")).bool);
    try std.testing.expectEqualSlices(u8, receipt, try support.read(fixture, receipt_path, 16 * 1024 * 1024));
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, "executed/workflow-known-failure/verify-after-recover", false);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    std.debug.print("ordinary failed batch: receipt, no-op recovery and byte-exact single-invocation pinned dpkg parity passed\n", .{});
}

fn referenceSingleFailure(fixture: *foundation.Fixture, executable: []const u8, root: []const u8, arch: []const u8, name: []const u8) !u8 {
    var guarded = try foundation.guardedRoot(fixture.io, root);
    guarded.close(fixture.io);
    const reference_name = try support.path(fixture.allocator, name, "reference-single-install");
    try fixture.directory(reference_name);
    return support.runExit(fixture, &.{
        executable,                                                       "--force-not-root",                                 "--force-bad-path",
        try std.fmt.allocPrint(fixture.allocator, "--root={s}", .{root}), "--force-confold",                                  "--abort-after=1",
        "--install",                                                      try archive(fixture, arch, "fail-script", "1.0-1"), try archive(fixture, arch, "base-dep", "1.0-1"),
        try archive(fixture, arch, "scenario-main", "1.0-1"),
    }, try support.path(fixture.allocator, reference_name, "reference.log"));
}

fn ownedAbandon(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
) !void {
    for ([_]bool{ false, true }) |invalid_source| {
        const name = if (invalid_source) "executed/owned-abandon-preflight" else "executed/owned-abandon-unchanged";
        var scenario = try seededScenario(fixture, driver, helper, reference, arch, name, false);
        defer scenario.deinit();
        const operation: []const u8 = if (invalid_source) "install" else "upgrade_all";
        const selectors: []const Selector = if (invalid_source) &.{.{ .name = "scenario-main" }} else &.{};
        const lock = try fixture.absolute(try support.path(fixture.allocator, name, "lock.json"));
        const cache = try fixture.absolute(try support.path(fixture.allocator, name, "cache"));
        const state = try fixture.absolute(try support.path(fixture.allocator, name, "state"));
        var plan = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "plan"), operation, "plan_only", selectors, source, keyring, lock);
        defer plan.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(plan.report.value, "exit_status")).integer);
        var reserved = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "reserve"), .{
            .ordinary_operation = operation,
            .ordinary_mode = "reserve",
            .selectors = selectors,
            .cache_path = cache,
            .state_path = state,
            .sources = &.{source},
            .keyrings = &.{keyring},
            .lock_input = lock,
            .orchestration_id = @splat(17),
        });
        defer reserved.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(reserved.report.value, "exit_status")).integer);
        const root_relative = scenario.native_root[fixture.path.len + 1 ..];
        const owner = try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-deferred-ack-v1.json");
        const owner_path = try fixture.absolute(try support.path(fixture.allocator, name, "bound.owner.json"));
        try fixture.write(try support.path(fixture.allocator, name, "bound.owner.json"), try support.read(fixture, owner, 64 * 1024), 0o644);
        if (invalid_source) try fixture.write(try support.path(fixture.allocator, name, "invalid.sources"), "not-an-apt-source\n", 0o644);
        var executed = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "execute"), .{
            .ordinary_operation = operation,
            .ordinary_mode = "execute",
            .selectors = selectors,
            .cache_path = cache,
            .state_path = state,
            .sources = if (invalid_source) &.{try fixture.absolute(try support.path(fixture.allocator, name, "invalid.sources"))} else &.{source},
            .keyrings = &.{keyring},
            .lock_input = lock,
            .orchestration_id = @splat(17),
            .owner_evidence = owner_path,
            .capture_evidence = true,
        });
        defer executed.deinit();
        try std.testing.expectEqual(@as(i64, if (invalid_source) 2 else 0), (try field(executed.report.value, "exit_status")).integer);
        try std.testing.expect(!(try field(executed.report.value, "changed")).bool);
        var abandoned = try parse(fixture, owner, 64 * 1024);
        defer abandoned.deinit();
        try same(try string(abandoned.value, "state"), "abandoned");
        try support.absent(fixture, try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-v1.json"));
        const abandoned_path = try fixture.absolute(try support.path(fixture.allocator, name, "abandoned.owner.json"));
        try fixture.write(try support.path(fixture.allocator, name, "abandoned.owner.json"), try support.read(fixture, owner, 64 * 1024), 0o644);
        var finalized = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "finalize"), .{
            .ordinary_operation = operation,
            .ordinary_mode = "recover",
            .selectors = selectors,
            .cache_path = try fixture.absolute(try support.path(fixture.allocator, name, "unused-cache")),
            .state_path = try fixture.absolute(try support.path(fixture.allocator, name, "unused-state")),
            .orchestration_id = @splat(17),
            .owner_evidence = abandoned_path,
            .acknowledgment = "ownership",
        });
        defer finalized.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(finalized.report.value, "exit_status")).integer);
        try support.absent(fixture, owner);
        const comparison = try support.path(fixture.allocator, name, "comparison");
        try fixture.directory(comparison);
        try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
        std.debug.print("ordinary owned abandonment {s}: real owner handoff and unchanged pinned-dpkg state passed\n", .{name});
    }
}

const PendingProofCheck = struct {
    operation: []const u8 = "install",
    recommends: bool = false,
    state: []const u8 = "pending",
    outcome: []const u8 = "succeeded",
    expected_error: ?[]const u8 = null,
};

fn pendingOwnedProof(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    arch: []const u8,
    name: []const u8,
    label: []const u8,
    lock: []const u8,
    selectors: []const Selector,
    owner: []const u8,
    unused_cache: []const u8,
    unused_state: []const u8,
    check: PendingProofCheck,
) !void {
    const before = try projected.evidenceInventory(fixture, root, true);
    var verification = try workflow(fixture, driver, root, arch, try support.path(fixture.allocator, name, label), .{
        .ordinary_operation = check.operation,
        .ordinary_mode = "recover",
        .selectors = selectors,
        .cache_path = unused_cache,
        .state_path = unused_state,
        .orchestration_id = @splat(17),
        .owner_evidence = owner,
        .recommends = check.recommends,
        .owned_verification = .{ .lock_path = lock, .state = check.state, .outcome = check.outcome, .expected_error = check.expected_error },
    });
    defer verification.deinit();
    try std.testing.expectEqual(check.expected_error == null, (try field(verification.report.value, "verified")).bool);
    try std.testing.expectEqualSlices(u8, before, try projected.evidenceInventory(fixture, root, true));
}

fn ownedRecoveryBoundaries(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
    cli: []const u8,
) !void {
    const selected: []const Selector = &.{ .{ .name = "scenario-main" }, .{ .name = "conffile-pkg" } };
    const boundaries = [_]struct { execution: []const u8, acknowledgment: []const u8 }{
        .{ .execution = "after_native_receipt", .acknowledgment = "after_native_acknowledged" },
        .{ .execution = "after_completed_record", .acknowledgment = "after_deferred_acknowledged" },
        .{ .execution = "after_owed_provenance_document", .acknowledgment = "before_deferred_record_cleared" },
        .{ .execution = "after_provenance_published", .acknowledgment = "after_deferred_record_cleared" },
        .{ .execution = "after_native_acknowledged", .acknowledgment = "after_deferred_marker_cleared" },
    };
    for (boundaries) |boundary| {
        const name = try std.fmt.allocPrint(fixture.allocator, "executed/workflow-owned-{s}", .{boundary.execution});
        var scenario = try seededScenario(fixture, driver, helper, reference, arch, name, false);
        defer scenario.deinit();
        const lock = try fixture.absolute(try support.path(fixture.allocator, name, "lock.json"));
        const cache = try fixture.absolute(try support.path(fixture.allocator, name, "cache"));
        const state = try fixture.absolute(try support.path(fixture.allocator, name, "state"));
        const unused_cache = try fixture.absolute(try support.path(fixture.allocator, name, "unused-cache"));
        const unused_state = try fixture.absolute(try support.path(fixture.allocator, name, "unused-state"));
        var plan = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "plan"), "install", "plan_only", selected, source, keyring, lock);
        defer plan.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(plan.report.value, "exit_status")).integer);
        var reserved = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "reserve"), .{
            .ordinary_mode = "reserve",
            .selectors = selected,
            .sources = &.{source},
            .keyrings = &.{keyring},
            .cache_path = cache,
            .state_path = state,
            .lock_input = lock,
            .orchestration_id = @splat(17),
        });
        defer reserved.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(reserved.report.value, "exit_status")).integer);
        const root_relative = scenario.native_root[fixture.path.len + 1 ..];
        const owner = try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-deferred-ack-v1.json");
        const record = try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-v1.json");
        const receipt_path = try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path);
        const completion_path = try support.path(fixture.allocator, root_relative, debz.root_operation_completion.document_path);
        const bound_path = try fixture.absolute(try support.path(fixture.allocator, name, "bound.owner.json"));
        try fixture.write(try support.path(fixture.allocator, name, "bound.owner.json"), try support.read(fixture, owner, 64 * 1024), 0o644);
        try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "execute-crash"), .{
            .ordinary_mode = "execute",
            .selectors = selected,
            .sources = &.{source},
            .keyrings = &.{keyring},
            .cache_path = cache,
            .state_path = state,
            .lock_input = lock,
            .orchestration_id = @splat(17),
            .owner_evidence = bound_path,
            .completion_crash = boundary.execution,
        });
        const original_record = try support.read(fixture, record, 64 * 1024);
        var foreign = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "foreign-recover"), .{
            .ordinary_mode = "recover",
            .selectors = selected,
            .cache_path = unused_cache,
            .state_path = unused_state,
            .orchestration_id = @splat(18),
            .defer_recovery_clear = true,
            .owner_evidence = bound_path,
        });
        defer foreign.deinit();
        try std.testing.expectEqual(@as(i64, 8), (try field(foreign.report.value, "exit_status")).integer);
        try std.testing.expectEqualSlices(u8, original_record, try support.read(fixture, record, 64 * 1024));
        var recovery_owner = bound_path;
        if (std.mem.eql(u8, boundary.execution, "after_completed_record")) {
            try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "pending-publication-crash"), .{
                .ordinary_mode = "recover",
                .selectors = selected,
                .cache_path = unused_cache,
                .state_path = unused_state,
                .orchestration_id = @splat(17),
                .defer_recovery_clear = true,
                .owner_evidence = bound_path,
                .completion_crash = "after_owed_provenance_document",
            });
            const pending_pre_path = try support.path(fixture.allocator, name, "pending-prepublication.owner.json");
            try fixture.write(pending_pre_path, try support.read(fixture, owner, 64 * 1024), 0o644);
            recovery_owner = try fixture.absolute(pending_pre_path);
            var pending_pre = try parse(fixture, owner, 64 * 1024);
            defer pending_pre.deinit();
            try same(try string(pending_pre.value, "state"), "pending");
            var unpublished = try parse(fixture, record, 64 * 1024);
            defer unpublished.deinit();
            try same(try string(unpublished.value, "provenance"), "pending");
            try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-unpublished", lock, selected, recovery_owner, unused_cache, unused_state, .{ .expected_error = "InvalidCompletion" });
        }
        var recovered = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "recover"), .{
            .ordinary_mode = "recover",
            .selectors = selected,
            .cache_path = unused_cache,
            .state_path = unused_state,
            .orchestration_id = @splat(17),
            .defer_recovery_clear = true,
            .owner_evidence = recovery_owner,
        });
        defer recovered.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(recovered.report.value, "exit_status")).integer);
        const pending_path = try support.path(fixture.allocator, name, "pending.owner.json");
        try fixture.write(pending_path, try support.read(fixture, owner, 64 * 1024), 0o644);
        const pending_file = try fixture.absolute(pending_path);
        var pending = try parse(fixture, owner, 64 * 1024);
        defer pending.deinit();
        try same(try string(pending.value, "state"), "pending");
        const published_record = try support.read(fixture, record, 64 * 1024);
        var repeated = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "recover-again"), .{
            .ordinary_mode = "recover",
            .selectors = selected,
            .cache_path = unused_cache,
            .state_path = unused_state,
            .orchestration_id = @splat(17),
            .defer_recovery_clear = true,
            .owner_evidence = pending_file,
        });
        defer repeated.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(repeated.report.value, "exit_status")).integer);
        try std.testing.expectEqualSlices(u8, published_record, try support.read(fixture, record, 64 * 1024));
        var locked = try parse(fixture, lock[fixture.path.len + 1 ..], 1024 * 1024);
        defer locked.deinit();
        var receipt = try parse(fixture, receipt_path, 16 * 1024 * 1024);
        defer receipt.deinit();
        var completion = try parse(fixture, completion_path, 64 * 1024);
        defer completion.deinit();
        try same(try string(receipt.value, "outcome"), "succeeded");
        try same(try string(receipt.value, "exact_lock_sha256"), try string(locked.value, "digest_sha256"));
        try same(try string(try field(completion.value, "transaction_provenance"), "document_sha256"), try string(receipt.value, "digest_sha256"));
        const proof_before = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
        var proof = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "verify-pending"), .{
            .ordinary_mode = "recover",
            .selectors = selected,
            .cache_path = unused_cache,
            .state_path = unused_state,
            .orchestration_id = @splat(17),
            .owner_evidence = pending_file,
            .owned_verification = .{ .lock_path = lock, .state = "pending" },
        });
        defer proof.deinit();
        try std.testing.expect((try field(proof.report.value, "verified")).bool);
        try std.testing.expectEqualSlices(u8, proof_before, try foundation.capture(fixture.allocator, fixture.io, scenario.native_root));
        try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-success-as-failure", lock, selected, pending_file, unused_cache, unused_state, .{ .outcome = "failed", .expected_error = "TransactionNotFailed" });
        try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-pending-as-released", lock, selected, pending_file, unused_cache, unused_state, .{ .state = "released", .expected_error = "ReleasedOwnerRequired" });
        try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-pending"), false);
        if (std.mem.eql(u8, boundary.execution, "after_native_receipt")) {
            try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-bound-owner", lock, selected, bound_path, unused_cache, unused_state, .{ .expected_error = "PendingOwnerRequired" });
            try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-wrong-operation", lock, selected, pending_file, unused_cache, unused_state, .{ .operation = "remove", .expected_error = "InvalidCompletion" });
            try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-wrong-request", lock, &.{.{ .name = "different" }}, pending_file, unused_cache, unused_state, .{ .expected_error = "InvalidCompletion" });
            try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-wrong-policy", lock, selected, pending_file, unused_cache, unused_state, .{ .recommends = true, .expected_error = "InvalidCompletion" });
            const evidence_root = scenario.native_root[fixture.path.len + 1 ..];
            for ([_]struct { label: []const u8, relative: []const u8 }{
                .{ .label = "intent", .relative = "native-execution-intent-v1.json" },
                .{ .label = "progress", .relative = "native-execution-progress-v1.log" },
                .{ .label = "authorization", .relative = "native-transaction-authorization-v2.json" },
                .{ .label = "program", .relative = "native-transaction-program-v2.json" },
                .{ .label = "triggers", .relative = "native-trigger-events-v1.json" },
                .{ .label = "managed", .relative = "native-managed-state-v1.json" },
            }) |damage| {
                const path = try support.path(fixture.allocator, evidence_root, try support.path(fixture.allocator, "var/lib/debz", damage.relative));
                const original = try support.read(fixture, path, 16 * 1024 * 1024);
                try fixture.write(path, "{}\n", 0o644);
                try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, try std.fmt.allocPrint(fixture.allocator, "verify-damaged-{s}", .{damage.label}), lock, selected, pending_file, unused_cache, unused_state, .{ .expected_error = "EvidenceChanged" });
                try fixture.write(path, original, 0o644);
            }
            const progress_path = try support.path(fixture.allocator, evidence_root, "var/lib/debz/native-execution-progress-v1.log");
            const progress_bytes = try support.read(fixture, progress_path, 16 * 1024 * 1024);
            try fixture.dir.deleteFile(fixture.io, progress_path);
            try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-partial-acknowledgment", lock, selected, pending_file, unused_cache, unused_state, .{});
            try fixture.write(progress_path, progress_bytes, 0o644);
            const completion_bytes = try support.read(fixture, completion_path, 64 * 1024);
            try fixture.write(completion_path, "{}\n", 0o644);
            try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-damaged-completion", lock, selected, pending_file, unused_cache, unused_state, .{ .expected_error = "NonCanonicalDocument" });
            try fixture.write(completion_path, completion_bytes, 0o644);
            for ([_]struct { label: []const u8, relative: []const u8 }{
                .{ .label = "script", .relative = "native-lifecycle-script-v1.json" },
                .{ .label = "trigger-authority", .relative = "native-trigger-authority-v1.json" },
                .{ .label = "foreign-outcome", .relative = "native-script-outcome-v1-foreign.json" },
                .{ .label = "staging", .relative = ".debz-native-foreign" },
            }) |unresolved| {
                const path = try support.path(fixture.allocator, evidence_root, try support.path(fixture.allocator, "var/lib/debz", unresolved.relative));
                try support.absent(fixture, path);
                try fixture.write(path, "{}\n", 0o644);
                try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, try std.fmt.allocPrint(fixture.allocator, "verify-unresolved-{s}", .{unresolved.label}), lock, selected, pending_file, unused_cache, unused_state, .{ .expected_error = "UnresolvedNativeEvidence" });
                try fixture.dir.deleteFile(fixture.io, path);
            }
            const original_receipt = try support.read(fixture, receipt_path, 16 * 1024 * 1024);
            try fixture.write(receipt_path, "{}\n", 0o644);
            try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-damaged-receipt", lock, selected, pending_file, unused_cache, unused_state, .{ .expected_error = "MissingField" });
            var damaged_ack = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "acknowledge-damaged-receipt"), .{
                .ordinary_mode = "recover",
                .selectors = selected,
                .cache_path = unused_cache,
                .state_path = unused_state,
                .orchestration_id = @splat(17),
                .defer_recovery_clear = true,
                .owner_evidence = pending_file,
                .acknowledgment = "recovery",
            });
            defer damaged_ack.deinit();
            try std.testing.expectEqual(@as(i64, 8), (try field(damaged_ack.report.value, "exit_status")).integer);
            try std.testing.expectEqualSlices(u8, published_record, try support.read(fixture, record, 64 * 1024));
            try std.testing.expectEqualSlices(u8, try support.read(fixture, pending_path, 64 * 1024), try support.read(fixture, owner, 64 * 1024));
            try fixture.write(receipt_path, original_receipt, 0o644);
            var wrong_ack = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "acknowledge-wrong-operation"), .{
                .ordinary_operation = "remove",
                .ordinary_mode = "recover",
                .selectors = selected,
                .cache_path = unused_cache,
                .state_path = unused_state,
                .orchestration_id = @splat(17),
                .defer_recovery_clear = true,
                .owner_evidence = pending_file,
                .acknowledgment = "recovery",
            });
            defer wrong_ack.deinit();
            try std.testing.expectEqual(@as(i64, 8), (try field(wrong_ack.report.value, "exit_status")).integer);
            try std.testing.expectEqualSlices(u8, published_record, try support.read(fixture, record, 64 * 1024));
        }
        var foreign_ack = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "foreign-acknowledgment"), .{
            .ordinary_mode = "recover",
            .selectors = selected,
            .cache_path = unused_cache,
            .state_path = unused_state,
            .orchestration_id = @splat(18),
            .defer_recovery_clear = true,
            .owner_evidence = pending_file,
            .acknowledgment = "recovery",
        });
        defer foreign_ack.deinit();
        try std.testing.expectEqual(@as(i64, 2), (try field(foreign_ack.report.value, "exit_status")).integer);
        try std.testing.expectEqualSlices(u8, published_record, try support.read(fixture, record, 64 * 1024));
        const reference_log = try support.path(fixture.allocator, name, "reference-install");
        try fixture.directory(reference_log);
        if (try support.reference(fixture, reference, scenario.reference_root, .{
            .operation = "install",
            .archives = &.{ try archive(fixture, arch, "base-dep", "1.0-1"), try archive(fixture, arch, "scenario-main", "1.0-1"), try archive(fixture, arch, "conffile-pkg", "1.0-1") },
            .triggers = true,
        }, reference_log) != 0) return error.ReferenceOwnedRecoveryFailed;
        const comparison = try support.path(fixture.allocator, name, "comparison");
        try fixture.directory(comparison);
        try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
        const receipt_bytes = try support.read(fixture, receipt_path, 16 * 1024 * 1024);
        try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "acknowledgment-crash"), .{
            .ordinary_mode = "recover",
            .selectors = selected,
            .cache_path = unused_cache,
            .state_path = unused_state,
            .orchestration_id = @splat(17),
            .defer_recovery_clear = true,
            .owner_evidence = pending_file,
            .acknowledgment = "recovery",
            .completion_crash = boundary.acknowledgment,
        });
        if (std.mem.eql(u8, boundary.acknowledgment, "after_native_acknowledged")) {
            try pendingOwnedProof(fixture, driver, scenario.native_root, arch, name, "verify-native-acknowledged", lock, selected, pending_file, unused_cache, unused_state, .{});
            try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-native-acknowledged"), false);
        }
        for ([_][]const u8{ "acknowledge", "acknowledge-again" }) |phase| {
            var acknowledgment = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, phase), .{
                .ordinary_mode = "recover",
                .selectors = selected,
                .cache_path = unused_cache,
                .state_path = unused_state,
                .orchestration_id = @splat(17),
                .defer_recovery_clear = true,
                .owner_evidence = pending_file,
                .acknowledgment = "recovery",
            });
            defer acknowledgment.deinit();
            try std.testing.expectEqual(@as(i64, 0), (try field(acknowledgment.report.value, "exit_status")).integer);
        }
        try support.absent(fixture, owner);
        try support.absent(fixture, record);
        try support.absent(fixture, try support.path(fixture.allocator, root_relative, "var/lib/debz/native-execution-intent-v1.json"));
        try std.testing.expectEqualSlices(u8, receipt_bytes, try support.read(fixture, receipt_path, 16 * 1024 * 1024));
        try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-finalized"), true);
        try support.absent(fixture, try support.path(fixture.allocator, name, "unused-cache"));
        try support.absent(fixture, try support.path(fixture.allocator, name, "unused-state"));
        try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
        std.debug.print("ordinary owned {s}: real execution/acknowledgment crashes, pending owner proof and pinned-dpkg parity passed\n", .{boundary.execution});
    }
}

fn ownedKnownFailure(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
    cli: []const u8,
) !void {
    const name = "executed/workflow-owned-known-failure";
    var scenario = try seededScenario(fixture, driver, helper, reference, arch, name, false);
    defer scenario.deinit();
    const selected: []const Selector = &.{ .{ .name = "scenario-main" }, .{ .name = "fail-script" } };
    const lock = try fixture.absolute("executed/workflow-owned-known-failure/lock.json");
    const cache = try fixture.absolute("executed/workflow-owned-known-failure/cache");
    const state = try fixture.absolute("executed/workflow-owned-known-failure/state");
    const unused_cache = try fixture.absolute("executed/workflow-owned-known-failure/unused-cache");
    const unused_state = try fixture.absolute("executed/workflow-owned-known-failure/unused-state");
    var plan = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "plan"), "install", "plan_only", selected, source, keyring, lock);
    defer plan.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(plan.report.value, "exit_status")).integer);
    var reserve = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "reserve"), .{
        .ordinary_mode = "reserve",
        .selectors = selected,
        .sources = &.{source},
        .keyrings = &.{keyring},
        .cache_path = cache,
        .state_path = state,
        .lock_input = lock,
        .orchestration_id = @splat(17),
    });
    defer reserve.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(reserve.report.value, "exit_status")).integer);
    const root_relative = scenario.native_root[fixture.path.len + 1 ..];
    const owner = try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-deferred-ack-v1.json");
    const record = try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-v1.json");
    const receipt_path = try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path);
    const status_path = try support.path(fixture.allocator, root_relative, "var/lib/dpkg/status");
    const intent_path = try support.path(fixture.allocator, root_relative, "var/lib/debz/native-execution-intent-v1.json");
    const bound_path = try fixture.absolute(try support.path(fixture.allocator, name, "bound.owner.json"));
    try fixture.write(try support.path(fixture.allocator, name, "bound.owner.json"), try support.read(fixture, owner, 64 * 1024), 0o644);
    try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "pending-publication-crash"), .{
        .ordinary_mode = "execute",
        .selectors = selected,
        .sources = &.{source},
        .keyrings = &.{keyring},
        .cache_path = cache,
        .state_path = state,
        .lock_input = lock,
        .orchestration_id = @splat(17),
        .owner_evidence = bound_path,
        .completion_crash = "after_owed_provenance_document",
    });
    var unpublished = try parse(fixture, record, 64 * 1024);
    defer unpublished.deinit();
    try same(try string(unpublished.value, "outcome"), "failed_after_mutation");
    try same(try string(unpublished.value, "provenance"), "pending");
    const pending_path = try support.path(fixture.allocator, name, "pending.owner.json");
    try fixture.write(pending_path, try support.read(fixture, owner, 64 * 1024), 0o644);
    const pending_file = try fixture.absolute(pending_path);
    var pending = try parse(fixture, owner, 64 * 1024);
    defer pending.deinit();
    try same(try string(pending.value, "state"), "pending");
    var before_publication = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "verify-unpublished"), .{
        .ordinary_mode = "recover",
        .selectors = selected,
        .cache_path = unused_cache,
        .state_path = unused_state,
        .orchestration_id = @splat(17),
        .owner_evidence = pending_file,
        .owned_verification = .{ .lock_path = lock, .state = "pending", .outcome = "failed", .expected_error = "InvalidCompletion" },
    });
    defer before_publication.deinit();
    try std.testing.expect(!(try field(before_publication.report.value, "verified")).bool);
    var recovery = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "recover"), .{
        .ordinary_mode = "recover",
        .selectors = selected,
        .cache_path = unused_cache,
        .state_path = unused_state,
        .orchestration_id = @splat(17),
        .defer_recovery_clear = true,
        .owner_evidence = pending_file,
    });
    defer recovery.deinit();
    try std.testing.expectEqual(@as(i64, 7), (try field(recovery.report.value, "exit_status")).integer);
    const original_record = try support.read(fixture, record, 64 * 1024);
    const original_receipt = try support.read(fixture, receipt_path, 16 * 1024 * 1024);
    const original_status = try support.read(fixture, status_path, 1024 * 1024);
    const original_intent = try support.read(fixture, intent_path, 64 * 1024);
    try std.testing.expect(std.mem.indexOf(u8, original_status, "Status: install ok half-configured") != null);
    const replacement = std.mem.indexOf(u8, original_status, "Version: 1.0-1") orelse return error.MissingFailureStatusVersion;
    for ([_]struct { name: []const u8, outcome: []const u8, selectors: []const Selector, expected_error: ?[]const u8 }{
        .{ .name = "success-not-failure", .outcome = "succeeded", .selectors = selected, .expected_error = "TransactionNotSuccessful" },
        .{ .name = "failed-proof", .outcome = "failed", .selectors = selected, .expected_error = null },
        .{ .name = "failed-proof-again", .outcome = "failed", .selectors = selected, .expected_error = null },
        .{ .name = "wrong-request", .outcome = "failed", .selectors = &.{.{ .name = "different" }}, .expected_error = "InvalidCompletion" },
    }) |item| {
        var proof = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, item.name), .{
            .ordinary_mode = "recover",
            .selectors = item.selectors,
            .cache_path = unused_cache,
            .state_path = unused_state,
            .orchestration_id = @splat(17),
            .owner_evidence = pending_file,
            .owned_verification = .{ .lock_path = lock, .state = "pending", .outcome = item.outcome, .expected_error = item.expected_error },
        });
        defer proof.deinit();
        try std.testing.expectEqual(item.expected_error == null, (try field(proof.report.value, "verified")).bool);
    }
    for ([_]struct { name: []const u8, path: []const u8, replacement: []const u8, expected_error: []const u8 }{
        .{ .name = "changed-database", .path = status_path, .replacement = try std.mem.concat(fixture.allocator, u8, &.{
            original_status[0..replacement], "Version: 1.0-2", original_status[replacement + "Version: 1.0-1".len ..],
        }), .expected_error = "FinalStateMismatch" },
        .{ .name = "changed-intent", .path = intent_path, .replacement = "{}\n", .expected_error = "EvidenceChanged" },
    }) |item| {
        const original = if (std.mem.eql(u8, item.path, status_path)) original_status else original_intent;
        try fixture.write(item.path, item.replacement, 0o644);
        var refused = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, item.name), .{
            .ordinary_mode = "recover",
            .selectors = selected,
            .cache_path = unused_cache,
            .state_path = unused_state,
            .orchestration_id = @splat(17),
            .owner_evidence = pending_file,
            .owned_verification = .{ .lock_path = lock, .state = "pending", .outcome = "failed", .expected_error = item.expected_error },
        });
        defer refused.deinit();
        try std.testing.expect(!(try field(refused.report.value, "verified")).bool);
        try fixture.write(item.path, original, 0o644);
        try std.testing.expectEqualSlices(u8, original_record, try support.read(fixture, record, 64 * 1024));
    }
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-pending-failure"), false);
    if (try referenceSingleFailure(fixture, reference, scenario.reference_root, arch, name) != 1) return error.ReferenceOwnedFailureNotReproduced;
    const comparison = try support.path(fixture.allocator, name, "comparison");
    try fixture.directory(comparison);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "acknowledgment-crash"), .{
        .ordinary_mode = "recover",
        .selectors = selected,
        .cache_path = unused_cache,
        .state_path = unused_state,
        .orchestration_id = @splat(17),
        .defer_recovery_clear = true,
        .owner_evidence = pending_file,
        .acknowledgment = "recovery",
        .completion_crash = "after_native_acknowledged",
    });
    var after_crash = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "verify-after-acknowledgment-crash"), .{
        .ordinary_mode = "recover",
        .selectors = selected,
        .cache_path = unused_cache,
        .state_path = unused_state,
        .orchestration_id = @splat(17),
        .owner_evidence = pending_file,
        .owned_verification = .{ .lock_path = lock, .state = "pending", .outcome = "failed" },
    });
    defer after_crash.deinit();
    try std.testing.expect((try field(after_crash.report.value, "verified")).bool);
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-failed-acknowledgment"), false);
    var acknowledged = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "acknowledge"), .{
        .ordinary_mode = "recover",
        .selectors = selected,
        .cache_path = unused_cache,
        .state_path = unused_state,
        .orchestration_id = @splat(17),
        .defer_recovery_clear = true,
        .owner_evidence = pending_file,
        .acknowledgment = "recovery",
    });
    defer acknowledged.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(acknowledged.report.value, "exit_status")).integer);
    try support.absent(fixture, owner);
    try support.absent(fixture, record);
    try support.absent(fixture, intent_path);
    try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-final-failure"), false);
    try std.testing.expectEqualSlices(u8, original_receipt, try support.read(fixture, receipt_path, 16 * 1024 * 1024));
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    std.debug.print("ordinary owned failed receipt: unpublished refusal, status/intent corruption, honest failure acknowledgment and byte-exact single-invocation dpkg parity passed\n", .{});
}

fn ownedFinalizationBoundaries(
    fixture: *foundation.Fixture,
    driver: []const u8,
    helper: []const u8,
    reference: []const u8,
    arch: []const u8,
    source: []const u8,
    keyring: []const u8,
    cli: []const u8,
) !void {
    const selected: []const Selector = &.{ .{ .name = "scenario-main" }, .{ .name = "conffile-pkg" } };
    for ([_][]const u8{ "after_provenance_published", "after_ownership_terminal_publish", "after_ownership_record_clear" }) |boundary| {
        const name = try std.fmt.allocPrint(fixture.allocator, "executed/workflow-finalize-{s}", .{boundary});
        var scenario = try seededScenario(fixture, driver, helper, reference, arch, name, false);
        defer scenario.deinit();
        const lock = try fixture.absolute(try support.path(fixture.allocator, name, "lock.json"));
        const cache = try fixture.absolute(try support.path(fixture.allocator, name, "cache"));
        const state = try fixture.absolute(try support.path(fixture.allocator, name, "state"));
        const unused_cache = try fixture.absolute(try support.path(fixture.allocator, name, "unused-cache"));
        const unused_state = try fixture.absolute(try support.path(fixture.allocator, name, "unused-state"));
        var planned = try ordinaryWorkflow(fixture, driver, &scenario, try support.path(fixture.allocator, name, "plan"), "install", "plan_only", selected, source, keyring, lock);
        defer planned.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(planned.report.value, "exit_status")).integer);
        var reserve = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "reserve"), .{
            .ordinary_mode = "reserve",
            .selectors = selected,
            .sources = &.{source},
            .keyrings = &.{keyring},
            .cache_path = cache,
            .state_path = state,
            .lock_input = lock,
            .orchestration_id = @splat(17),
        });
        defer reserve.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(reserve.report.value, "exit_status")).integer);
        const root_relative = scenario.native_root[fixture.path.len + 1 ..];
        const owner = try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-deferred-ack-v1.json");
        const bound_path = try support.path(fixture.allocator, name, "bound.owner.json");
        try fixture.write(bound_path, try support.read(fixture, owner, 64 * 1024), 0o644);
        try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "execute-crash"), .{
            .ordinary_mode = "execute",
            .selectors = selected,
            .sources = &.{source},
            .keyrings = &.{keyring},
            .cache_path = cache,
            .state_path = state,
            .lock_input = lock,
            .orchestration_id = @splat(17),
            .owner_evidence = try fixture.absolute(bound_path),
            .completion_crash = boundary,
        });
        const retained_path = try support.path(fixture.allocator, name, "terminal.owner.json");
        const retained_bytes = try support.read(fixture, owner, 64 * 1024);
        try fixture.write(retained_path, retained_bytes, 0o644);
        const retained_file = try fixture.absolute(retained_path);
        var retained = try parse(fixture, owner, 64 * 1024);
        defer retained.deinit();
        try same(try string(retained.value, "state"), if (std.mem.eql(u8, boundary, "after_provenance_published")) "bound" else "released");
        const completion_path = try support.path(fixture.allocator, root_relative, debz.root_operation_completion.document_path);
        const receipt_path = try support.path(fixture.allocator, root_relative, debz.native_provenance.document_path);
        const receipt_before = try support.read(fixture, receipt_path, 16 * 1024 * 1024);
        const status_path = try support.path(fixture.allocator, root_relative, "var/lib/dpkg/status");
        const status_before = try support.read(fixture, status_path, 1024 * 1024);
        try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-owner-retained"), false);
        if (std.mem.eql(u8, boundary, "after_provenance_published")) {
            const original_completion = try support.read(fixture, completion_path, 64 * 1024);
            try fixture.write(completion_path, "{}\n", 0o644);
            var refused = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "damaged-completion"), .{
                .ordinary_mode = "recover",
                .selectors = selected,
                .cache_path = unused_cache,
                .state_path = unused_state,
                .orchestration_id = @splat(17),
                .owner_evidence = retained_file,
                .acknowledgment = "ownership",
            });
            defer refused.deinit();
            try std.testing.expectEqual(@as(i64, 8), (try field(refused.report.value, "exit_status")).integer);
            try std.testing.expectEqualSlices(u8, retained_bytes, try support.read(fixture, owner, 64 * 1024));
            try fixture.write(completion_path, original_completion, 0o644);
            try workflowCrash(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "finalize-crash"), .{
                .ordinary_mode = "recover",
                .selectors = selected,
                .cache_path = unused_cache,
                .state_path = unused_state,
                .orchestration_id = @splat(17),
                .owner_evidence = retained_file,
                .acknowledgment = "ownership",
                .completion_crash = "after_native_acknowledged",
            });
        } else {
            const before_proof = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
            var proof = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "verify-terminal-owner"), .{
                .ordinary_mode = "recover",
                .selectors = selected,
                .cache_path = unused_cache,
                .state_path = unused_state,
                .orchestration_id = @splat(17),
                .owner_evidence = retained_file,
                .owned_verification = .{ .lock_path = lock, .state = "released" },
            });
            defer proof.deinit();
            try std.testing.expect((try field(proof.report.value, "verified")).bool);
            try std.testing.expectEqualSlices(u8, before_proof, try foundation.capture(fixture.allocator, fixture.io, scenario.native_root));
            if (std.mem.eql(u8, boundary, "after_ownership_record_clear")) {
                const first_owner = "executed/workflow-owned-success/released.owner.json";
                var foreign = try parse(fixture, first_owner, 64 * 1024);
                defer foreign.deinit();
                if (std.mem.eql(u8, try string(foreign.value, "attempt_id"), try string(retained.value, "attempt_id")))
                    return error.ForeignAttemptNotDistinct;
                try fixture.write(owner, try support.read(fixture, first_owner, 64 * 1024), 0o644);
                const foreign_evidence = try projected.evidenceInventory(fixture, scenario.native_root, true);
                var foreign_proof = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "verify-terminal-foreign-attempt"), .{
                    .ordinary_mode = "recover",
                    .selectors = selected,
                    .cache_path = unused_cache,
                    .state_path = unused_state,
                    .orchestration_id = @splat(17),
                    .owner_evidence = try fixture.absolute(first_owner),
                    .owned_verification = .{ .lock_path = lock, .state = "released", .expected_error = "InvalidCompletion" },
                });
                defer foreign_proof.deinit();
                try std.testing.expect(!(try field(foreign_proof.report.value, "verified")).bool);
                try std.testing.expectEqualSlices(u8, foreign_evidence, try projected.evidenceInventory(fixture, scenario.native_root, true));
                try fixture.write(owner, retained_bytes, 0o644);
            }
            var deferred = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "defer-owner"), .{
                .ordinary_mode = "recover",
                .selectors = selected,
                .cache_path = unused_cache,
                .state_path = unused_state,
                .orchestration_id = @splat(17),
                .owner_evidence = retained_file,
                .defer_recovery_clear = true,
            });
            defer deferred.deinit();
            try std.testing.expectEqual(@as(i64, if (std.mem.eql(u8, boundary, "after_ownership_record_clear")) 8 else 0), (try field(deferred.report.value, "exit_status")).integer);
        }
        for ([_][]const u8{ "finalize", "finalize-again" }) |phase| {
            var finalized = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, phase), .{
                .ordinary_mode = "recover",
                .selectors = selected,
                .cache_path = unused_cache,
                .state_path = unused_state,
                .orchestration_id = @splat(17),
                .owner_evidence = retained_file,
                .acknowledgment = "ownership",
            });
            defer finalized.deinit();
            try std.testing.expectEqual(@as(i64, 0), (try field(finalized.report.value, "exit_status")).integer);
        }
        try support.absent(fixture, owner);
        try support.absent(fixture, try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-v1.json"));
        try support.absent(fixture, try support.path(fixture.allocator, root_relative, "var/lib/debz/native-execution-intent-v1.json"));
        try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, "verify-public-finalized"), true);
        try std.testing.expectEqualSlices(u8, status_before, try support.read(fixture, status_path, 1024 * 1024));
        try std.testing.expectEqualSlices(u8, receipt_before, try support.read(fixture, receipt_path, 16 * 1024 * 1024));
        var completion = try parse(fixture, completion_path, 64 * 1024);
        defer completion.deinit();
        var receipt = try parse(fixture, receipt_path, 16 * 1024 * 1024);
        defer receipt.deinit();
        var locked = try parse(fixture, lock[fixture.path.len + 1 ..], 1024 * 1024);
        defer locked.deinit();
        try same(try string(receipt.value, "exact_lock_sha256"), try string(locked.value, "digest_sha256"));
        try same(try string(try field(completion.value, "transaction_provenance"), "document_sha256"), try string(receipt.value, "digest_sha256"));
        const reference_log = try support.path(fixture.allocator, name, "reference-install");
        try fixture.directory(reference_log);
        if (try support.reference(fixture, reference, scenario.reference_root, .{
            .operation = "install",
            .archives = &.{ try archive(fixture, arch, "base-dep", "1.0-1"), try archive(fixture, arch, "scenario-main", "1.0-1"), try archive(fixture, arch, "conffile-pkg", "1.0-1") },
            .triggers = true,
        }, reference_log) != 0) return error.ReferenceOwnedFinalizeFailed;
        const comparison = try support.path(fixture.allocator, name, "comparison");
        try fixture.directory(comparison);
        try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
        std.debug.print("ordinary finalization {s}: real terminal crash, exact owner cleanup and pinned-dpkg parity passed\n", .{boundary});
    }
}

fn missingHelper(fixture: *foundation.Fixture, driver: []const u8, reference: []const u8, arch: []const u8) !void {
    var scenario = try support.Scenario.init(fixture, "executed/missing-helper", driver, reference, arch, false);
    defer scenario.deinit();
    try scenario.seed(try archive(fixture, arch, "essential-core", "1.0-1"));
    const helper = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], "usr/bin/dpkg-trigger");
    try support.absent(fixture, helper);
    try inspectInstalledFamily(fixture, driver, scenario.native_root, arch, "executed/missing-helper-inspection", "essential-core", true, true);
    const status = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], "var/lib/dpkg/status");
    const original = try support.read(fixture, status, 1024 * 1024);
    const lock = try fixture.absolute("executed/missing-helper.lock.json");
    const source = try fixture.absolute("executed/workflow.sources");
    const keyring = try fixture.absolute("executed/repository/fixture-keyring.gpg");
    var planned = try workflow(fixture, driver, scenario.native_root, arch, "executed/missing-helper-plan", .{
        .family_execution = try signedRequest(fixture, scenario.native_root, arch, "resolve_lock", "scenario-main", source, keyring, lock),
        .capture_evidence = true,
    });
    defer planned.deinit();
    try expectFamily(planned.report.value, "resolve_lock", true);
    var refused = try workflow(fixture, driver, scenario.native_root, arch, "executed/missing-helper-refused", .{
        .family_execution = try signedRequest(fixture, scenario.native_root, arch, "create", "scenario-main", source, keyring, lock),
        .capture_evidence = true,
    });
    defer refused.deinit();
    try expectFamily(refused.report.value, "create", false);
    try std.testing.expect(!(try field(refused.report.value, "changed")).bool);
    try std.testing.expectEqual(.null, try field(refused.report.value, "provenance_path"));
    const diagnostic = try string(try field(refused.report.value, "diagnostic"), "message");
    if (std.ascii.indexOfIgnoreCase(diagnostic, "helper") == null) return error.MissingHelperDiagnostic;
    try std.testing.expectEqual(.null, try field(refused.evidence.?.value, "native_completion"));
    try support.absent(fixture, helper);
    try support.absent(fixture, try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], debz.native_provenance.document_path));
    try std.testing.expectEqualSlices(u8, original, try support.read(fixture, status, 1024 * 1024));
    std.debug.print("family missing helper: real signed plan refused execution before status mutation\n", .{});
}

fn failedTransaction(fixture: *foundation.Fixture, driver: []const u8, reference: []const u8, arch: []const u8, update: bool) !void {
    const label: []const u8 = if (update) "failed-update" else "failed-customize";
    const name = try std.fmt.allocPrint(fixture.allocator, "executed/{s}", .{label});
    var scenario = try support.Scenario.init(fixture, name, driver, reference, arch, true);
    defer scenario.deinit();
    try scenario.seed(try archive(fixture, arch, "native-helper-target", "1.0-1"));
    try scenario.seed(try archive(fixture, arch, "essential-core", "1.0-1"));
    if (update) {
        const old = try support.makePackage(fixture, arch, "0.1-1", "fail-script", "executed/old-fail-script", .{ .no_scripts = true });
        try scenario.seed(old);
    }
    const lock = try fixture.absolute(try support.path(fixture.allocator, name, "lock.json"));
    const source = try fixture.absolute("executed/workflow.sources");
    const keyring = try fixture.absolute("executed/repository/fixture-keyring.gpg");
    const plan_request = try signedRequest(fixture, scenario.native_root, arch, "resolve_lock", "fail-script", source, keyring, lock);
    var plan = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "plan"), .{
        .family_execution = plan_request,
        .family_update_planning = update,
        .capture_evidence = true,
    });
    defer plan.deinit();
    try expectFamily(plan.report.value, "resolve_lock", true);
    var request = try signedRequest(fixture, scenario.native_root, arch, if (update) "update" else "customize", "fail-script", source, keyring, lock);
    var failed = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "execute"), .{
        .family_execution = request,
        .capture_evidence = true,
    });
    defer failed.deinit();
    try expectFamily(failed.report.value, request.operation, false);
    try same(try string(failed.report.value, "exit_status"), "transaction");
    try std.testing.expect((try field(failed.report.value, "changed")).bool);
    try std.testing.expect((try field(try field(failed.report.value, "diagnostic"), "recoverable")).bool);
    const receipt_relative = try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], debz.native_provenance.document_path);
    var receipt = try parse(fixture, receipt_relative, 16 * 1024 * 1024);
    defer receipt.deinit();
    try same(try string(receipt.value, "outcome"), "failed");
    var completion = try parse(fixture, try support.path(fixture.allocator, scenario.native_root[fixture.path.len + 1 ..], debz.root_operation_completion.document_path), 64 * 1024);
    defer completion.deinit();
    var locked = try parse(fixture, lock[fixture.path.len + 1 ..], 1024 * 1024);
    defer locked.deinit();
    const returned = try field(failed.evidence.?.value, "native_completion");
    try same(try string(returned, "outcome"), "failed");
    try same(try string(returned, "settlement"), "cleared");
    try same(try string(returned, "operation"), if (update) "upgrade" else "install");
    for ([_]struct { name: []const u8, expected: []const u8 }{
        .{ .name = "attempt_id", .expected = try string(receipt.value, "attempt_id") },
        .{ .name = "lock_sha256", .expected = try string(locked.value, "digest_sha256") },
        .{ .name = "caller_request_sha256", .expected = try string(completion.value, "request_sha256") },
        .{ .name = "caller_policy_sha256", .expected = try string(completion.value, "policy_sha256") },
        .{ .name = "transaction_digest_sha256", .expected = try string(receipt.value, "digest_sha256") },
        .{ .name = "completion_digest_sha256", .expected = try string(completion.value, "digest_sha256") },
        .{ .name = "program_sha256", .expected = try string(receipt.value, "program_sha256") },
    }) |binding| {
        const actual = try hexEvidence(try field(returned, binding.name));
        try same(&actual, binding.expected);
    }
    const failed_evidence = try projected.rootInventory(fixture, scenario.native_root, true);
    try refusedVerification(fixture, driver, request, try support.path(fixture.allocator, name, "failed-not-success"), returned, null);
    var relabeled = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try std.json.Stringify.valueAlloc(fixture.allocator, returned, .{}), .{ .allocate = .alloc_always });
    defer relabeled.deinit();
    relabeled.value.object.getPtr("outcome").?.* = .{ .string = "succeeded" };
    try refusedVerification(fixture, driver, request, try support.path(fixture.allocator, name, "relabeled-not-success"), relabeled.value, null);
    try std.testing.expectEqualSlices(u8, failed_evidence, try projected.rootInventory(fixture, scenario.native_root, true));
    const reference_name = try std.fmt.allocPrint(fixture.allocator, "{s}-reference-execute", .{name});
    try fixture.directory(reference_name);
    const archive_path = try archive(fixture, arch, "fail-script", "1.0-1");
    if (try support.reference(fixture, reference, scenario.reference_root, .{ .operation = "install", .archives = &.{archive_path}, .triggers = true }, reference_name) != 1)
        return error.ReferenceFailureMissing;
    const comparison = try support.path(fixture.allocator, name, "comparison");
    try fixture.directory(comparison);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    const receipt_bytes = try support.read(fixture, receipt_relative, 16 * 1024 * 1024);
    const before = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
    request = try familyRequest(fixture, scenario.native_root, arch, "recover");
    var recovered = try workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "recover"), .{
        .family_execution = request,
        .capture_evidence = true,
    });
    defer recovered.deinit();
    try expectFamily(recovered.report.value, "recover", true);
    try std.testing.expect(!(try field(recovered.report.value, "changed")).bool);
    try std.testing.expectEqual(.null, try field(recovered.report.value, "provenance_path"));
    try std.testing.expectEqual(.null, try field(recovered.evidence.?.value, "native_completion"));
    try std.testing.expectEqualSlices(u8, receipt_bytes, try support.read(fixture, receipt_relative, 16 * 1024 * 1024));
    try std.testing.expectEqualSlices(u8, before, try foundation.capture(fixture.allocator, fixture.io, scenario.native_root));
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    std.debug.print("family {s}: real failed script, failed proof and pinned dpkg state passed\n", .{label});
}

fn activeInspection(fixture: *foundation.Fixture, driver: []const u8, arch: []const u8) !void {
    const root = try fixture.makeRoot("active/native", arch);
    defer fixture.allocator.free(root);
    try support.copyProgram(fixture, "active/native", "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
    const package = try fixture.makePackageWith(arch, "1", .data, .{ .workspace = "active/package" });
    defer fixture.allocator.free(package);
    try fixture.directory("active/execute");
    const request_path = try fixture.absolute("active/execute/native.request.json");
    const report_path = try fixture.absolute("active/execute/native.report.json");
    const request = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = root,
        .architecture = arch,
        .operation = "install",
        .archives = &.{package},
        .packages = &.{},
        .report = report_path,
        .recovery = true,
        .caller_owned = true,
        .isolated_helper = true,
        .crash_at = "after_execution_intent",
    }, .{});
    try fixture.write("active/execute/native.request.json", request, 0o644);
    _ = fixture.environment.swapRemove("DEBZ_NATIVE_WORKFLOW_REQUEST");
    try fixture.environment.put("DEBZ_NATIVE_LIFECYCLE_REQUEST", request_path);
    const result = std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", driver },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    }) catch |err| {
        const note = try std.fmt.allocPrint(fixture.allocator, "native active-operation seed failed: {s}\n", .{@errorName(err)});
        defer fixture.allocator.free(note);
        try fixture.write("active/execute/native.log", note, 0o644);
        return err;
    };
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const log = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    defer fixture.allocator.free(log);
    try fixture.write("active/execute/native.log", log, 0o644);
    if (result.term != .exited or result.term.exited != 86) {
        std.debug.print("active inspection seed exited {any}: {s}\n", .{ result.term, log[log.len - @min(log.len, 12_000) ..] });
        return error.ActiveOperationCrashMissing;
    }
    try support.absent(fixture, "active/execute/native.report.json");
    _ = fixture.environment.swapRemove("DEBZ_NATIVE_LIFECYCLE_REQUEST");
    var recorded = try parse(fixture, "active/native/var/lib/debz/root-operation-v1.json", 64 * 1024);
    defer recorded.deinit();
    const before = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(before);
    var inspected = try workflow(fixture, driver, root, arch, "active/inspection", .{
        .family_execution = try familyRequest(fixture, root, arch, "inspect"),
        .capture_evidence = true,
    });
    defer inspected.deinit();
    try expectFamily(inspected.report.value, "inspect", true);
    const evidence = inspected.evidence.?.value;
    const observed = try oracle.validateDiagnosticInspection(inspected.report.value, evidence, root);
    try std.testing.expect((try field(observed, "native_active_evidence")).bool);
    try std.testing.expect((try field(observed, "status_database_present")).bool);
    const operation = try field(observed, "observed_operation");
    try same(try string(operation, "backend"), "native");
    try same(try string(operation, "state"), try string(recorded.value, "state"));
    try std.testing.expectEqual(.null, try field(evidence, "native_install"));
    try std.testing.expectEqual(.null, try field(evidence, "native_completion"));
    const after = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(after);
    try std.testing.expectEqualSlices(u8, before, after);
    std.debug.print("family inspection: genuine active root operation remained diagnostic-only and unchanged\n", .{});
}

fn refusals(fixture: *foundation.Fixture, arch: []const u8) !void {
    const root = try fixture.makeRoot("refusals/native", arch);
    defer fixture.allocator.free(root);
    const invalid_driver = "/not-a-native-workflow-driver";
    var host_request = try familyRequest(fixture, "/", arch, "inspect");
    try std.testing.expectError(error.NotDisposableRoot, workflow(fixture, invalid_driver, "/", arch, "refusals/host-execution", .{
        .family_execution = host_request,
    }));
    try same(preflightDiagnostic(error.NotDisposableRoot), "disposable fixture root");
    try support.absent(fixture, "refusals/host-execution");
    try std.testing.expectError(error.NotDisposableRoot, workflow(fixture, invalid_driver, "/", arch, "refusals/host-verification", .{
        .family_verification = host_request,
    }));
    try support.absent(fixture, "refusals/host-verification");
    try std.testing.expectError(error.FamilyRequestRequired, workflow(fixture, invalid_driver, root, arch, "refusals/missing-plan", .{
        .family_update_planning = true,
    }));
    try same(preflightDiagnostic(error.FamilyRequestRequired), "requires a family request");
    try support.absent(fixture, "refusals/missing-plan");
    host_request.root = "/";
    try std.testing.expectError(error.InvalidFamilyRoot, workflow(fixture, invalid_driver, root, arch, "refusals/wrong-root", .{
        .family_execution = host_request,
    }));
    try support.absent(fixture, "refusals/wrong-root");
    std.debug.print("family: host-root and missing-plan refusals occurred before request creation or spawn\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    if (std.mem.eql(u8, driver, "--inside-projected")) {
        const root = args.next() orelse return error.MissingProjectedRoot;
        return projected.inside(init, allocator, root);
    }
    var pinned: ?[]const u8 = null;
    var helper: ?[]const u8 = null;
    var self: ?[]const u8 = null;
    var cli: ?[]const u8 = null;
    var python: []const u8 = "python3";
    var executed_only = false;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--reference-dpkg")) {
            if (pinned != null) return error.DuplicateReference;
            pinned = args.next() orelse return error.MissingReferencePath;
        } else if (std.mem.eql(u8, arg, "--native-helper")) {
            if (helper != null) return error.DuplicateHelper;
            helper = args.next() orelse return error.MissingHelper;
        } else if (std.mem.eql(u8, arg, "--self")) {
            self = args.next() orelse return error.MissingSelf;
        } else if (std.mem.eql(u8, arg, "--cli")) {
            cli = args.next() orelse return error.MissingPublicCli;
        } else if (std.mem.eql(u8, arg, "--fixture-python")) {
            python = args.next() orelse return error.MissingFixturePython;
        } else if (std.mem.eql(u8, arg, "--executed-only")) {
            executed_only = true;
        } else return error.InvalidArguments;
    }
    const reference = try support.prerequisites(init, allocator, pinned);
    defer allocator.free(reference.architecture);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed after family acceptance failure: {s}\n", .{@errorName(err)});
    if (!executed_only) {
        try refusals(&fixture, reference.architecture);
        try transport(&fixture, driver, reference.architecture);
        try planning(&fixture, driver);
    }
    try activeInspection(&fixture, driver, reference.architecture);
    try archiveExecution(&fixture, driver, helper orelse return error.MissingHelper, reference.executable, reference.architecture, python);
    const source = try fixture.absolute("executed/workflow.sources");
    const keyring = try fixture.absolute("executed/repository/fixture-keyring.gpg");
    try ordinaryFamilyTimeline(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);
    try batchWorkflow(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);
    try ownedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);
    try reconciliation(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);
    try ordinaryRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);
    try ordinaryKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);
    try ownedAbandon(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);
    try ownedRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);
    try ownedKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);
    try ownedFinalizationBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);
    try projected.run(&fixture, self orelse return error.MissingSelf, driver, reference.executable, reference.architecture);
    try missingHelper(&fixture, driver, reference.executable, reference.architecture);
    try failedTransaction(&fixture, driver, reference.executable, reference.architecture, false);
    try failedTransaction(&fixture, driver, reference.executable, reference.architecture, true);
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
