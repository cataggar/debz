const std = @import("std");
const debz = @import("debz");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const oracle = @import("native_recovery_oracle.zig");
const projected = @import("native_recovery_projected_workflows.zig");
const options = @import("native_test_options");

const operation_path = "var/lib/debz/root-operation-v1.json";
const intent_path = debz.native_recovery.intent_path;
const completion_path = "var/lib/debz/root-operation-completion-v1.json";
const provenance_path = debz.native_provenance.legacy_document_path;
const helper_path = "usr/bin/dpkg-trigger";

const Report = struct {
    outcome: []const u8,
    detail: []const u8 = "",
    attempt_id: ?[]const u8 = null,
    program_sha256: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
};

const Invocation = struct {
    operation: []const u8,
    archive: ?[]const u8 = null,
    packages: []const foundation.PackageIdentity = &.{},
    crash_at: ?[]const u8 = null,
    caller_owned: bool = true,
    isolated_helper: bool = true,
    trigger_execution: bool = false,
    acknowledge: bool = false,
    seed_success_report: bool = false,
};

fn verifyTransport(input: Invocation) !void {
    if (std.mem.eql(u8, input.operation, "recover") and
        (input.archive != null or input.packages.len != 0 or input.crash_at != null))
        return error.RecoveryMustUsePersistedEvidence;
    if (input.isolated_helper and !input.caller_owned) return error.IsolatedHelperRequiresCaller;
    if (input.acknowledge and (!input.caller_owned or !std.mem.eql(u8, input.operation, "recover")))
        return error.AcknowledgmentRequiresRecoveringCaller;
}

fn relative(fixture: *foundation.Fixture, root: []const u8, path: []const u8) ![]u8 {
    if (std.mem.eql(u8, root, fixture.path)) return fixture.allocator.dupe(u8, path);
    if (!std.mem.startsWith(u8, root, fixture.path) or root.len <= fixture.path.len or
        root[fixture.path.len] != '/') return error.NotFixtureRoot;
    return support.path(fixture.allocator, root[fixture.path.len + 1 ..], path);
}

fn bytes(fixture: *foundation.Fixture, root: []const u8, name: []const u8, limit: usize) ![]u8 {
    const path = try relative(fixture, root, name);
    defer fixture.allocator.free(path);
    return support.read(fixture, path, limit);
}

fn missing(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !void {
    const path = try relative(fixture, root, name);
    defer fixture.allocator.free(path);
    try support.absent(fixture, path);
}

fn document(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !std.json.Parsed(std.json.Value) {
    const data = try bytes(fixture, root, name, 16 * 1024 * 1024);
    defer fixture.allocator.free(data);
    return std.json.parseFromSlice(std.json.Value, fixture.allocator, data, .{ .allocate = .alloc_always });
}

fn field(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidEvidence;
    return value.object.get(key) orelse error.MissingEvidence;
}

fn text(value: std.json.Value, key: []const u8) ![]const u8 {
    const entry = try field(value, key);
    if (entry != .string) return error.InvalidEvidence;
    return entry.string;
}

fn same(left: []const u8, right: []const u8) !void {
    if (!std.mem.eql(u8, left, right)) {
        std.debug.print("expected {s}, got {s}\n", .{ right, left });
        return error.BrokenRecoveryBinding;
    }
}

fn sha256(input: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(input, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

fn snapshot(fixture: *foundation.Fixture, root: []const u8) ![]u8 {
    return foundation.capture(fixture.allocator, fixture.io, root);
}

fn unchanged(fixture: *foundation.Fixture, root: []const u8, previous: []const u8) !void {
    const current = try snapshot(fixture, root);
    defer fixture.allocator.free(current);
    if (!std.mem.eql(u8, current, previous)) return error.BlockedRecoveryMutatedPackageState;
}

fn rootWithoutActiveClaim(fixture: *foundation.Fixture, root: []const u8) ![]const u8 {
    var inventory = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try projected.rootInventory(fixture, root, false), .{
        .allocate = .alloc_always,
    });
    defer inventory.deinit();
    if (inventory.value != .array) return error.InvalidRootInventory;
    var seen = false;
    for (inventory.value.array.items) |*entry| {
        if (!std.mem.eql(u8, try text(entry.*, "path"), operation_path)) continue;
        if (seen) return error.DuplicateRootClaim;
        seen = true;
        if (entry.* != .object) return error.InvalidRootInventory;
        // Only the active claim's generation/digest may advance on a blocked retry.
        (entry.object.getPtr("data_hex") orelse return error.InvalidRootInventory).* = .null;
        (entry.object.getPtr("size") orelse return error.InvalidRootInventory).* = .{ .integer = 0 };
    }
    if (!seen) return error.MissingRootClaim;
    return std.json.Stringify.valueAlloc(fixture.allocator, inventory.value, .{});
}

fn stickyActiveClaim(fixture: *foundation.Fixture, root: []const u8) ![]const u8 {
    var claim = try document(fixture, root, operation_path);
    defer claim.deinit();
    if (claim.value != .object) return error.InvalidRootClaim;
    for ([_][]const u8{ "generation", "state", "phase", "step", "updated_unix", "digest_sha256" }) |changing| {
        if (!claim.value.object.swapRemove(changing)) return error.InvalidRootClaim;
    }
    return std.json.Stringify.valueAlloc(fixture.allocator, claim.value, .{});
}

fn invoke(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    arch: []const u8,
    destination: []const u8,
    input: Invocation,
) !?std.json.Parsed(Report) {
    var guarded = try foundation.guardedRoot(fixture.io, root);
    guarded.close(fixture.io);
    try verifyTransport(input);
    try fixture.directory(destination);
    const request_relative = try support.path(fixture.allocator, destination, "native.request.json");
    defer fixture.allocator.free(request_relative);
    const report_relative = try support.path(fixture.allocator, destination, "native.report.json");
    defer fixture.allocator.free(report_relative);
    try support.absent(fixture, report_relative);
    const request_path = try fixture.absolute(request_relative);
    defer fixture.allocator.free(request_path);
    const report_path = try fixture.absolute(report_relative);
    defer fixture.allocator.free(report_path);
    const archives: []const []const u8 = if (input.archive) |archive| &.{archive} else &.{};
    const encoded = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = root,
        .architecture = arch,
        .operation = input.operation,
        .archives = archives,
        .packages = input.packages,
        .recovery = true,
        .report = report_path,
        .caller_owned = input.caller_owned,
        .isolated_helper = input.isolated_helper,
        .triggers = input.trigger_execution,
        .acknowledge_native = input.acknowledge,
        .crash_at = input.crash_at,
    }, .{});
    defer fixture.allocator.free(encoded);
    try fixture.write(request_relative, encoded, 0o644);
    try fixture.environment.put("DEBZ_NATIVE_LIFECYCLE_REQUEST", request_path);
    if (input.seed_success_report)
        try fixture.write(report_relative, "{\"outcome\":\"applied\"}\n", 0o644);
    const log = try support.path(fixture.allocator, destination, "native.log");
    defer fixture.allocator.free(log);
    const result = std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", driver },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    }) catch |err| {
        std.debug.print("{s}: process error {s}; fixture {s}\n", .{ destination, @errorName(err), fixture.path });
        return err;
    };
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const combined = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    defer fixture.allocator.free(combined);
    try fixture.write(log, combined, 0o644);
    if (result.term != .exited or result.term.exited != (if (input.crash_at != null) @as(u8, 86) else 0)) {
        if (result.term == .exited and result.term.exited == 0 and input.crash_at != null)
            return error.CrashSelectorIgnored;
        std.debug.print("{s}: exit {any}, expected {d}; fixture {s}/{s}:\n{s}\n", .{
            destination,  result.term, if (input.crash_at != null) @as(u8, 86) else @as(u8, 0),
            fixture.path, log,         combined[combined.len - @min(combined.len, 12_000) ..],
        });
        return error.UnexpectedNativeProcessExit;
    }
    if (input.crash_at != null) {
        support.absent(fixture, report_relative) catch |err| switch (err) {
            error.UnexpectedArtifact => return error.CrashProducedCompletionReport,
            else => return err,
        };
        return null;
    }
    const data = try support.read(fixture, report_relative, 64 * 1024);
    defer fixture.allocator.free(data);
    const report = try std.json.parseFromSlice(Report, fixture.allocator, data, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    for ([_][]const u8{ "applied", "script_failed", "trigger_failed", "recovery_required", "refused", "handoff" }) |outcome|
        if (std.mem.eql(u8, outcome, report.value.outcome)) return report;
    var invalid = report;
    invalid.deinit();
    return error.InvalidRecoveryReport;
}

fn expectReport(report: ?std.json.Parsed(Report), outcome: []const u8, detail: ?[]const u8) !std.json.Parsed(Report) {
    const value = report orelse return error.MissingRecoveryReport;
    errdefer {
        var bad = value;
        bad.deinit();
    }
    try same(value.value.outcome, outcome);
    if (detail) |expected| try same(value.value.detail, expected);
    return value;
}

const HelperIdentity = struct { inode: u64, digest: [64]u8 };

fn helperIdentity(fixture: *foundation.Fixture, root: []const u8) !HelperIdentity {
    const path = try relative(fixture, root, helper_path);
    defer fixture.allocator.free(path);
    const stat = try fixture.dir.statFile(fixture.io, path, .{ .follow_symlinks = false });
    const raw = try support.read(fixture, path, 8 * 1024 * 1024);
    defer fixture.allocator.free(raw);
    return .{ .inode = stat.inode, .digest = sha256(raw) };
}

fn sameHelper(fixture: *foundation.Fixture, root: []const u8, previous: HelperIdentity) !void {
    const current = try helperIdentity(fixture, root);
    if (current.inode != previous.inode) return error.PackageOwnedHelperReplaced;
    try same(&current.digest, &previous.digest);
}

fn installTools(fixture: *foundation.Fixture, root: []const u8) !void {
    const root_relative = root[fixture.path.len + 1 ..];
    try support.copyProgram(fixture, root_relative, "/bin/sh", "/bin/sh");
    try support.copyProgram(fixture, root_relative, "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
}

fn originalRequestFor(
    fixture: *foundation.Fixture,
    root: []const u8,
    intent: debz.native_recovery.Intent,
    isolated_helper: bool,
    caller_owned: bool,
    archive: ?[]const u8,
) ![]u8 {
    const entry = for (intent.blobs) |blob| {
        if (blob.kind == .request) break blob;
    } else return error.MissingOriginalHelperRequest;
    const raw = try bytes(fixture, root, entry.storage_path, 16 * 1024 * 1024);
    errdefer fixture.allocator.free(raw);
    if (entry.size != raw.len) return error.HelperRequestChanged;
    try same(&sha256(raw), &entry.sha256);
    if (!caller_owned) {
        if (isolated_helper) return error.IsolatedHelperRequiresCaller;
        var transport = try std.json.parseFromSlice(std.json.Value, fixture.allocator, raw, .{
            .allocate = .alloc_always,
        });
        defer transport.deinit();
        try same(try text(transport.value, "root"), root);
        try same(try text(transport.value, "architecture"), intent.architecture);
        try same(try text(transport.value, "operation"), @tagName(intent.operation));
        const owned = try field(transport.value, "caller_owned");
        if (owned != .bool or owned.bool) return error.UnexpectedCallerOwner;
        const archives = try field(transport.value, "archives");
        if (archives != .array or archives.array.items.len != 1 or archive == null or
            archives.array.items[0] != .string) return error.MissingOriginalArchive;
        try same(archives.array.items[0].string, archive.?);
        return raw;
    }
    var decoded = try debz.native_execution_request.decodePersisted(fixture.allocator, raw);
    defer decoded.deinit();
    if ((decoded.helper() != null) != isolated_helper or !std.mem.eql(u8, decoded.execution().install_root, root))
        return error.UnboundHelperRequest;
    try same(&decoded.execution().caller.attempt_id, &intent.attempt_id);
    try same(&decoded.execution().program.program_sha256, &intent.program_sha256);
    return raw;
}

fn originalRequest(fixture: *foundation.Fixture, root: []const u8, intent: debz.native_recovery.Intent) ![]u8 {
    return originalRequestFor(fixture, root, intent, true, true, null);
}

fn verifyProofFor(
    fixture: *foundation.Fixture,
    root: []const u8,
    report: Report,
    intent: debz.native_recovery.Intent,
    original_request: []const u8,
    expected_outcome: debz.native_provenance.Outcome,
    check_trace: bool,
    isolated_helper: bool,
    caller_owned: bool,
) !void {
    try same(report.provenance_path orelse return error.MissingReportBinding, provenance_path);
    const proof_bytes = try bytes(fixture, root, provenance_path, 16 * 1024 * 1024);
    defer fixture.allocator.free(proof_bytes);
    var parsed_proof = try debz.native_provenance.decode(fixture.allocator, proof_bytes);
    defer parsed_proof.deinit();
    const proof = parsed_proof.document;
    if (proof.outcome != expected_outcome) return error.WrongRecoveryOutcome;
    try same(report.attempt_id orelse return error.MissingReportBinding, &intent.attempt_id);
    try same(report.program_sha256 orelse return error.MissingReportBinding, &intent.program_sha256);
    try same(&proof.attempt_id, &intent.attempt_id);
    try same(&proof.program_sha256, &intent.program_sha256);
    try same(&proof.execution_intent_sha256, &intent.digest_sha256);
    try same(proof.install_root, root);
    try same(&proof.root_identity_sha256, &intent.root_identity_sha256);
    try same(&proof.authorization_sha256, &intent.authorization_sha256);
    try same(&proof.exact_lock_sha256, &intent.exact_lock_sha256);
    try same(&proof.artifact_evidence_sha256, &intent.artifact_evidence_sha256);
    try same(&proof.initial_database_generation_sha256, &intent.database_generation_sha256);
    const root_stat = try std.Io.Dir.cwd().statFile(fixture.io, root, .{ .follow_symlinks = false });
    if (proof.root_inode != root_stat.inode or intent.root_inode != root_stat.inode)
        return error.ProvenanceChangedPhysicalRoot;
    var decoded: ?debz.native_execution_request.OwnedRequest = if (caller_owned)
        try debz.native_execution_request.decodePersisted(fixture.allocator, original_request)
    else
        null;
    defer if (decoded) |*request| request.deinit();
    if (decoded) |request| {
        if (!std.meta.eql(proof.operation, request.execution().caller.operation))
            return error.ProvenanceChangedCallerOperation;
        try same(&request.execution().program.request_sha256, &intent.request_sha256);
        try same(&request.execution().caller.request_sha256, &proof.request_sha256);
        try same(&request.execution().caller.policy_sha256, &proof.policy_sha256);
    } else {
        if (proof.operation != .package_transaction) return error.ProvenanceChangedCallerOperation;
        try same(&proof.request_sha256, &intent.request_sha256);
        try same(&proof.policy_sha256, &intent.policy_sha256);
    }
    var root_dir = try foundation.guardedRoot(fixture.io, root);
    defer root_dir.close(fixture.io);
    const root_fs: debz.root_fs.Root = .init(fixture.io, root_dir);
    try debz.native_provenance.verifyEvidence(fixture.allocator, root_fs, proof);
    var request_found = false;
    var helper_found = false;
    var script_count: usize = 0;
    var scripts: std.ArrayList(oracle.ScriptInvocation) = .empty;
    defer scripts.deinit(fixture.allocator);
    var retained_scripts: std.ArrayList(std.json.Parsed(debz.native_recovery.ScriptOutcome)) = .empty;
    defer {
        for (retained_scripts.items) |*item| item.deinit();
        retained_scripts.deinit(fixture.allocator);
    }
    for (proof.evidence_files) |evidence| {
        switch (evidence.kind) {
            .execution_request => {
                if (request_found) return error.DuplicateHelperRequest;
                const raw = try bytes(fixture, root, evidence.path, 16 * 1024 * 1024);
                defer fixture.allocator.free(raw);
                if (!std.mem.eql(u8, raw, original_request)) return error.HelperRequestChanged;
                request_found = true;
            },
            .helper_binary => {
                if (helper_found) return error.DuplicateHelperBinary;
                helper_found = true;
            },
            .script_outcome => {
                const raw = try bytes(fixture, root, evidence.path, 16 * 1024 * 1024);
                defer fixture.allocator.free(raw);
                const script = try std.json.parseFromSlice(debz.native_recovery.ScriptOutcome, fixture.allocator, raw, .{
                    .allocate = .alloc_always,
                    .ignore_unknown_fields = false,
                });
                try debz.native_recovery.validateScriptOutcome(script.value);
                try retained_scripts.append(fixture.allocator, script);
                script_count += 1;
            },
            else => {},
        }
    }
    if (request_found != caller_owned or helper_found != isolated_helper or
        ((if (decoded) |request| request.helper() != null else false) != isolated_helper))
        return error.UnexpectedHelperEvidence;
    const helper = if (decoded) |request| request.helper() else null;
    if (helper) |bound| {
        for (proof.evidence_files) |evidence|
            if (evidence.kind == .helper_binary) {
                try same(&bound.sha256, &evidence.sha256);
                break;
            };
    }
    for (retained_scripts.items) |retained| {
        const script = retained.value;
        const invocation: oracle.ScriptInvocation = .{
            .package = script.package,
            .version = script.package_version,
            .architecture = script.architecture,
            .kind = @tagName(script.kind),
            .source = script.source,
            .arguments = script.arguments,
            .environment = script.environment,
            .script_sha256 = script.script_sha256,
            .invocation_sha256 = script.invocation_sha256,
        };
        if (helper) |bound| try oracle.validateHelperInvocation(
            fixture.allocator, root, bound.source_path, bound.target_path, bound.sha256,
            decoded.?.execution().program.script_policy_sha256, invocation,
        );
        try scripts.append(fixture.allocator, invocation);
    }
    if (check_trace) {
        if (script_count == 0) return error.MissingExecutedScriptReceipt;
        const trace = try bytes(fixture, root, support.trace, 16 * 1024 * 1024);
        defer fixture.allocator.free(trace);
        try oracle.validateScriptTrace(fixture.allocator, trace, scripts.items);
        var altered = scripts.items[0];
        altered.arguments = &.{"fabricated-argument"};
        var others = try fixture.allocator.dupe(oracle.ScriptInvocation, scripts.items);
        defer fixture.allocator.free(others);
        others[0] = altered;
        if (oracle.validateScriptTrace(fixture.allocator, trace, others)) |_| return error.TraceOracleAcceptedForgery else |err| if (err != error.ScriptTraceMismatch) return err;
        if (helper) |bound| {
            if (oracle.validateHelperInvocation(
                fixture.allocator, root, bound.source_path, bound.target_path, bound.sha256,
                decoded.?.execution().program.script_policy_sha256, altered,
            )) |_| return error.HelperOracleAcceptedForgery else |err| if (err != error.ScriptHelperBindingMismatch) return err;
        }
    }
}

fn verifyProof(
    fixture: *foundation.Fixture,
    root: []const u8,
    report: Report,
    intent: debz.native_recovery.Intent,
    original_request: []const u8,
    expected_outcome: debz.native_provenance.Outcome,
    check_trace: bool,
) !void {
    return verifyProofFor(fixture, root, report, intent, original_request, expected_outcome, check_trace, true, true);
}

fn negativeTransport(fixture: *foundation.Fixture, driver: []const u8, root: []const u8, arch: []const u8) !void {
    for ([_]struct { name: []const u8, input: Invocation, expected: anyerror }{
        .{ .name = "ack-install", .input = .{ .operation = "install", .acknowledge = true }, .expected = error.AcknowledgmentRequiresRecoveringCaller },
        .{ .name = "ack-unowned", .input = .{ .operation = "recover", .caller_owned = false, .isolated_helper = false, .acknowledge = true }, .expected = error.AcknowledgmentRequiresRecoveringCaller },
        .{ .name = "isolated-unowned", .input = .{ .operation = "install", .caller_owned = false }, .expected = error.IsolatedHelperRequiresCaller },
        .{ .name = "archive-on-recover", .input = .{ .operation = "recover", .archive = "/no-archive" }, .expected = error.RecoveryMustUsePersistedEvidence },
    }) |case| {
        const dest = try support.path(fixture.allocator, "transport", case.name);
        defer fixture.allocator.free(dest);
        if (invoke(fixture, driver, root, arch, dest, case.input)) |report| {
            if (report) |*value| value.deinit();
            return error.InvalidTransportWasAccepted;
        } else |err| {
            if (err != case.expected) return err;
        }
        const request_path = try support.path(fixture.allocator, dest, "native.request.json");
        defer fixture.allocator.free(request_path);
        try support.absent(fixture, request_path);
    }
}

fn crashTransport(fixture: *foundation.Fixture, driver: []const u8, arch: []const u8) !void {
    const no_script = try fixture.makePackageWith(arch, "1", .data, .{ .workspace = "transport/package" });
    defer fixture.allocator.free(no_script);
    const root = try fixture.makeRoot("transport/root", arch);
    defer fixture.allocator.free(root);
    try installTools(fixture, root);
    try negativeTransport(fixture, driver, root, arch);
    try std.testing.expectError(error.CrashSelectorIgnored, invoke(
        fixture,
        driver,
        root,
        arch,
        "transport/ignored-selector",
        .{ .operation = "install", .archive = no_script, .crash_at = "after_script_outcome" },
    ));
    var ignored_request = try document(fixture, fixture.path, "transport/ignored-selector/native.request.json");
    defer ignored_request.deinit();
    try same(try text(ignored_request.value, "crash_at"), "after_script_outcome");
    if ((try field(ignored_request.value, "recovery")) != .bool or !(try field(ignored_request.value, "recovery")).bool)
        return error.CrashRequestLostRecovery;
    const crash_root = try fixture.makeRoot("transport/crash", arch);
    defer fixture.allocator.free(crash_root);
    try installTools(fixture, crash_root);
    _ = try invoke(fixture, driver, crash_root, arch, "transport/actual-crash", .{
        .operation = "install",
        .archive = no_script,
        .crash_at = "after_execution_intent",
    });
    var operation = try document(fixture, crash_root, operation_path);
    defer operation.deinit();
    try same(try text(operation.value, "backend"), "native");
    const poisoned_root = try fixture.makeRoot("transport/poisoned", arch);
    defer fixture.allocator.free(poisoned_root);
    try installTools(fixture, poisoned_root);
    try std.testing.expectError(error.CrashProducedCompletionReport, invoke(
        fixture,
        driver,
        poisoned_root,
        arch,
        "transport/poisoned-crash",
        .{ .operation = "install", .archive = no_script, .crash_at = "after_execution_intent", .seed_success_report = true },
    ));
}

fn completedWithoutLiveHelper(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
) !void {
    const name = "helper-terminal-without-live-helper";
    const expected = try fixture.makeRoot(name ++ "/reference", arch);
    const root = try fixture.makeRoot(name ++ "/native", arch);
    try installTools(fixture, expected);
    try installTools(fixture, root);
    try fixture.directory(name ++ "/reference/var/log");
    try fixture.directory(name ++ "/native/var/log");
    const original_helper = try helperIdentity(fixture, root);
    const archive = try support.makePackage(fixture, arch, "1", foundation.package, name ++ "/package", .{});
    try fixture.directory(name ++ "/reference-install");
    if (try support.reference(fixture, dpkg, expected, .{
        .operation = "install",
        .archives = &.{archive},
    }, name ++ "/reference-install") != 0) return error.ReferenceInstallFailed;
    var installed = try expectReport(try invoke(fixture, driver, root, arch, name ++ "/install", .{
        .operation = "install",
        .archive = archive,
    }), "applied", null);
    defer installed.deinit();
    const intent_bytes = try bytes(fixture, root, intent_path, 16 * 1024 * 1024);
    var intent = try debz.native_recovery.decodeIntent(fixture.allocator, intent_bytes);
    defer intent.deinit();
    const original_request = try originalRequest(fixture, root, intent.intent);
    var request = try debz.native_execution_request.decodePersisted(fixture.allocator, original_request);
    defer request.deinit();
    const cached_source = (request.helper() orelse return error.MissingHelperBinding).source_path;
    try verifyProof(fixture, root, installed.value, intent.intent, original_request, .succeeded, true);
    try fixture.directory(name ++ "/comparison");
    try foundation.compare(fixture.*, expected, root, name ++ "/comparison");
    const claim = try bytes(fixture, root, operation_path, 64 * 1024);
    const receipt = try bytes(fixture, root, provenance_path, 16 * 1024 * 1024);
    const target = try relative(fixture, root, helper_path);
    const saved_target = try std.fmt.allocPrint(fixture.allocator, "{s}.saved", .{target});
    const source = try relative(fixture, root, cached_source);
    const saved_source = try std.fmt.allocPrint(fixture.allocator, "{s}.saved", .{source});
    try fixture.dir.rename(target, fixture.dir, saved_target, fixture.io);
    defer fixture.dir.rename(saved_target, fixture.dir, target, fixture.io) catch {};
    try fixture.dir.rename(source, fixture.dir, saved_source, fixture.io);
    defer fixture.dir.rename(saved_source, fixture.dir, source, fixture.io) catch {};
    try missing(fixture, root, helper_path);
    try missing(fixture, root, cached_source);
    const before = try projected.rootInventory(fixture, root, true);
    for (0..2) |index| {
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/without-live-helper-{d}", .{ name, index });
        var recovered = try expectReport(try invoke(fixture, driver, root, arch, destination, .{
            .operation = "recover",
        }), "applied", null);
        defer recovered.deinit();
        try same(try bytes(fixture, root, operation_path, 64 * 1024), claim);
        try same(try bytes(fixture, root, provenance_path, 16 * 1024 * 1024), receipt);
        try missing(fixture, root, helper_path);
        try missing(fixture, root, cached_source);
        try std.testing.expectEqualSlices(u8, before, try projected.rootInventory(fixture, root, true));
    }
    try fixture.dir.rename(saved_source, fixture.dir, source, fixture.io);
    try fixture.dir.rename(saved_target, fixture.dir, target, fixture.io);
    try sameHelper(fixture, root, original_helper);
    var acknowledged = try expectReport(try invoke(fixture, driver, root, arch, name ++ "/ack", .{
        .operation = "recover",
        .acknowledge = true,
    }), "applied", null);
    defer acknowledged.deinit();
    try same(try bytes(fixture, root, provenance_path, 16 * 1024 * 1024), receipt);
    try missing(fixture, root, operation_path);
    try missing(fixture, root, intent_path);
    try foundation.compare(fixture.*, expected, root, name ++ "/comparison");
    std.debug.print("{s}: terminal receipt recovered twice with both helper paths absent, original claim and pinned dpkg intact\n", .{name});
}

fn missingPackageOwnedHelper(fixture: *foundation.Fixture, driver: []const u8, arch: []const u8) !void {
    const name = "helper-target-absent";
    const root = try fixture.makeRoot(name ++ "/native", arch);
    try support.copyProgram(fixture, name ++ "/native", "/bin/sh", "/bin/sh");
    try fixture.directory(name ++ "/native/var/log");
    try missing(fixture, root, helper_path);
    const archive = try support.makePackage(fixture, arch, "1", foundation.package, name ++ "/package", .{});
    const before = try snapshot(fixture, root);
    var refused = try expectReport(try invoke(fixture, driver, root, arch, name ++ "/refuse", .{
        .operation = "install",
        .archive = archive,
    }), "recovery_required", "NativeHelperBootstrapOwnerMissing");
    defer refused.deinit();
    var claim = try document(fixture, root, operation_path);
    defer claim.deinit();
    const started = try field(claim.value, "mutation_started");
    if (started != .bool or started.bool) return error.MissingHelperCrossedMutationBoundary;
    try missing(fixture, root, helper_path);
    try missing(fixture, root, intent_path);
    try missing(fixture, root, "var/lib/debz/native-helper-cache-v1");
    try unchanged(fixture, root, before);
    const claim_before = try bytes(fixture, root, operation_path, 64 * 1024);
    const stable = try projected.rootInventory(fixture, root, true);
    for (0..2) |index| {
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/repeat-{d}", .{ name, index });
        var repeated = try expectReport(try invoke(fixture, driver, root, arch, destination, .{
            .operation = "recover",
        }), "recovery_required", "FileNotFound");
        defer repeated.deinit();
        try same(try bytes(fixture, root, operation_path, 64 * 1024), claim_before);
        try std.testing.expectEqualSlices(u8, stable, try projected.rootInventory(fixture, root, true));
        try unchanged(fixture, root, before);
    }
    std.debug.print("{s}: missing package-owned helper refused before mutation or placeholder creation\n", .{name});
}

fn sealJsonDigest(fixture: *foundation.Fixture, document_value: *std.json.Value, domain: []const u8) !void {
    if (document_value.* != .object) return error.InvalidPersistedRequest;
    const member = document_value.object.getPtr("digest_sha256") orelse return error.MissingPersistedDigest;
    member.* = .{ .string = "0" ** 64 };
    const canonical = try std.json.Stringify.valueAlloc(fixture.allocator, document_value.*, .{});
    const tagged = try std.mem.concat(fixture.allocator, u8, &.{ domain, canonical });
    const digest = sha256(tagged);
    member.* = .{ .string = try fixture.allocator.dupe(u8, &digest) };
}

fn rehashedCallerPolicy(fixture: *foundation.Fixture, driver: []const u8, arch: []const u8) !void {
    const name = "caller-rehashed-policy";
    const root = try fixture.makeRoot(name ++ "/native", arch);
    try installTools(fixture, root);
    try fixture.directory(name ++ "/native/var/log");
    const original_helper = try helperIdentity(fixture, root);
    const archive = try support.makePackage(fixture, arch, "1", foundation.package, name ++ "/package", .{});
    _ = try invoke(fixture, driver, root, arch, name ++ "/crash", .{
        .operation = "install",
        .archive = archive,
        .crash_at = "after_execution_intent",
        .isolated_helper = false,
    });
    const claim = try bytes(fixture, root, operation_path, 64 * 1024);
    var intent = try debz.native_recovery.decodeIntent(fixture.allocator, try bytes(fixture, root, intent_path, 16 * 1024 * 1024));
    defer intent.deinit();
    const request_blob = for (intent.intent.blobs) |blob| {
        if (blob.kind == .request) break blob;
    } else return error.MissingOriginalHelperRequest;
    var persisted = try document(fixture, root, request_blob.storage_path);
    defer persisted.deinit();
    try same(try text(persisted.value, "schema"), debz.native_execution_request.schema_id);
    const caller = persisted.value.object.getPtr("caller") orelse return error.MissingCallerBinding;
    if (caller.* != .object) return error.InvalidPersistedRequest;
    const policy = caller.object.getPtr("policy_sha256") orelse return error.MissingCallerPolicy;
    policy.* = .{ .string = "f" ** 64 };
    try sealJsonDigest(fixture, &persisted.value, "debz-native-execution-request-v1\x00");
    const serialized = try std.json.Stringify.valueAlloc(fixture.allocator, persisted.value, .{});
    const altered_request = try std.mem.concat(fixture.allocator, u8, &.{ serialized, "\n" });
    var decoded = try debz.native_execution_request.decodePersisted(fixture.allocator, altered_request);
    defer decoded.deinit();
    try same(&decoded.execution().caller.policy_sha256, "f" ** 64);
    const request_file = try relative(fixture, root, request_blob.storage_path);
    try fixture.write(request_file, altered_request, request_blob.mode);
    const blobs = try fixture.allocator.dupe(debz.native_recovery.Blob, intent.intent.blobs);
    for (blobs) |*blob| {
        if (blob.kind != .request) continue;
        blob.size = altered_request.len;
        blob.sha256 = sha256(altered_request);
    }
    var altered_intent = intent.intent;
    altered_intent.blobs = blobs;
    debz.native_recovery.sealIntent(&altered_intent);
    var json: std.Io.Writer.Allocating = .init(fixture.allocator);
    try std.json.Stringify.value(altered_intent, .{ .whitespace = .minified }, &json.writer);
    try json.writer.writeByte('\n');
    const intent_bytes = try json.toOwnedSlice();
    var valid_intent = try debz.native_recovery.decodeIntent(fixture.allocator, intent_bytes);
    defer valid_intent.deinit();
    try fixture.write(try relative(fixture, root, intent_path), intent_bytes, 0o600);
    const archive_relative = archive[fixture.path.len + 1 ..];
    try fixture.dir.deleteFile(fixture.io, archive_relative);
    try support.absent(fixture, archive_relative);
    const before = try projected.rootInventory(fixture, root, true);
    for (0..2) |index| {
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/refuse-{d}", .{ name, index });
        var refused = try expectReport(try invoke(fixture, driver, root, arch, destination, .{
            .operation = "recover",
            .isolated_helper = false,
        }), "recovery_required", "RecoveryRequestBindingMismatch");
        defer refused.deinit();
        try same(try bytes(fixture, root, operation_path, 64 * 1024), claim);
        try std.testing.expectEqualSlices(u8, before, try projected.rootInventory(fixture, root, true));
        try sameHelper(fixture, root, original_helper);
    }
    std.debug.print("{s}: canonical rehashed request and intent still refuse changed caller policy twice\n", .{name});
}

fn afterActiveClearLegacyEvidence(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
) !void {
    const name = "after-active-clear-legacy-active";
    const expected = try fixture.makeRoot(name ++ "/reference", arch);
    const root = try fixture.makeRoot(name ++ "/native", arch);
    try installTools(fixture, expected);
    try installTools(fixture, root);
    try fixture.directory(name ++ "/reference/var/log");
    try fixture.directory(name ++ "/native/var/log");
    const original_helper = try helperIdentity(fixture, root);
    const first = try support.makePackage(fixture, arch, "1", foundation.package, name ++ "/packages", .{});
    const second = try support.makePackage(fixture, arch, "2", foundation.package, name ++ "/packages", .{});
    const third = try support.makePackage(fixture, arch, "3", foundation.package, name ++ "/packages", .{});
    try fixture.directory(name ++ "/reference-first");
    if (try support.reference(fixture, dpkg, expected, .{
        .operation = "install",
        .archives = &.{first},
    }, name ++ "/reference-first") != 0) return error.ReferenceInstallFailed;
    _ = try invoke(fixture, driver, root, arch, name ++ "/first-crash", .{
        .operation = "install",
        .archive = first,
        .caller_owned = false,
        .isolated_helper = false,
        .crash_at = "after_active_clear",
    });
    var completed = try expectReport(try invoke(fixture, driver, root, arch, name ++ "/first-recovery", .{
        .operation = "recover",
        .caller_owned = false,
        .isolated_helper = false,
    }), "applied", null);
    defer completed.deinit();
    try missing(fixture, root, operation_path);
    try fixture.directory(name ++ "/comparison");
    try foundation.compare(fixture.*, expected, root, name ++ "/comparison");
    const old_receipt = try bytes(fixture, root, provenance_path, 16 * 1024 * 1024);
    var old_proof = try debz.native_provenance.decode(fixture.allocator, old_receipt);
    defer old_proof.deinit();
    try fixture.directory(name ++ "/reference-second");
    if (try support.reference(fixture, dpkg, expected, .{
        .operation = "upgrade",
        .archives = &.{second},
    }, name ++ "/reference-second") != 0) return error.ReferenceUpgradeFailed;
    var following = try expectReport(try invoke(fixture, driver, root, arch, name ++ "/second-upgrade", .{
        .operation = "upgrade",
        .archive = second,
        .caller_owned = false,
        .isolated_helper = false,
    }), "applied", null);
    defer following.deinit();
    if (std.mem.eql(u8, following.value.attempt_id orelse return error.MissingFollowOnAttempt, &old_proof.document.attempt_id))
        return error.CompletedAttemptReused;
    try foundation.compare(fixture.*, expected, root, name ++ "/comparison");
    var directory = try foundation.guardedRoot(fixture.io, root);
    defer directory.close(fixture.io);
    try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, directory), old_proof.document);
    const third_party = [_]foundation.PackageIdentity{.{ .name = foundation.package, .architecture = arch }};
    try fixture.directory(name ++ "/legacy-untracked");
    var interrupted = try support.native(fixture, driver, root, arch, .{
        .operation = "upgrade",
        .archives = &.{third},
        .packages = &third_party,
        .fault = "after_script_before_record",
    }, name ++ "/legacy-untracked");
    defer interrupted.deinit();
    try same(interrupted.value.outcome, "recovery_required");
    const old_provenance = try bytes(fixture, root, provenance_path, 16 * 1024 * 1024);
    const active_claim = try bytes(fixture, root, operation_path, 64 * 1024);
    const before = try projected.rootInventory(fixture, root, true);
    for (0..2) |index| {
        const output = try std.fmt.allocPrint(fixture.allocator, "{s}/active-refusal-{d}", .{ name, index });
        var refused = (try invoke(fixture, driver, root, arch, output, .{
            .operation = "recover",
            .caller_owned = false,
            .isolated_helper = false,
        })) orelse return error.MissingActiveRefusal;
        defer refused.deinit();
        if (!std.mem.eql(u8, refused.value.outcome, "recovery_required") and
            !std.mem.eql(u8, refused.value.outcome, "refused")) return error.ActiveEvidenceWasMasked;
        try same(try bytes(fixture, root, operation_path, 64 * 1024), active_claim);
        try same(try bytes(fixture, root, provenance_path, 16 * 1024 * 1024), old_provenance);
        try std.testing.expectEqualSlices(u8, before, try projected.rootInventory(fixture, root, true));
    }
    try fixture.dir.deleteFile(fixture.io, try relative(fixture, root, operation_path));
    const orphaned = try projected.rootInventory(fixture, root, false);
    const package_before = try snapshot(fixture, root);
    for (0..2) |index| {
        const output = try std.fmt.allocPrint(fixture.allocator, "{s}/orphan-refusal-{d}", .{ name, index });
        var refused = (try invoke(fixture, driver, root, arch, output, .{
            .operation = "recover",
            .caller_owned = false,
            .isolated_helper = false,
        })) orelse return error.MissingOrphanRefusal;
        defer refused.deinit();
        if (!std.mem.eql(u8, refused.value.outcome, "recovery_required") and
            !std.mem.eql(u8, refused.value.outcome, "refused")) return error.OrphanEvidenceWasMasked;
        try missing(fixture, root, operation_path);
        try same(try bytes(fixture, root, provenance_path, 16 * 1024 * 1024), old_provenance);
        try std.testing.expectEqualSlices(u8, orphaned, try projected.rootInventory(fixture, root, false));
        try unchanged(fixture, root, package_before);
    }
    try sameHelper(fixture, root, original_helper);
    std.debug.print("{s}: follow-on pinned-dpkg upgrade, newer active script and orphan refusals preserved old proof\n", .{name});
}

const OrdinaryCase = struct {
    name: []const u8,
    crash: []const u8,
    caller_owned: bool = false,
    isolated_helper: bool = false,
    known_preinst_failure: bool = false,
};

fn recoveredOrdinary(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    case: OrdinaryCase,
) !void {
    const reference_name = try support.path(fixture.allocator, case.name, "reference");
    const native_name = try support.path(fixture.allocator, case.name, "native");
    const expected = try fixture.makeRoot(reference_name, arch);
    const root = try fixture.makeRoot(native_name, arch);
    try installTools(fixture, expected);
    try installTools(fixture, root);
    for ([_][]const u8{ expected, root }) |target| {
        try fixture.directory(try relative(fixture, target, "var/log"));
        if (case.known_preinst_failure) {
            const marker = try relative(fixture, target, support.failure);
            try support.fixtureFile(fixture, marker, foundation.package ++ "@1:preinst:install\n", 0o644);
        }
    }
    const helper_before = try helperIdentity(fixture, root);
    const package_name = try support.path(fixture.allocator, case.name, "package");
    const archive = try support.makePackage(fixture, arch, "1", foundation.package, package_name, .{});
    const reference_run = try support.path(fixture.allocator, case.name, "reference-install");
    try fixture.directory(reference_run);
    const reference_exit = try support.reference(fixture, dpkg, expected, .{
        .operation = "install",
        .archives = &.{archive},
    }, reference_run);
    if (reference_exit != (if (case.known_preinst_failure) @as(u8, 1) else @as(u8, 0)))
        return error.UnexpectedOrdinaryReferenceExit;

    const crash_output = try support.path(fixture.allocator, case.name, "crash");
    if (try invoke(fixture, driver, root, arch, crash_output, .{
        .operation = "install",
        .archive = archive,
        .crash_at = case.crash,
        .caller_owned = case.caller_owned,
        .isolated_helper = case.isolated_helper,
    }) != null) return error.CrashProducedCompletionReport;
    var original_claim = try document(fixture, root, operation_path);
    defer original_claim.deinit();
    try same(try text(original_claim.value, "backend"), "native");
    var intent = try debz.native_recovery.decodeIntent(fixture.allocator, try bytes(fixture, root, intent_path, 16 * 1024 * 1024));
    defer intent.deinit();
    try same(try text(original_claim.value, "attempt_id"), &intent.intent.attempt_id);
    const request = try originalRequestFor(fixture, root, intent.intent, case.isolated_helper, case.caller_owned, archive);
    const archive_relative = archive[fixture.path.len + 1 ..];
    try fixture.dir.deleteFile(fixture.io, archive_relative);
    try support.absent(fixture, archive_relative);
    const completed_outcome: []const u8 = if (case.known_preinst_failure) "script_failed" else "applied";
    const proof_outcome: debz.native_provenance.Outcome = if (case.known_preinst_failure) .failed else .succeeded;
    const recovery_output = try support.path(fixture.allocator, case.name, "fresh-recovery");
    var recovered = try expectReport(try invoke(fixture, driver, root, arch, recovery_output, .{
        .operation = "recover",
        .caller_owned = case.caller_owned,
        .isolated_helper = case.isolated_helper,
    }), completed_outcome, null);
    defer recovered.deinit();
    const comparison = try support.path(fixture.allocator, case.name, "comparison");
    try fixture.directory(comparison);
    try foundation.compare(fixture.*, expected, root, comparison);
    try verifyProofFor(fixture, root, recovered.value, intent.intent, request, proof_outcome, true, case.isolated_helper, case.caller_owned);
    try sameHelper(fixture, root, helper_before);
    const proof_before = try bytes(fixture, root, provenance_path, 16 * 1024 * 1024);
    const package_before = try snapshot(fixture, root);
    const root_before = try projected.rootInventory(fixture, root, case.caller_owned);
    if (case.caller_owned) {
        var pending = try document(fixture, root, operation_path);
        defer pending.deinit();
        try same(try text(pending.value, "attempt_id"), &intent.intent.attempt_id);
        try same(try text(pending.value, "outcome"), "pending");
        try missing(fixture, root, completion_path);
    } else {
        try missing(fixture, root, operation_path);
        try missing(fixture, root, intent_path);
        var terminal = try document(fixture, root, completion_path);
        defer terminal.deinit();
        try same(try text(terminal.value, "attempt_id"), &intent.intent.attempt_id);
    }
    const repeat_output = try support.path(fixture.allocator, case.name, "repeat");
    var repeated = try expectReport(try invoke(fixture, driver, root, arch, repeat_output, .{
        .operation = "recover",
        .caller_owned = case.caller_owned,
        .isolated_helper = case.isolated_helper,
    }), completed_outcome, null);
    defer repeated.deinit();
    try verifyProofFor(fixture, root, repeated.value, intent.intent, request, proof_outcome, true, case.isolated_helper, case.caller_owned);
    try unchanged(fixture, root, package_before);
    try std.testing.expectEqualSlices(u8, root_before, try projected.rootInventory(fixture, root, case.caller_owned));
    try same(try bytes(fixture, root, provenance_path, 16 * 1024 * 1024), proof_before);
    if (case.caller_owned) {
        const ack_output = try support.path(fixture.allocator, case.name, "caller-ack");
        var acknowledged = try expectReport(try invoke(fixture, driver, root, arch, ack_output, .{
            .operation = "recover",
            .caller_owned = true,
            .isolated_helper = case.isolated_helper,
            .acknowledge = true,
        }), completed_outcome, null);
        defer acknowledged.deinit();
        try unchanged(fixture, root, package_before);
        try missing(fixture, root, operation_path);
        try missing(fixture, root, intent_path);
        var terminal = try document(fixture, root, completion_path);
        defer terminal.deinit();
        try same(try text(terminal.value, "attempt_id"), &intent.intent.attempt_id);
    }
    try same(try bytes(fixture, root, provenance_path, 16 * 1024 * 1024), proof_before);
    try sameHelper(fixture, root, helper_before);
    try foundation.compare(fixture.*, expected, root, comparison);
    std.debug.print("{s}: real exit 86, evicted archive, pinned dpkg, typed proof, immutable repeat{s}\n", .{
        case.name, if (case.caller_owned) " and caller acknowledgment" else "",
    });
}

fn blockedUnknown(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    upgrade: bool,
) !void {
    const name = if (upgrade) "unknown-upgrade-postrm" else "unknown-script";
    var scenario = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer scenario.deinit();
    if (upgrade) {
        const old = try support.makePackage(fixture, arch, "1", foundation.package, try support.path(fixture.allocator, name, "old"), .{});
        try scenario.seed(old);
    }
    const original_helper = try helperIdentity(fixture, scenario.native_root);
    const archive = try support.makePackage(
        fixture, arch, if (upgrade) "2" else "1", foundation.package, try support.path(fixture.allocator, name, "new"), .{},
    );
    const crash = if (upgrade) "after_upgrade_postrm_return_before_outcome" else "after_script_return_before_outcome";
    if (try invoke(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "crash"), .{
        .operation = if (upgrade) "upgrade" else "install",
        .archive = archive,
        .crash_at = crash,
        .caller_owned = false,
        .isolated_helper = false,
    }) != null) return error.CrashProducedCompletionReport;
    var intent = try debz.native_recovery.decodeIntent(fixture.allocator, try bytes(fixture, scenario.native_root, intent_path, 16 * 1024 * 1024));
    defer intent.deinit();
    const request = try originalRequestFor(fixture, scenario.native_root, intent.intent, false, false, archive);
    var initial_claim = try document(fixture, scenario.native_root, operation_path);
    defer initial_claim.deinit();
    try same(try text(initial_claim.value, "attempt_id"), &intent.intent.attempt_id);
    const original_claim = try stickyActiveClaim(fixture, scenario.native_root);
    const active_path = "var/lib/debz/native-lifecycle-script-v1.json";
    const active = try bytes(fixture, scenario.native_root, active_path, 1024 * 1024);
    var script = try document(fixture, scenario.native_root, active_path);
    defer script.deinit();
    try same(try text(script.value, "outcome"), "in_flight");
    const trace = try bytes(fixture, scenario.native_root, support.trace, 1024 * 1024);
    if (std.mem.indexOf(u8, trace, if (upgrade) foundation.package ++ "@1:postrm\t" else foundation.package ++ "@1:preinst\t") == null)
        return error.UnknownScriptNotExecuted;
    const archive_relative = archive[fixture.path.len + 1 ..];
    try fixture.dir.deleteFile(fixture.io, archive_relative);
    try support.absent(fixture, archive_relative);
    const package_before = try snapshot(fixture, scenario.native_root);
    const first_output = try support.path(fixture.allocator, name, "fresh-recovery");
    var refused = try expectReport(try invoke(fixture, driver, scenario.native_root, arch, first_output, .{
        .operation = "recover", .caller_owned = false, .isolated_helper = false,
    }), "recovery_required", "script_outcome_unknown");
    defer refused.deinit();
    try unchanged(fixture, scenario.native_root, package_before);
    try sameHelper(fixture, scenario.native_root, original_helper);
    try same(try bytes(fixture, scenario.native_root, active_path, 1024 * 1024), active);
    var blocked_claim = try document(fixture, scenario.native_root, operation_path);
    defer blocked_claim.deinit();
    try same(try text(blocked_claim.value, "attempt_id"), &intent.intent.attempt_id);
    try same(try text(blocked_claim.value, "backend"), "native");
    try same(try stickyActiveClaim(fixture, scenario.native_root), original_claim);
    try verifyProofFor(fixture, scenario.native_root, refused.value, intent.intent, request, .recovery_required, false, false, false);
    try missing(fixture, scenario.native_root, completion_path);
    const proof = try bytes(fixture, scenario.native_root, provenance_path, 16 * 1024 * 1024);
    const stable = try rootWithoutActiveClaim(fixture, scenario.native_root);
    for (0..2) |index| {
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/repeat-{d}", .{ name, index });
        var repeated = try expectReport(try invoke(fixture, driver, scenario.native_root, arch, destination, .{
            .operation = "recover", .caller_owned = false, .isolated_helper = false,
        }), "recovery_required", "script_outcome_unknown");
        defer repeated.deinit();
        try unchanged(fixture, scenario.native_root, package_before);
        try sameHelper(fixture, scenario.native_root, original_helper);
        try same(try bytes(fixture, scenario.native_root, provenance_path, 16 * 1024 * 1024), proof);
        try same(try bytes(fixture, scenario.native_root, active_path, 1024 * 1024), active);
        try same(try stickyActiveClaim(fixture, scenario.native_root), original_claim);
        try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, scenario.native_root));
    }
    const selected = [_]foundation.PackageIdentity{.{ .name = "debz-recovery-absent", .architecture = arch }};
    var blocked = try expectReport(try invoke(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "blocked-purge"), .{
        .operation = "purge", .packages = &selected, .caller_owned = false, .isolated_helper = false,
    }), "recovery_required", null);
    defer blocked.deinit();
    try unchanged(fixture, scenario.native_root, package_before);
    var retained_claim = try document(fixture, scenario.native_root, operation_path);
    defer retained_claim.deinit();
    try same(try text(retained_claim.value, "attempt_id"), &intent.intent.attempt_id);
    try same(try stickyActiveClaim(fixture, scenario.native_root), original_claim);
    try same(try bytes(fixture, scenario.native_root, provenance_path, 16 * 1024 * 1024), proof);
    try sameHelper(fixture, scenario.native_root, original_helper);
    std.debug.print("{s}: real exit 86, evicted archive, in-flight script retained and recovery refused repeatedly\n", .{name});
}

fn triggerOutcome(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    isolated: bool,
) !void {
    const name = if (isolated) "isolated-helper-trigger-outcome" else "known-trigger-outcome";
    const first_name = "debz-recovery-a";
    const source_name = "debz-trigger-source";
    var scenario = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer scenario.deinit();
    const first = try support.makePackage(fixture, arch, "1", first_name, try support.path(fixture.allocator, name, "first"), .{
        .declarations = "interest-noawait debz-a\n",
        .activation = "debz-b",
        .activation_when = "triggered",
    });
    const second = try support.makePackage(fixture, arch, "1", "debz-recovery-b", try support.path(fixture.allocator, name, "second"), .{
        .declarations = "interest-noawait debz-b\n",
    });
    try scenario.seed(first);
    try scenario.seed(second);
    const helper_before = try helperIdentity(fixture, scenario.native_root);
    const source = try support.makePackage(fixture, arch, "1", source_name, try support.path(fixture.allocator, name, "source"), .{
        .declarations = "activate-noawait debz-a\n",
    });
    const reference_run = try support.path(fixture.allocator, name, "reference-install");
    try fixture.directory(reference_run);
    if (try support.reference(fixture, dpkg, scenario.reference_root, .{
        .operation = "install", .archives = &.{source}, .triggers = true,
    }, reference_run) != 0) return error.UnexpectedReferenceTriggerExit;
    if (try invoke(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "crash"), .{
        .operation = "install", .archive = source, .crash_at = "after_trigger_outcome",
        .caller_owned = isolated, .isolated_helper = isolated, .trigger_execution = true,
    }) != null) return error.CrashProducedCompletionReport;
    var intent = try debz.native_recovery.decodeIntent(fixture.allocator, try bytes(fixture, scenario.native_root, intent_path, 16 * 1024 * 1024));
    defer intent.deinit();
    const request = try originalRequestFor(fixture, scenario.native_root, intent.intent, isolated, isolated, source);
    const archive_relative = source[fixture.path.len + 1 ..];
    try fixture.dir.deleteFile(fixture.io, archive_relative);
    try support.absent(fixture, archive_relative);
    var recovered = try expectReport(try invoke(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "fresh-recovery"), .{
        .operation = "recover", .caller_owned = isolated, .isolated_helper = isolated, .trigger_execution = true,
    }), "applied", null);
    defer recovered.deinit();
    const comparison = try support.path(fixture.allocator, name, "comparison");
    try fixture.directory(comparison);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    try verifyProofFor(fixture, scenario.native_root, recovered.value, intent.intent, request, .succeeded, true, isolated, isolated);
    try sameHelper(fixture, scenario.native_root, helper_before);
    const proof_bytes = try bytes(fixture, scenario.native_root, provenance_path, 16 * 1024 * 1024);
    var proof = try debz.native_provenance.decode(fixture.allocator, proof_bytes);
    defer proof.deinit();
    var found = false;
    for (proof.document.evidence_files) |file| {
        if (file.kind != .trigger_events) continue;
        if (found) return error.DuplicateTriggerEvents;
        found = true;
        const raw = try bytes(fixture, scenario.native_root, file.path, 1024 * 1024);
        var events = try std.json.parseFromSlice(debz.native_recovery.TriggerEventsDocument, fixture.allocator, raw, .{ .allocate = .alloc_always });
        defer events.deinit();
        try same(&events.value.digest_sha256, &proof.document.trigger_evidence_sha256);
        if (events.value.events.len != 2) return error.IncorrectTriggerEventCount;
        const observed = events.value.events;
        if (observed[0].origin != .automatic or observed[1].origin != .dynamic or
            observed[0].activation_awaits or observed[1].activation_awaits)
            return error.IncorrectTriggerEventOrigin;
        try same(observed[0].source_package, source_name);
        try same(observed[0].trigger, "debz-a");
        try same(observed[1].source_package, first_name);
        try same(observed[1].trigger, "debz-b");
    }
    if (!found) return error.MissingTriggerEvents;
    const package_before = try snapshot(fixture, scenario.native_root);
    var repeated = try expectReport(try invoke(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "repeat"), .{
        .operation = "recover", .caller_owned = isolated, .isolated_helper = isolated, .trigger_execution = true,
    }), "applied", null);
    defer repeated.deinit();
    try unchanged(fixture, scenario.native_root, package_before);
    try same(try bytes(fixture, scenario.native_root, provenance_path, 16 * 1024 * 1024), proof_bytes);
    if (isolated) {
        var acknowledged = try expectReport(try invoke(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "ack"), .{
            .operation = "recover", .caller_owned = true, .isolated_helper = true, .trigger_execution = true, .acknowledge = true,
        }), "applied", null);
        defer acknowledged.deinit();
        try missing(fixture, scenario.native_root, operation_path);
        try missing(fixture, scenario.native_root, intent_path);
        try unchanged(fixture, scenario.native_root, package_before);
    } else {
        try missing(fixture, scenario.native_root, operation_path);
        try missing(fixture, scenario.native_root, intent_path);
    }
    try same(try bytes(fixture, scenario.native_root, provenance_path, 16 * 1024 * 1024), proof_bytes);
    try sameHelper(fixture, scenario.native_root, helper_before);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    std.debug.print("{s}: exit 86, pinned dpkg and exact automatic/dynamic receipt order with immutable recovery\n", .{name});
}

const Corruption = enum { intent, progress, artifact, managed_root, completed_phase };

fn corruptedOrdinary(
    fixture: *foundation.Fixture,
    driver: []const u8,
    arch: []const u8,
    corruption: Corruption,
) !void {
    const name = switch (corruption) {
        .intent => "changed-intent",
        .progress => "changed-progress",
        .artifact => "changed-artifact",
        .managed_root => "changed-managed-root",
        .completed_phase => "changed-completed-phase",
    };
    const root = try fixture.makeRoot(try support.path(fixture.allocator, name, "native"), arch);
    try installTools(fixture, root);
    try fixture.directory(try relative(fixture, root, "var/log"));
    const helper_before = try helperIdentity(fixture, root);
    const archive = try support.makePackage(fixture, arch, "1", foundation.package, try support.path(fixture.allocator, name, "package"), .{
        .no_scripts = corruption != .completed_phase,
        .scripts = .{ .only_postinst = corruption == .completed_phase },
    });
    const crash = switch (corruption) {
        .managed_root => "during_filesystem_publication",
        .completed_phase => "after_script_prepared",
        else => "after_execution_intent",
    };
    if (try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "crash"), .{
        .operation = "install", .archive = archive, .crash_at = crash,
        .caller_owned = false, .isolated_helper = false,
    }) != null) return error.CrashProducedCompletionReport;
    var intent = try debz.native_recovery.decodeIntent(fixture.allocator, try bytes(fixture, root, intent_path, 16 * 1024 * 1024));
    defer intent.deinit();
    _ = try originalRequestFor(fixture, root, intent.intent, false, false, archive);
    var initial = try document(fixture, root, operation_path);
    defer initial.deinit();
    try same(try text(initial.value, "attempt_id"), &intent.intent.attempt_id);
    const original_claim = try stickyActiveClaim(fixture, root);
    const script_path = "var/lib/debz/native-lifecycle-script-v1.json";
    const original_script = bytes(fixture, root, script_path, 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => null,
        else => return err,
    };
    switch (corruption) {
        .intent => {
            const before = try bytes(fixture, root, intent_path, 16 * 1024 * 1024);
            try fixture.write(try relative(fixture, root, intent_path), before[0 .. before.len / 2], 0o600);
        },
        .progress => {
            const before = try bytes(fixture, root, debz.native_recovery.progress_path, 16 * 1024 * 1024);
            const changed = try std.mem.concat(fixture.allocator, u8, &.{ before, "corrupt\n" });
            try fixture.write(try relative(fixture, root, debz.native_recovery.progress_path), changed, 0o600);
        },
        .artifact => {
            var artifact: ?debz.native_recovery.Blob = null;
            for (intent.intent.blobs) |blob| {
                if (blob.kind != .artifact) continue;
                if (artifact != null) return error.DuplicateRetainedArtifact;
                artifact = blob;
            }
            const retained = artifact orelse return error.MissingRetainedArtifact;
            const raw = try bytes(fixture, root, retained.storage_path, 16 * 1024 * 1024);
            if (raw.len == 0) return error.EmptyRetainedArtifact;
            raw[0] = 'X';
            try fixture.write(try relative(fixture, root, retained.storage_path), raw, retained.mode);
        },
        .managed_root, .completed_phase => try fixture.write(
            try relative(fixture, root, "usr/share/" ++ foundation.package ++ "/data"),
            "external replacement\n", 0o644,
        ),
    }
    const archive_relative = archive[fixture.path.len + 1 ..];
    try fixture.dir.deleteFile(fixture.io, archive_relative);
    try support.absent(fixture, archive_relative);
    const package_before = try snapshot(fixture, root);
    var first = try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "fresh-recovery"), .{
        .operation = "recover", .caller_owned = false, .isolated_helper = false,
    }), "recovery_required", null);
    defer first.deinit();
    try unchanged(fixture, root, package_before);
    try sameHelper(fixture, root, helper_before);
    if (original_script) |script| {
        try same(try bytes(fixture, root, script_path, 1024 * 1024), script);
    } else try missing(fixture, root, script_path);
    var active = try document(fixture, root, operation_path);
    defer active.deinit();
    try same(try text(active.value, "attempt_id"), &intent.intent.attempt_id);
    try same(try stickyActiveClaim(fixture, root), original_claim);
    try missing(fixture, root, completion_path);
    const stable = try rootWithoutActiveClaim(fixture, root);
    for (0..2) |index| {
        var blocked = try expectReport(try invoke(fixture, driver, root, arch, try std.fmt.allocPrint(fixture.allocator, "{s}/repeat-{d}", .{ name, index }), .{
            .operation = "recover", .caller_owned = false, .isolated_helper = false,
        }), "recovery_required", null);
        defer blocked.deinit();
        try unchanged(fixture, root, package_before);
        try sameHelper(fixture, root, helper_before);
        if (original_script) |script| {
            try same(try bytes(fixture, root, script_path, 1024 * 1024), script);
        } else try missing(fixture, root, script_path);
        var claim = try document(fixture, root, operation_path);
        defer claim.deinit();
        try same(try text(claim.value, "attempt_id"), &intent.intent.attempt_id);
        try same(try stickyActiveClaim(fixture, root), original_claim);
        try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, root));
        try missing(fixture, root, completion_path);
    }
    const absent_package = [_]foundation.PackageIdentity{.{ .name = "debz-recovery-absent", .architecture = arch }};
    var refused = try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "blocked-purge"), .{
        .operation = "purge", .packages = &absent_package, .caller_owned = false, .isolated_helper = false,
    }), "recovery_required", null);
    defer refused.deinit();
    try unchanged(fixture, root, package_before);
    try sameHelper(fixture, root, helper_before);
    try same(try stickyActiveClaim(fixture, root), original_claim);
    if (original_script) |script| {
        try same(try bytes(fixture, root, script_path, 1024 * 1024), script);
    } else try missing(fixture, root, script_path);
    std.debug.print("{s}: real exit 86, archived artifact evicted; repeated tamper refusals kept package/helper bytes intact\n", .{name});
}

fn caseRun(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    name: []const u8,
    crash: []const u8,
    unknown: bool,
    tamper: ?enum { helper_source, request },
) !void {
    const reference_name = try support.path(fixture.allocator, name, "reference");
    defer fixture.allocator.free(reference_name);
    const native_name = try support.path(fixture.allocator, name, "native");
    defer fixture.allocator.free(native_name);
    const expected = try fixture.makeRoot(reference_name, arch);
    defer fixture.allocator.free(expected);
    const root = try fixture.makeRoot(native_name, arch);
    defer fixture.allocator.free(root);
    const reference_log_dir = try relative(fixture, expected, "var/log");
    defer fixture.allocator.free(reference_log_dir);
    const native_log_dir = try relative(fixture, root, "var/log");
    defer fixture.allocator.free(native_log_dir);
    try fixture.directory(reference_log_dir);
    try fixture.directory(native_log_dir);
    try installTools(fixture, expected);
    try installTools(fixture, root);
    const original_helper = try helperIdentity(fixture, root);
    const packages = try support.path(fixture.allocator, name, "package");
    defer fixture.allocator.free(packages);
    const config = "#!/bin/sh\n# config:1\nprintf '%s\\n' 'config:1' >> /config-invoked\nexit 97\n";
    const archive = try support.makePackage(fixture, arch, "1", foundation.package, packages, if (unknown) .{
        .preinst_append = "printf 'new payload\\n' > /usr/share/debz-native-demo/data\n",
        .config_content = config,
    } else .{});
    defer fixture.allocator.free(archive);
    const payload_path = "usr/share/" ++ foundation.package ++ "/data";
    if (unknown) {
        const fixture_payload = try relative(fixture, root, payload_path);
        defer fixture.allocator.free(fixture_payload);
        try fixture.write(fixture_payload, "old payload\n", 0o644);
    }
    const reference_log = try support.path(fixture.allocator, name, "reference-run");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    if (!unknown and try support.reference(fixture, dpkg, expected, .{
        .operation = "install",
        .archives = &.{archive},
    }, reference_log) != 0) return error.ReferenceInstallFailed;
    const crash_output = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_output);
    _ = try invoke(fixture, driver, root, arch, crash_output, .{
        .operation = "install",
        .archive = archive,
        .crash_at = crash,
    });
    if (unknown) {
        const changed = try bytes(fixture, root, payload_path, 64);
        defer fixture.allocator.free(changed);
        try same(changed, "new payload\n");
        try same(try bytes(fixture, root, "var/lib/dpkg/tmp.ci/config", 64 * 1024), config);
        try missing(fixture, root, "var/lib/dpkg/info/" ++ foundation.package ++ ".config");
        try missing(fixture, root, "config-invoked");
    }
    const intent_data = try bytes(fixture, root, intent_path, 16 * 1024 * 1024);
    defer fixture.allocator.free(intent_data);
    var intent = try debz.native_recovery.decodeIntent(fixture.allocator, intent_data);
    defer intent.deinit();
    const request = try originalRequest(fixture, root, intent.intent);
    defer fixture.allocator.free(request);
    var caller = try document(fixture, root, operation_path);
    defer caller.deinit();
    try same(try text(caller.value, "attempt_id"), &intent.intent.attempt_id);
    const archive_relative = archive[fixture.path.len + 1 ..];
    try fixture.dir.deleteFile(fixture.io, archive_relative);
    try support.absent(fixture, archive_relative);
    if (tamper) |changed| {
        var decoded = try debz.native_execution_request.decodePersisted(fixture.allocator, request);
        defer decoded.deinit();
        const source = switch (changed) {
            .helper_source => (decoded.helper() orelse return error.MissingHelperBinding).source_path,
            .request => for (intent.intent.blobs) |blob| {
                if (blob.kind == .request) break blob.storage_path;
            } else return error.MissingOriginalHelperRequest,
        };
        const path = try relative(fixture, root, source);
        defer fixture.allocator.free(path);
        if (changed == .helper_source) {
            try fixture.write(path, "altered cached helper\n", 0o500);
        } else {
            try fixture.dir.deleteFile(fixture.io, path);
        }
        const before = try snapshot(fixture, root);
        defer fixture.allocator.free(before);
        const output = try support.path(fixture.allocator, name, "tampered-recovery");
        defer fixture.allocator.free(output);
        var refused = try expectReport(try invoke(fixture, driver, root, arch, output, .{
            .operation = "recover",
        }), "recovery_required", if (changed == .helper_source) "HelperDigestMismatch" else null);
        defer refused.deinit();
        try unchanged(fixture, root, before);
        try sameHelper(fixture, root, original_helper);
        std.debug.print("{s}: altered helper/request refused without package mutation\n", .{name});
        return;
    }

    const before_recovery = try snapshot(fixture, root);
    defer fixture.allocator.free(before_recovery);
    if (std.mem.eql(u8, crash, "after_execution_intent")) {
        const downgrade_name = try support.path(fixture.allocator, name, "downgraded-helper");
        defer fixture.allocator.free(downgrade_name);
        var downgraded = try expectReport(try invoke(fixture, driver, root, arch, downgrade_name, .{
            .operation = "recover",
            .isolated_helper = false,
        }), "recovery_required", "NativeHelperBindingRequired");
        defer downgraded.deinit();
        try unchanged(fixture, root, before_recovery);
    }

    const recovery_name = try support.path(fixture.allocator, name, "fresh-recovery");
    defer fixture.allocator.free(recovery_name);
    var result = try expectReport(try invoke(fixture, driver, root, arch, recovery_name, .{
        .operation = "recover",
    }), if (unknown) "recovery_required" else "applied", if (unknown) "script_outcome_unknown" else null);
    defer result.deinit();
    if (unknown) {
        try unchanged(fixture, root, before_recovery);
        try same(try bytes(fixture, root, "var/lib/dpkg/tmp.ci/config", 64 * 1024), config);
        try missing(fixture, root, "var/lib/dpkg/info/" ++ foundation.package ++ ".config");
        try missing(fixture, root, "config-invoked");
        try verifyProof(fixture, root, result.value, intent.intent, request, .recovery_required, false);
        const script_path = "var/lib/debz/native-lifecycle-script-v1.json";
        var active = try document(fixture, root, script_path);
        defer active.deinit();
        try same(try text(active.value, "outcome"), "in_flight");
        const trace = try bytes(fixture, root, support.trace, 16 * 1024 * 1024);
        defer fixture.allocator.free(trace);
        if (std.mem.indexOf(u8, trace, foundation.package ++ "@1:preinst\t") == null)
            return error.UnknownScriptWasNotExecuted;
        const selected = [_]foundation.PackageIdentity{.{ .name = "debz-not-present", .architecture = arch }};
        const blocked_name = try support.path(fixture.allocator, name, "blocked-purge");
        defer fixture.allocator.free(blocked_name);
        var repeated = try expectReport(try invoke(fixture, driver, root, arch, blocked_name, .{
            .operation = "purge",
            .packages = &selected,
        }), "recovery_required", null);
        defer repeated.deinit();
        try unchanged(fixture, root, before_recovery);
        try same(try bytes(fixture, root, "var/lib/dpkg/tmp.ci/config", 64 * 1024), config);
        try missing(fixture, root, "var/lib/dpkg/info/" ++ foundation.package ++ ".config");
        try missing(fixture, root, "config-invoked");
        const fixture_payload = try relative(fixture, root, payload_path);
        defer fixture.allocator.free(fixture_payload);
        try fixture.write(fixture_payload, "old payload\n", 0o644);
        if (unchanged(fixture, root, before_recovery)) |_| return error.RolledBackPayloadWasAccepted else |err| if (err != error.BlockedRecoveryMutatedPackageState) return err;
    } else {
        try sameHelper(fixture, root, original_helper);
        const evidence = try support.path(fixture.allocator, name, "comparison");
        defer fixture.allocator.free(evidence);
        try fixture.directory(evidence);
        try foundation.compare(fixture.*, expected, root, evidence);
        try verifyProof(fixture, root, result.value, intent.intent, request, .succeeded, true);
        const receipt_before = try bytes(fixture, root, provenance_path, 16 * 1024 * 1024);
        defer fixture.allocator.free(receipt_before);
        const completed_state = try snapshot(fixture, root);
        defer fixture.allocator.free(completed_state);
        try missing(fixture, root, completion_path);
        var still_owned = try document(fixture, root, operation_path);
        defer still_owned.deinit();
        try same(try text(still_owned.value, "outcome"), "pending");
        const repeat_name = try support.path(fixture.allocator, name, "repeat");
        defer fixture.allocator.free(repeat_name);
        var repeated = try expectReport(try invoke(fixture, driver, root, arch, repeat_name, .{
            .operation = "recover",
        }), "applied", null);
        defer repeated.deinit();
        try unchanged(fixture, root, completed_state);
        if (std.mem.eql(u8, crash, "after_script_outcome")) {
            const trace = try bytes(fixture, root, support.trace, 16 * 1024 * 1024);
            defer fixture.allocator.free(trace);
            const doubled = try std.mem.concat(fixture.allocator, u8, &.{ trace, trace });
            defer fixture.allocator.free(doubled);
            const trace_relative = try relative(fixture, root, support.trace);
            defer fixture.allocator.free(trace_relative);
            try fixture.write(trace_relative, doubled, 0o644);
            if (foundation.compare(fixture.*, expected, root, evidence)) |_| return error.DuplicateTraceAccepted else |err| if (err != error.NativeDpkgMismatch) return err;
            try fixture.write(trace_relative, trace, 0o644);
            try foundation.compare(fixture.*, expected, root, evidence);
        }
        const ack_name = try support.path(fixture.allocator, name, "caller-ack");
        defer fixture.allocator.free(ack_name);
        var acknowledged = try expectReport(try invoke(fixture, driver, root, arch, ack_name, .{
            .operation = "recover",
            .acknowledge = true,
        }), "applied", null);
        defer acknowledged.deinit();
        try unchanged(fixture, root, completed_state);
        try missing(fixture, root, operation_path);
        try missing(fixture, root, intent_path);
        var completion = try document(fixture, root, completion_path);
        defer completion.deinit();
        try same(try text(completion.value, "attempt_id"), &intent.intent.attempt_id);
        const receipt_after = try bytes(fixture, root, provenance_path, 16 * 1024 * 1024);
        defer fixture.allocator.free(receipt_after);
        if (!std.mem.eql(u8, receipt_before, receipt_after)) return error.AcknowledgmentReplacedReceipt;
        try sameHelper(fixture, root, original_helper);
    }
    std.debug.print("{s}: real exit-86, archive eviction, helper-bound recovery and state checks passed\n", .{name});
}

fn knownFailure(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    boundary: []const u8,
) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "postinst-failure-{s}", .{boundary});
    defer fixture.allocator.free(name);
    const reference_name = try support.path(fixture.allocator, name, "reference");
    defer fixture.allocator.free(reference_name);
    const native_name = try support.path(fixture.allocator, name, "native");
    defer fixture.allocator.free(native_name);
    const expected = try fixture.makeRoot(reference_name, arch);
    defer fixture.allocator.free(expected);
    const root = try fixture.makeRoot(native_name, arch);
    defer fixture.allocator.free(root);
    try installTools(fixture, expected);
    try installTools(fixture, root);
    const original_helper = try helperIdentity(fixture, root);
    for ([_][]const u8{ expected, root }) |target| {
        const log_dir = try relative(fixture, target, "var/log");
        defer fixture.allocator.free(log_dir);
        try fixture.directory(log_dir);
        const failure_path = try relative(fixture, target, support.failure);
        defer fixture.allocator.free(failure_path);
        try support.fixtureFile(fixture, failure_path, foundation.package ++ "@1:postinst:configure\n", 0o644);
    }
    const package_dir = try support.path(fixture.allocator, name, "package");
    defer fixture.allocator.free(package_dir);
    const archive = try support.makePackage(fixture, arch, "1", foundation.package, package_dir, .{});
    defer fixture.allocator.free(archive);
    const reference_run = try support.path(fixture.allocator, name, "reference-run");
    defer fixture.allocator.free(reference_run);
    try fixture.directory(reference_run);
    if (try support.reference(fixture, dpkg, expected, .{
        .operation = "install",
        .archives = &.{archive},
    }, reference_run) != 1) return error.ExpectedReferencePostinstFailure;

    const crash_output = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_output);
    _ = try invoke(fixture, driver, root, arch, crash_output, .{
        .operation = "install",
        .archive = archive,
        .crash_at = boundary,
    });
    var claim = try document(fixture, root, operation_path);
    defer claim.deinit();
    if (std.mem.eql(u8, try text(claim.value, "state"), "completed"))
        return error.FailedScriptClearedRootClaim;
    try same(try text(claim.value, "outcome"), "pending");

    var progress = try document(fixture, root, "var/lib/debz/native-execution-progress-v1.log");
    defer progress.deinit();
    const records = try field(progress.value, "records");
    if (records != .array) return error.InvalidRecoveryProgress;
    var known_exit = false;
    var failure_step: ?i64 = null;
    for (records.array.items) |record| {
        const action = try field(record, "action");
        if (!std.mem.eql(u8, try text(action, "kind"), "script")) continue;
        if (std.mem.eql(u8, try text(record, "stage"), "outcome") and
            std.mem.eql(u8, try text(record, "result"), "exited"))
            known_exit = true;
        if (std.mem.eql(u8, try text(record, "stage"), "completed") and
            std.mem.eql(u8, try text(record, "result"), "failed"))
        {
            if (failure_step != null) return error.DuplicateFailedScript;
            const step = try field(action, "program_step");
            if (step != .integer) return error.InvalidRecoveryProgress;
            failure_step = step.integer;
        }
    }
    if (!known_exit) return error.MissingKnownScriptExit;
    if (std.mem.eql(u8, boundary, "after_script_failure_state")) {
        const step = failure_step orelse return error.MissingFailedScriptState;
        var applied = false;
        for (records.array.items) |record| {
            const action = try field(record, "action");
            if (!std.mem.eql(u8, try text(action, "kind"), "database")) continue;
            const program_step = try field(action, "program_step");
            if (program_step != .integer) return error.InvalidRecoveryProgress;
            if (program_step.integer == step and
                std.mem.eql(u8, try text(record, "stage"), "completed") and
                std.mem.eql(u8, try text(record, "result"), "applied"))
                applied = true;
        }
        if (!applied) return error.FailedScriptStateNotDurable;
        const status = try bytes(fixture, root, "var/lib/dpkg/status", 16 * 1024 * 1024);
        defer fixture.allocator.free(status);
        if (std.mem.indexOf(u8, status, "Status: install ok half-configured") == null)
            return error.MissingHalfConfiguredStatus;
    }
    const intent_data = try bytes(fixture, root, intent_path, 16 * 1024 * 1024);
    defer fixture.allocator.free(intent_data);
    var intent = try debz.native_recovery.decodeIntent(fixture.allocator, intent_data);
    defer intent.deinit();
    const request = try originalRequest(fixture, root, intent.intent);
    defer fixture.allocator.free(request);
    const archive_relative = archive[fixture.path.len + 1 ..];
    try fixture.dir.deleteFile(fixture.io, archive_relative);
    try support.absent(fixture, archive_relative);

    const recovery_name = try support.path(fixture.allocator, name, "fresh-recovery");
    defer fixture.allocator.free(recovery_name);
    var result = try expectReport(try invoke(fixture, driver, root, arch, recovery_name, .{
        .operation = "recover",
    }), "script_failed", null);
    defer result.deinit();
    const evidence = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(evidence);
    try fixture.directory(evidence);
    try foundation.compare(fixture.*, expected, root, evidence);
    try verifyProof(fixture, root, result.value, intent.intent, request, .failed, true);
    try sameHelper(fixture, root, original_helper);
    const before = try snapshot(fixture, root);
    defer fixture.allocator.free(before);
    const proof = try bytes(fixture, root, provenance_path, 16 * 1024 * 1024);
    defer fixture.allocator.free(proof);
    const repeat_name = try support.path(fixture.allocator, name, "repeat");
    defer fixture.allocator.free(repeat_name);
    var repeated = try expectReport(try invoke(fixture, driver, root, arch, repeat_name, .{
        .operation = "recover",
    }), "script_failed", null);
    defer repeated.deinit();
    try unchanged(fixture, root, before);
    const ack_name = try support.path(fixture.allocator, name, "caller-ack");
    defer fixture.allocator.free(ack_name);
    var acknowledged = try expectReport(try invoke(fixture, driver, root, arch, ack_name, .{
        .operation = "recover",
        .acknowledge = true,
    }), "script_failed", null);
    defer acknowledged.deinit();
    try unchanged(fixture, root, before);
    try missing(fixture, root, operation_path);
    try missing(fixture, root, intent_path);
    var completion = try document(fixture, root, completion_path);
    defer completion.deinit();
    try same(try text(completion.value, "attempt_id"), &intent.intent.attempt_id);
    const retained_proof = try bytes(fixture, root, provenance_path, 16 * 1024 * 1024);
    defer fixture.allocator.free(retained_proof);
    if (!std.mem.eql(u8, proof, retained_proof)) return error.FailedRecoveryChangedProvenance;
    try sameHelper(fixture, root, original_helper);
    std.debug.print("{s}: durable failed postinst, fresh recovery and pinned dpkg parity passed\n", .{name});
}

fn namespaceGate(allocator: std.mem.Allocator, io: std.Io) !void {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ "/usr/bin/unshare", "--mount", "--", "/bin/true" },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) return error.RequiresMountNamespace;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    var pinned: ?[]const u8 = null;
    while (args.next()) |argument| {
        if (std.mem.eql(u8, argument, "--reference-dpkg")) {
            if (pinned != null) return error.DuplicateReference;
            pinned = args.next() orelse return error.MissingReferencePath;
        } else return error.InvalidArguments;
    }
    const reference = try support.prerequisites(init, allocator, pinned);
    defer allocator.free(reference.architecture);
    try namespaceGate(allocator, init.io);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed after helper failure: {s}\n", .{@errorName(err)});
    try crashTransport(&fixture, driver, reference.architecture);
    try completedWithoutLiveHelper(&fixture, driver, reference.executable, reference.architecture);
    try missingPackageOwnedHelper(&fixture, driver, reference.architecture);
    try rehashedCallerPolicy(&fixture, driver, reference.architecture);
    try afterActiveClearLegacyEvidence(&fixture, driver, reference.executable, reference.architecture);
    for ([_][]const u8{
        "after_execution_intent", "during_filesystem_publication",
        "after_script_outcome", "after_provenance",
    }) |boundary| {
        const name = try std.fmt.allocPrint(fixture.allocator, "caller-{s}", .{boundary});
        try recoveredOrdinary(&fixture, driver, reference.executable, reference.architecture, .{
            .name = name, .crash = boundary, .caller_owned = true,
        });
    }
    for ([_]bool{ true, false }) |isolated|
        try recoveredOrdinary(&fixture, driver, reference.executable, reference.architecture, .{
            .name = if (isolated) "typed-runtime-known-failure" else "caller-known-failure",
            .crash = "after_failure_outcome",
            .caller_owned = true,
            .isolated_helper = isolated,
            .known_preinst_failure = true,
        });
    for ([_][]const u8{
        "after_execution_intent", "during_filesystem_publication", "during_database_publication",
        "after_script_prepared", "after_script_outcome", "after_provenance",
    }) |boundary| try recoveredOrdinary(&fixture, driver, reference.executable, reference.architecture, .{
        .name = boundary, .crash = boundary,
    });
    try recoveredOrdinary(&fixture, driver, reference.executable, reference.architecture, .{
        .name = "known-failure-compensation",
        .crash = "after_failure_outcome",
        .known_preinst_failure = true,
    });
    try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, false);
    try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, true);
    try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, false);
    try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, true);
    for ([_]Corruption{ .intent, .progress, .artifact, .managed_root, .completed_phase }) |which|
        try corruptedOrdinary(&fixture, driver, reference.architecture, which);
    for ([_]struct { name: []const u8, crash: []const u8, unknown: bool = false }{
        .{ .name = "helper-intent", .crash = "after_execution_intent" },
        .{ .name = "helper-outcome", .crash = "after_script_outcome" },
        .{ .name = "helper-provenance", .crash = "after_provenance" },
        .{ .name = "helper-unknown-script", .crash = "after_script_return_before_outcome", .unknown = true },
    }) |case| try caseRun(&fixture, driver, reference.executable, reference.architecture, case.name, case.crash, case.unknown, null);
    try caseRun(&fixture, driver, reference.executable, reference.architecture, "helper-source-drift", "after_execution_intent", false, .helper_source);
    try caseRun(&fixture, driver, reference.executable, reference.architecture, "helper-request-missing", "after_execution_intent", false, .request);
    for ([_][]const u8{ "after_failure_outcome", "after_script_failure_state" }) |boundary|
        try knownFailure(&fixture, driver, reference.executable, reference.architecture, boundary);
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
