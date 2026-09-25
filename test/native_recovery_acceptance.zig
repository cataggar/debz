const std = @import("std");
const debz = @import("debz");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const family = @import("native_recovery_family.zig");
const oracle = @import("native_recovery_oracle.zig");
const options = @import("native_test_options");

const namespace = "var/lib/debz/";
const operation_path = namespace ++ "root-operation-v1.json";
const intent_path = namespace ++ "native-execution-intent-v1.json";
const completion_path = namespace ++ "root-operation-completion-v1.json";
const provenance_path = namespace ++ "native-transaction-provenance-v1.json";
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
    crash_at: ?[]const u8 = null,
    completion_crash: ?[]const u8 = null,
    core: bool = false,
    deadline_ms: ?u64 = null,
    acknowledge: bool = false,
    packages: []const foundation.PackageIdentity = &.{},
};

const HelperIdentity = struct { inode: u64, sha256: [32]u8 };

fn helperIdentity(fixture: *foundation.Fixture, root: []const u8) !HelperIdentity {
    const path = try relative(fixture, root, helper_path);
    defer fixture.allocator.free(path);
    var file = try fixture.dir.openFile(fixture.io, path, .{ .follow_symlinks = false });
    defer file.close(fixture.io);
    const inode = (try file.stat(fixture.io)).inode;
    var reader = file.reader(fixture.io, &.{});
    const bytes = try reader.interface.allocRemaining(fixture.allocator, .limited(8 * 1024 * 1024));
    defer fixture.allocator.free(bytes);
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &sha256, .{});
    return .{ .inode = inode, .sha256 = sha256 };
}

fn assertHelperUnchanged(fixture: *foundation.Fixture, root: []const u8, original: HelperIdentity) !void {
    const current = try helperIdentity(fixture, root);
    if (current.inode != original.inode or !std.mem.eql(u8, &current.sha256, &original.sha256))
        return error.PackageOwnedHelperReplaced;
}

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidEvidence;
    return value.object.get(name) orelse error.MissingEvidenceField;
}

fn text(value: std.json.Value, name: []const u8) ![]const u8 {
    const item = try field(value, name);
    if (item != .string) return error.InvalidEvidenceField;
    return item.string;
}

fn boolean(value: std.json.Value, name: []const u8) !bool {
    const item = try field(value, name);
    if (item != .bool) return error.InvalidEvidenceField;
    return item.bool;
}

fn equal(actual: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, actual, expected)) {
        std.debug.print("expected {s}, got {s}\n", .{ expected, actual });
        return error.UnexpectedRecoveryEvidence;
    }
}

fn document(fixture: *foundation.Fixture, path: []const u8) !std.json.Parsed(std.json.Value) {
    const bytes = try support.read(fixture, path, 16 * 1024 * 1024);
    defer fixture.allocator.free(bytes);
    return std.json.parseFromSlice(std.json.Value, fixture.allocator, bytes, .{
        .allocate = .alloc_always,
    });
}

fn relative(fixture: *foundation.Fixture, root: []const u8, name: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, root, fixture.path) or root.len <= fixture.path.len or
        root[fixture.path.len] != '/') return error.InvalidFixtureRoot;
    return support.path(fixture.allocator, root[fixture.path.len + 1 ..], name);
}

fn rootDocument(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !std.json.Parsed(std.json.Value) {
    const path = try relative(fixture, root, name);
    defer fixture.allocator.free(path);
    return document(fixture, path);
}

fn rootBytes(fixture: *foundation.Fixture, root: []const u8, name: []const u8) ![]u8 {
    const path = try relative(fixture, root, name);
    defer fixture.allocator.free(path);
    return support.read(fixture, path, 16 * 1024 * 1024);
}

fn rootAbsent(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !void {
    const path = try relative(fixture, root, name);
    defer fixture.allocator.free(path);
    try support.absent(fixture, path);
}

fn snapshot(fixture: *foundation.Fixture, root: []const u8) ![]u8 {
    return foundation.capture(fixture.allocator, fixture.io, root);
}

fn unchanged(fixture: *foundation.Fixture, root: []const u8, before: []const u8) !void {
    const after = try snapshot(fixture, root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.RecoveryChangedPackageState;
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
    const payload = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = root,
        .architecture = arch,
        .operation = input.operation,
        .archives = archives,
        .packages = input.packages,
        .report = report_path,
        .recovery = true,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = input.core,
        .crash_at = input.crash_at,
        .core_completion_crash = input.completion_crash,
        .deadline_after_ms = input.deadline_ms,
        .acknowledge_native = input.acknowledge,
    }, .{});
    defer fixture.allocator.free(payload);
    try fixture.write(request_relative, payload, 0o644);
    try fixture.environment.put("DEBZ_NATIVE_LIFECYCLE_REQUEST", request_path);

    const log = try support.path(fixture.allocator, destination, "native.log");
    defer fixture.allocator.free(log);
    const result = std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", driver },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    }) catch |err| {
        std.debug.print("{s}: driver failed ({s}), fixture {s}\n", .{ destination, @errorName(err), fixture.path });
        return err;
    };
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const combined = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    defer fixture.allocator.free(combined);
    try fixture.write(log, combined, 0o644);
    const crashing = input.crash_at != null or input.completion_crash != null;
    const expected_exit: u8 = if (crashing) 86 else 0;
    if (result.term != .exited or result.term.exited != expected_exit) {
        std.debug.print("{s}: exit {any}, expected {d}; {s}/{s}:\n{s}\n", .{
            destination,                                            result.term, expected_exit, fixture.path, log,
            combined[combined.len - @min(combined.len, 12_000) ..],
        });
        return error.UnexpectedNativeProcessExit;
    }
    if (crashing) {
        try support.absent(fixture, report_relative);
        return null;
    }
    const bytes = try support.read(fixture, report_relative, 64 * 1024);
    defer fixture.allocator.free(bytes);
    return try std.json.parseFromSlice(Report, fixture.allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
}

fn expectedReport(report: ?std.json.Parsed(Report), outcome: []const u8, detail: ?[]const u8) !std.json.Parsed(Report) {
    const result = report orelse return error.MissingNativeReport;
    errdefer {
        var bad = result;
        bad.deinit();
    }
    try equal(result.value.outcome, outcome);
    if (detail) |expected| try equal(result.value.detail, expected);
    return result;
}

fn installHelper(fixture: *foundation.Fixture, root: []const u8) !void {
    const root_relative = root[fixture.path.len + 1 ..];
    try support.copyProgram(fixture, root_relative, "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
}

fn assertBinding(
    fixture: *foundation.Fixture,
    root: []const u8,
    report: Report,
    original: std.json.Value,
    intent: std.json.Value,
) !void {
    const attempt = try text(original, "attempt_id");
    const program = try text(intent, "program_sha256");
    try equal(report.attempt_id orelse return error.MissingReportBinding, attempt);
    try equal(report.program_sha256 orelse return error.MissingReportBinding, program);
    try equal(report.provenance_path orelse return error.MissingReportBinding, provenance_path);
    var proof = try rootDocument(fixture, root, provenance_path);
    defer proof.deinit();
    try equal(try text(proof.value, "backend"), "native");
    try equal(try text(proof.value, "install_root"), root);
    try equal(try text(proof.value, "attempt_id"), attempt);
    try equal(try text(proof.value, "program_sha256"), program);
    for ([_][]const u8{
        "authorization_sha256",     "root_identity_sha256", "exact_lock_sha256",
        "artifact_evidence_sha256",
    }) |name| try equal(try text(proof.value, name), try text(intent, name));
    try equal(try text(proof.value, "execution_intent_sha256"), try text(intent, "digest_sha256"));
    for ([_][]const u8{ "request_sha256", "policy_sha256" }) |name|
        try equal(try text(proof.value, name), try text(original, name));
    try equal(try text(proof.value, "initial_database_generation_sha256"), try text(intent, "database_generation_sha256"));
    const proof_bytes = try rootBytes(fixture, root, provenance_path);
    defer fixture.allocator.free(proof_bytes);
    var typed_proof = try debz.native_provenance.decode(fixture.allocator, proof_bytes);
    defer typed_proof.deinit();
    var guarded = try foundation.guardedRoot(fixture.io, root);
    defer guarded.close(fixture.io);
    try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, guarded), typed_proof.document);
    const request_file = for (typed_proof.document.evidence_files) |evidence| {
        if (evidence.kind == .execution_request) break evidence;
    } else return error.MissingOriginalCoreRequest;
    const request_bytes = try rootBytes(fixture, root, request_file.path);
    defer fixture.allocator.free(request_bytes);
    var request = try debz.native_execution_request.decodePersisted(fixture.allocator, request_bytes);
    defer request.deinit();
    try equal(&request.execution().caller.attempt_id, attempt);
    try equal(&request.execution().program.program_sha256, program);
    const helper = request.helper() orelse return error.MissingCoreHelperBinding;
    var scripts: usize = 0;
    for (typed_proof.document.evidence_files) |evidence| {
        if (evidence.kind != .script_outcome) continue;
        const raw = try rootBytes(fixture, root, evidence.path);
        defer fixture.allocator.free(raw);
        var outcome = try std.json.parseFromSlice(debz.native_recovery.ScriptOutcome, fixture.allocator, raw, .{
            .allocate = .alloc_always,
        });
        defer outcome.deinit();
        try debz.native_recovery.validateScriptOutcome(outcome.value);
        try oracle.validateHelperInvocation(fixture.allocator, root, helper.source_path, helper.target_path, helper.sha256,
            request.execution().program.script_policy_sha256, .{
                .package = outcome.value.package,
                .version = outcome.value.package_version,
                .architecture = outcome.value.architecture,
                .kind = @tagName(outcome.value.kind),
                .source = outcome.value.source,
                .arguments = outcome.value.arguments,
                .environment = outcome.value.environment,
                .script_sha256 = outcome.value.script_sha256,
                .invocation_sha256 = outcome.value.invocation_sha256,
            });
        scripts += 1;
    }
    if (scripts == 0) return error.MissingCoreScriptOutcome;
    const root_stat = try std.Io.Dir.cwd().statFile(fixture.io, root, .{ .follow_symlinks = false });
    const inode = try field(proof.value, "root_inode");
    if (inode != .integer or inode.integer < 0 or inode.integer != root_stat.inode)
        return error.WrongProvenanceRoot;
}

fn assertCompleted(
    fixture: *foundation.Fixture,
    root: []const u8,
    report: Report,
    original: std.json.Value,
    intent: std.json.Value,
) !void {
    try assertBinding(fixture, root, report, original, intent);
    var proof = try rootDocument(fixture, root, provenance_path);
    defer proof.deinit();
    try equal(try text(proof.value, "outcome"), "succeeded");
    var completion = try rootDocument(fixture, root, completion_path);
    defer completion.deinit();
    try equal(try text(completion.value, "attempt_id"), try text(original, "attempt_id"));
    try equal(try text(try field(completion.value, "journal"), "status"), "absent");
    try equal(
        try text(try field(completion.value, "transaction_provenance"), "document_sha256"),
        try text(proof.value, "digest_sha256"),
    );
    for ([_][]const u8{
        operation_path,                    intent_path,                                    namespace ++ "root-mutation-v1.json",
        namespace ++ "native-recovery-v1", namespace ++ "native-lifecycle-script-v1.json",
    }) |name| try rootAbsent(fixture, root, name);
}

fn coreCases(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    for ([_]struct { crash: []const u8, completion: ?[]const u8 = null, journal: bool = false }{
        .{ .crash = "during_filesystem_publication", .journal = true },
        .{ .crash = "during_database_publication", .journal = true },
        .{ .crash = "after_provenance" },
        .{ .crash = "after_execution_intent", .completion = "after_native_receipt" },
        .{ .crash = "after_execution_intent", .completion = "after_completed_record" },
        .{ .crash = "after_execution_intent", .completion = "after_owed_provenance_document" },
        .{ .crash = "after_execution_intent", .completion = "after_provenance_published" },
        .{ .crash = "after_execution_intent", .completion = "after_native_acknowledged" },
    }) |case| {
        const name = try std.fmt.allocPrint(fixture.allocator, "core-{s}", .{case.completion orelse case.crash});
        defer fixture.allocator.free(name);
        const reference_name = try support.path(fixture.allocator, name, "reference");
        defer fixture.allocator.free(reference_name);
        const native_name = try support.path(fixture.allocator, name, "native");
        defer fixture.allocator.free(native_name);
        const reference_root = try fixture.makeRoot(reference_name, arch);
        defer fixture.allocator.free(reference_root);
        const root = try fixture.makeRoot(native_name, arch);
        defer fixture.allocator.free(root);
        try installHelper(fixture, reference_root);
        try installHelper(fixture, root);
        for ([_][]const u8{ reference_root, root }) |target| {
            try support.copyProgram(fixture, target[fixture.path.len + 1 ..], "/bin/sh", "/bin/sh");
            try fixture.directory(try relative(fixture, target, "var/log"));
        }
        const helper_before = try helperIdentity(fixture, root);
        const packages = try support.path(fixture.allocator, name, "packages");
        defer fixture.allocator.free(packages);
        const archive = try support.makePackage(fixture, arch, "1", foundation.package, packages, .{});
        defer fixture.allocator.free(archive);
        const reference_log = try support.path(fixture.allocator, name, "reference-install");
        defer fixture.allocator.free(reference_log);
        try fixture.directory(reference_log);
        if (try support.reference(fixture, dpkg, reference_root, .{
            .operation = "install",
            .archives = &.{archive},
        }, reference_log) != 0) return error.ReferenceInstallFailed;
        const initial_output = try support.path(fixture.allocator, name, "crash");
        defer fixture.allocator.free(initial_output);
        _ = try invoke(fixture, driver, root, arch, initial_output, .{
            .operation = "install",
            .archive = archive,
            .crash_at = case.crash,
            .core = true,
        });
        var original = try rootDocument(fixture, root, operation_path);
        defer original.deinit();
        var intent = try rootDocument(fixture, root, intent_path);
        defer intent.deinit();
        try equal(try text(original.value, "backend"), "native");
        try equal(try text(original.value, "attempt_id"), try text(intent.value, "attempt_id"));
        if (case.journal) {
            var journal = try rootDocument(fixture, root, namespace ++ "root-mutation-v1.json");
            journal.deinit();
        }
        try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);

        if (case.completion) |boundary| {
            const crash_output = try support.path(fixture.allocator, name, "completion-crash");
            defer fixture.allocator.free(crash_output);
            _ = try invoke(fixture, driver, root, arch, crash_output, .{
                .operation = "recover",
                .core = true,
                .completion_crash = boundary,
            });
            var active = try rootDocument(fixture, root, operation_path);
            defer active.deinit();
            try equal(try text(active.value, "attempt_id"), try text(original.value, "attempt_id"));
            if (std.mem.eql(u8, boundary, "after_native_acknowledged")) {
                try rootAbsent(fixture, root, intent_path);
            } else {
                var pending = try rootDocument(fixture, root, intent_path);
                pending.deinit();
            }
        }
        const before = try snapshot(fixture, root);
        defer fixture.allocator.free(before);
        const finish_output = try support.path(fixture.allocator, name, "fresh-completion");
        defer fixture.allocator.free(finish_output);
        var report = try expectedReport(try invoke(fixture, driver, root, arch, finish_output, .{
            .operation = "recover",
            .core = true,
        }), "applied", null);
        defer report.deinit();
        if (case.completion != null) try unchanged(fixture, root, before);
        try assertHelperUnchanged(fixture, root, helper_before);
        const evidence_output = try support.path(fixture.allocator, name, "comparison");
        defer fixture.allocator.free(evidence_output);
        try fixture.directory(evidence_output);
        try foundation.compare(fixture.*, reference_root, root, evidence_output);
        try assertCompleted(fixture, root, report.value, original.value, intent.value);

        const proof_before = try rootBytes(fixture, root, provenance_path);
        defer fixture.allocator.free(proof_before);
        const completion_before = try rootBytes(fixture, root, completion_path);
        defer fixture.allocator.free(completion_before);
        const settled = try snapshot(fixture, root);
        defer fixture.allocator.free(settled);
        const repeat_output = try support.path(fixture.allocator, name, "repeat");
        defer fixture.allocator.free(repeat_output);
        var repeated = try expectedReport(try invoke(fixture, driver, root, arch, repeat_output, .{
            .operation = "recover",
            .core = true,
        }), "applied", null);
        defer repeated.deinit();
        try unchanged(fixture, root, settled);
        for ([_][]const u8{ provenance_path, completion_path }, [_][]const u8{ proof_before, completion_before }) |path, expected| {
            const observed = try rootBytes(fixture, root, path);
            defer fixture.allocator.free(observed);
            if (!std.mem.eql(u8, observed, expected)) return error.RepeatedRecoveryReplacedReceipt;
        }
        try rootAbsent(fixture, root, operation_path);
        try rootAbsent(fixture, root, intent_path);
        std.debug.print("{s}: real crash, evicted archive, fresh completion and immutable repeat passed\n", .{name});
    }
}

fn coreScriptOutcomes(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    for ([_]bool{ true, false }) |known| {
        const name = if (known) "core-known-preinst-failure" else "core-unknown-script-return";
        var scenario = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
        defer scenario.deinit();
        const packages = try support.path(fixture.allocator, name, "packages");
        defer fixture.allocator.free(packages);
        const archive = try support.makePackage(fixture, arch, "1", foundation.package, packages, .{});
        defer fixture.allocator.free(archive);
        const helper_before = try helperIdentity(fixture, scenario.native_root);
        if (known) {
            for ([_][]const u8{ scenario.reference_root, scenario.native_root }) |root| {
                const marker = try relative(fixture, root, support.failure);
                defer fixture.allocator.free(marker);
                try support.fixtureFile(fixture, marker, foundation.package ++ "@1:preinst:install\n", 0o644);
            }
            const reference_log = try support.path(fixture.allocator, name, "reference-install");
            defer fixture.allocator.free(reference_log);
            try fixture.directory(reference_log);
            if (try support.reference(fixture, dpkg, scenario.reference_root, .{
                .operation = "install",
                .archives = &.{archive},
                .triggers = true,
            }, reference_log) != 1) return error.UnexpectedReferencePreinstFailure;
        }
        const crash_log = try support.path(fixture.allocator, name, "crash");
        defer fixture.allocator.free(crash_log);
        _ = try invoke(fixture, driver, scenario.native_root, arch, crash_log, .{
            .operation = "install",
            .archive = archive,
            .core = true,
            .crash_at = if (known) "after_failure_outcome" else "after_script_return_before_outcome",
        });
        var original = try rootDocument(fixture, scenario.native_root, operation_path);
        defer original.deinit();
        var intent = try rootDocument(fixture, scenario.native_root, intent_path);
        defer intent.deinit();
        try equal(try text(original.value, "attempt_id"), try text(intent.value, "attempt_id"));
        try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
        try support.absent(fixture, archive[fixture.path.len + 1 ..]);
        const before = try snapshot(fixture, scenario.native_root);
        defer fixture.allocator.free(before);
        const recovery_log = try support.path(fixture.allocator, name, "fresh-recovery");
        defer fixture.allocator.free(recovery_log);
        var result = try expectedReport(try invoke(fixture, driver, scenario.native_root, arch, recovery_log, .{
            .operation = "recover",
            .core = true,
        }), if (known) "script_failed" else "recovery_required", null);
        defer result.deinit();
        try assertHelperUnchanged(fixture, scenario.native_root, helper_before);
        if (known) {
            const comparison = try support.path(fixture.allocator, name, "comparison");
            defer fixture.allocator.free(comparison);
            try fixture.directory(comparison);
            try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
            try assertBinding(fixture, scenario.native_root, result.value, original.value, intent.value);
            var proof = try rootDocument(fixture, scenario.native_root, provenance_path);
            defer proof.deinit();
            try equal(try text(proof.value, "outcome"), "failed");
            var completion = try rootDocument(fixture, scenario.native_root, completion_path);
            defer completion.deinit();
            try equal(try text(completion.value, "outcome"), "failed_after_mutation");
            try equal(try text(completion.value, "attempt_id"), try text(original.value, "attempt_id"));
            try equal(try text(try field(completion.value, "transaction_provenance"), "document_sha256"),
                try text(proof.value, "digest_sha256"));
            try rootAbsent(fixture, scenario.native_root, operation_path);
            try rootAbsent(fixture, scenario.native_root, intent_path);
        } else {
            try equal(result.value.detail, "native recovery_required: script_outcome_unknown");
            try unchanged(fixture, scenario.native_root, before);
            var pending = try rootDocument(fixture, scenario.native_root, operation_path);
            defer pending.deinit();
            try equal(try text(pending.value, "attempt_id"), try text(original.value, "attempt_id"));
            try rootAbsent(fixture, scenario.native_root, completion_path);
            const cache = try fixture.absolute("unused-core-family-cache");
            defer fixture.allocator.free(cache);
            const state = try fixture.absolute("unused-core-family-state");
            defer fixture.allocator.free(state);
            _ = fixture.environment.swapRemove("DEBZ_NATIVE_LIFECYCLE_REQUEST");
            defer _ = fixture.environment.swapRemove("DEBZ_NATIVE_WORKFLOW_REQUEST");
            const request: family.FamilyRequest = .{
                .operation = "recover",
                .root = scenario.native_root,
                .architecture = arch,
                .cache = cache,
                .state = state,
            };
            const workflow_log = try support.path(fixture.allocator, name, "family-unknown-recovery");
            defer fixture.allocator.free(workflow_log);
            var refused = try family.workflow(fixture, driver, scenario.native_root, arch, workflow_log, .{
                .family_execution = request,
                .selectors = &.{.{ .name = foundation.package }},
                .capture_evidence = true,
            });
            defer refused.deinit();
            try equal(try text(refused.report.value, "exit_status"), "recovery");
            if ((try field(refused.report.value, "succeeded")) != .bool or
                (try field(refused.report.value, "succeeded")).bool or
                (try field(refused.report.value, "changed")) != .bool or
                !(try field(refused.report.value, "changed")).bool)
                return error.UnknownScriptFamilyRecoveryAccepted;
            if ((try field(refused.report.value, "provenance_path")) != .null or
                !(try boolean(try field(refused.report.value, "diagnostic"), "recoverable")) or
                std.mem.indexOf(u8, try text(try field(refused.report.value, "diagnostic"), "message"), "unknown") == null)
                return error.UnknownScriptFamilyRecoveryReclassified;
            const evidence = refused.evidence orelse return error.MissingFamilyEvidence;
            if ((try field(evidence.value, "native_completion")) != .null)
                return error.UnknownScriptFamilyInventedCompletion;
            try unchanged(fixture, scenario.native_root, before);
            const inspection_log = try support.path(fixture.allocator, name, "family-unknown-inspection");
            defer fixture.allocator.free(inspection_log);
            var inspected = try family.workflow(fixture, driver, scenario.native_root, arch, inspection_log, .{
                .family_execution = .{
                    .operation = "inspect",
                    .root = scenario.native_root,
                    .architecture = arch,
                    .cache = cache,
                    .state = state,
                },
                .capture_evidence = true,
            });
            defer inspected.deinit();
            const inspected_evidence = inspected.evidence orelse return error.MissingFamilyEvidence;
            const observed = try oracle.validateDiagnosticInspection(
                inspected.report.value, inspected_evidence.value, scenario.native_root,
            );
            if (!try boolean(observed, "native_active_evidence"))
                return error.UnknownScriptFamilyLostActiveEvidence;
            try equal(try text(try field(observed, "observed_operation"), "state"),
                try text(pending.value, "state"));
            try unchanged(fixture, scenario.native_root, before);
            var still_pending = try rootDocument(fixture, scenario.native_root, operation_path);
            defer still_pending.deinit();
            try equal(try text(still_pending.value, "attempt_id"), try text(original.value, "attempt_id"));
            var still_intent = try rootDocument(fixture, scenario.native_root, intent_path);
            still_intent.deinit();
        }
        const settled = try snapshot(fixture, scenario.native_root);
        defer fixture.allocator.free(settled);
        const repeat_log = try support.path(fixture.allocator, name, "repeat");
        defer fixture.allocator.free(repeat_log);
        var repeated = try expectedReport(try invoke(fixture, driver, scenario.native_root, arch, repeat_log, .{
            .operation = "recover",
            .core = true,
        }), if (known) "applied" else "recovery_required", null);
        defer repeated.deinit();
        try unchanged(fixture, scenario.native_root, settled);
        try assertHelperUnchanged(fixture, scenario.native_root, helper_before);
        std.debug.print("{s}: known failure or unknown script outcome remained bound across fresh recovery\n", .{name});
    }
}

fn deadlineStartup(fixture: *foundation.Fixture, driver: []const u8, arch: []const u8) !void {
    const root = try fixture.makeRoot("deadline-startup/native", arch);
    defer fixture.allocator.free(root);
    const archive = try support.makePackage(fixture, arch, "1", foundation.package, "deadline-startup/packages", .{});
    defer fixture.allocator.free(archive);
    const before = try snapshot(fixture, root);
    defer fixture.allocator.free(before);
    var report = try expectedReport(try invoke(fixture, driver, root, arch, "deadline-startup/execute", .{
        .operation = "install",
        .archive = archive,
        .deadline_ms = 0,
    }), "refused", "deadline_exceeded");
    defer report.deinit();
    var operation = try rootDocument(fixture, root, operation_path);
    defer operation.deinit();
    if (try boolean(operation.value, "mutation_started")) return error.ExpiredDeadlineMutatedRoot;
    try rootAbsent(fixture, root, intent_path);
    try rootAbsent(fixture, root, namespace ++ "native-helper-cache-v1");
    try rootAbsent(fixture, root, helper_path);
    try unchanged(fixture, root, before);
    std.debug.print("deadline startup: zero budget refused before mutation and helper deployment\n", .{});
}

fn deadlinePersisted(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const reference_root = try fixture.makeRoot("deadline-persisted/reference", arch);
    defer fixture.allocator.free(reference_root);
    const root = try fixture.makeRoot("deadline-persisted/native", arch);
    defer fixture.allocator.free(root);
    try installHelper(fixture, reference_root);
    try installHelper(fixture, root);
    for ([_][]const u8{ reference_root, root }) |target| {
        try support.copyProgram(fixture, target[fixture.path.len + 1 ..], "/bin/sh", "/bin/sh");
        try fixture.directory(try relative(fixture, target, "var/log"));
    }
    const helper_before = try helperIdentity(fixture, root);
    const archive = try support.makePackage(fixture, arch, "1", foundation.package, "deadline-persisted/packages", .{});
    defer fixture.allocator.free(archive);
    try fixture.directory("deadline-persisted/reference-install");
    if (try support.reference(fixture, dpkg, reference_root, .{
        .operation = "install",
        .archives = &.{archive},
    }, "deadline-persisted/reference-install") != 0) return error.ReferenceInstallFailed;
    _ = try invoke(fixture, driver, root, arch, "deadline-persisted/crash", .{
        .operation = "install",
        .archive = archive,
        .crash_at = "after_execution_intent",
    });
    var original = try rootDocument(fixture, root, operation_path);
    defer original.deinit();
    var intent = try rootDocument(fixture, root, intent_path);
    defer intent.deinit();
    try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
    const record_before = try rootBytes(fixture, root, operation_path);
    defer fixture.allocator.free(record_before);
    const before = try snapshot(fixture, root);
    defer fixture.allocator.free(before);
    var expired = try expectedReport(try invoke(fixture, driver, root, arch, "deadline-persisted/expired", .{
        .operation = "recover",
        .deadline_ms = 0,
    }), "recovery_required", "deadline_exceeded");
    defer expired.deinit();
    const record_after = try rootBytes(fixture, root, operation_path);
    defer fixture.allocator.free(record_after);
    if (!std.mem.eql(u8, record_before, record_after)) return error.ExpiredDeadlineRewroteAuthority;
    try unchanged(fixture, root, before);
    var recovered = try expectedReport(try invoke(fixture, driver, root, arch, "deadline-persisted/fresh", .{
        .operation = "recover",
        .deadline_ms = 30_000,
    }), "applied", null);
    defer recovered.deinit();
    try assertBinding(fixture, root, recovered.value, original.value, intent.value);
    try fixture.directory("deadline-persisted/comparison");
    try foundation.compare(fixture.*, reference_root, root, "deadline-persisted/comparison");
    const proof_before = try rootBytes(fixture, root, provenance_path);
    defer fixture.allocator.free(proof_before);
    const settled = try snapshot(fixture, root);
    defer fixture.allocator.free(settled);
    var repeated = try expectedReport(try invoke(fixture, driver, root, arch, "deadline-persisted/repeat", .{
        .operation = "recover",
        .deadline_ms = 30_000,
    }), "applied", null);
    defer repeated.deinit();
    try unchanged(fixture, root, settled);
    var acknowledged = try expectedReport(try invoke(fixture, driver, root, arch, "deadline-persisted/ack", .{
        .operation = "recover",
        .acknowledge = true,
        .deadline_ms = 30_000,
    }), "applied", null);
    defer acknowledged.deinit();
    try unchanged(fixture, root, settled);
    try assertHelperUnchanged(fixture, root, helper_before);
    try rootAbsent(fixture, root, intent_path);
    const proof_after = try rootBytes(fixture, root, provenance_path);
    defer fixture.allocator.free(proof_after);
    if (!std.mem.eql(u8, proof_before, proof_after)) return error.AcknowledgmentReplacedReceipt;
    std.debug.print("deadline persisted: expired authority unchanged, fresh recovery and acknowledgment passed\n", .{});
}

fn deadlineScriptPackage(fixture: *foundation.Fixture, arch: []const u8) ![]u8 {
    const source = "deadline-script/packages/source";
    const control = try std.fmt.allocPrint(
        fixture.allocator,
        "Package: {s}\nVersion: 1\nArchitecture: {s}\nMaintainer: debz fixture <fixture@example.invalid>\nDescription: cumulative deadline fixture\n",
        .{ foundation.package, arch },
    );
    defer fixture.allocator.free(control);
    try fixture.write(source ++ "/DEBIAN/control", control, 0o644);
    try support.scripts(fixture, source, foundation.package, "1");
    for ([_]struct { kind: []const u8, seconds: u8 }{
        .{ .kind = "preinst", .seconds = 8 },
        .{ .kind = "postinst", .seconds = 25 },
    }) |script| {
        const path = try std.fmt.allocPrint(fixture.allocator, "{s}/DEBIAN/{s}", .{ source, script.kind });
        defer fixture.allocator.free(path);
        const original = try support.read(fixture, path, 64 * 1024);
        defer fixture.allocator.free(original);
        if (!std.mem.endsWith(u8, original, "exit 0\n")) return error.InvalidDeadlineScript;
        const appended = try std.fmt.allocPrint(fixture.allocator,
            "{s}\nprintf '%s\\n' '{s}-begin' >> /deadline-markers\n/bin/sleep {d}\nprintf '%s\\n' '{s}-end' >> /deadline-markers\nexit 0\n",
            .{ original[0 .. original.len - "exit 0\n".len], script.kind, script.seconds, script.kind },
        );
        defer fixture.allocator.free(appended);
        try fixture.write(path, appended, 0o755);
    }
    try fixture.write(source ++ "/DEBIAN/config", "#!/bin/sh\n# config:1\nprintf '%s\\n' 'config:1' >> /config-invoked\nexit 97\n", 0o755);
    try fixture.write(source ++ "/usr/share/" ++ foundation.package ++ "/data", "data version 1\n", 0o644);
    return fixture.buildPackage(source, "deadline-script/packages/" ++ foundation.package ++ ".deb", .{});
}

fn deadlineCancellation(fixture: *foundation.Fixture, driver: []const u8, arch: []const u8) !void {
    const root = try fixture.makeRoot("deadline-script/native", arch);
    defer fixture.allocator.free(root);
    const root_relative = root[fixture.path.len + 1 ..];
    try installHelper(fixture, root);
    const helper_before = try helperIdentity(fixture, root);
    try support.copyProgram(fixture, root_relative, "/bin/sh", "/bin/sh");
    try support.copyProgram(fixture, root_relative, "/bin/sleep", "/bin/sleep");
    try fixture.directory(try relative(fixture, root, "var/log"));
    const archive = try deadlineScriptPackage(fixture, arch);
    defer fixture.allocator.free(archive);
    const started = std.Io.Clock.awake.now(fixture.io);
    var cancelled = try expectedReport(try invoke(fixture, driver, root, arch, "deadline-script/execute", .{
        .operation = "install",
        .archive = archive,
        .deadline_ms = 30_000,
    }), "recovery_required", "deadline_exceeded");
    defer cancelled.deinit();
    const elapsed = started.durationTo(std.Io.Clock.awake.now(fixture.io)).toMilliseconds();
    if (elapsed < 25_000 or elapsed > 45_000) return error.DeadlineNotCumulative;
    const markers = try rootBytes(fixture, root, "deadline-markers");
    defer fixture.allocator.free(markers);
    try equal(markers, "preinst-begin\npreinst-end\npostinst-begin\n");
    const config = try rootBytes(fixture, root, "var/lib/dpkg/info/" ++ foundation.package ++ ".config");
    defer fixture.allocator.free(config);
    try equal(config, "#!/bin/sh\n# config:1\nprintf '%s\\n' 'config:1' >> /config-invoked\nexit 97\n");
    try rootAbsent(fixture, root, "var/lib/dpkg/tmp.ci/config");
    try rootAbsent(fixture, root, "config-invoked");
    var original = try rootDocument(fixture, root, operation_path);
    defer original.deinit();
    var intent = try rootDocument(fixture, root, intent_path);
    defer intent.deinit();
    const intent_bytes = try rootBytes(fixture, root, intent_path);
    defer fixture.allocator.free(intent_bytes);
    var retained_intent = try debz.native_recovery.decodeIntent(fixture.allocator, intent_bytes);
    defer retained_intent.deinit();
    const request_blob = for (retained_intent.intent.blobs) |blob| {
        if (blob.kind == .request) break blob;
    } else return error.MissingDeadlineOriginalRequest;
    const request_bytes = try rootBytes(fixture, root, request_blob.storage_path);
    defer fixture.allocator.free(request_bytes);
    var request = try debz.native_execution_request.decodePersisted(fixture.allocator, request_bytes);
    defer request.deinit();
    const helper = request.helper() orelse return error.MissingDeadlineHelperBinding;
    try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
    const before = try snapshot(fixture, root);
    defer fixture.allocator.free(before);
    var recovered = try expectedReport(try invoke(fixture, driver, root, arch, "deadline-script/fresh", .{
        .operation = "recover",
        .deadline_ms = 30_000,
    }), "recovery_required", "script_outcome_unknown");
    defer recovered.deinit();
    try unchanged(fixture, root, before);
    try assertHelperUnchanged(fixture, root, helper_before);
    try assertBinding(fixture, root, recovered.value, original.value, intent.value);
    var proof = try rootDocument(fixture, root, provenance_path);
    defer proof.deinit();
    try equal(try text(proof.value, "outcome"), "recovery_required");
    const proof_before = try rootBytes(fixture, root, provenance_path);
    defer fixture.allocator.free(proof_before);

    const namespace_relative = try relative(fixture, root, "var/lib/debz");
    defer fixture.allocator.free(namespace_relative);
    var dir = try fixture.dir.openDir(fixture.io, namespace_relative, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(fixture.io);
    var iterator = dir.iterate();
    var outcomes: [2]?std.json.Parsed(debz.native_recovery.ScriptOutcome) = .{ null, null };
    defer for (&outcomes) |*item| if (item.*) |*retained| retained.deinit();
    var count: usize = 0;
    while (try iterator.next(fixture.io)) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "native-script-outcome-v1-") or
            !std.mem.endsWith(u8, entry.name, ".json")) continue;
        const path = try support.path(fixture.allocator, "var/lib/debz", entry.name);
        defer fixture.allocator.free(path);
        const raw = try rootBytes(fixture, root, path);
        defer fixture.allocator.free(raw);
        var outcome = try std.json.parseFromSlice(debz.native_recovery.ScriptOutcome, fixture.allocator, raw, .{
            .allocate = .alloc_always,
        });
        try debz.native_recovery.validateScriptOutcome(outcome.value);
        if (!outcome.value.spawned) return error.MissingScriptSpawn;
        const kind = @tagName(outcome.value.kind);
        const exit_code = outcome.value.exit_code;
        try oracle.validateHelperInvocation(fixture.allocator, root, helper.source_path, helper.target_path, helper.sha256,
            request.execution().program.script_policy_sha256, .{
                .package = outcome.value.package,
                .version = outcome.value.package_version,
                .architecture = outcome.value.architecture,
                .kind = kind,
                .source = outcome.value.source,
                .arguments = outcome.value.arguments,
                .environment = outcome.value.environment,
                .script_sha256 = outcome.value.script_sha256,
                .invocation_sha256 = outcome.value.invocation_sha256,
            });
        const script_path = if (std.mem.eql(u8, kind, "preinst"))
            "deadline-script/packages/source/DEBIAN/preinst"
        else if (std.mem.eql(u8, kind, "postinst"))
            "deadline-script/packages/source/DEBIAN/postinst"
        else
            return error.UnexpectedScriptOutcome;
        const script = try support.read(fixture, script_path, 64 * 1024);
        defer fixture.allocator.free(script);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(script, &hash, .{});
        try equal(&outcome.value.script_sha256, &std.fmt.bytesToHex(hash, .lower));
        if (std.mem.eql(u8, kind, "preinst")) {
            if (outcome.value.disposition != .exited or exit_code != 0) return error.WrongPreinstOutcome;
        } else if (std.mem.eql(u8, kind, "postinst")) {
            if (outcome.value.disposition != .cancelled or exit_code != null) return error.CancelledScriptHadExitCode;
        } else return error.UnexpectedScriptOutcome;
        const slot: usize = if (std.mem.eql(u8, kind, "preinst")) 0 else 1;
        if (outcomes[slot] != null) return error.DuplicateDeadlineScriptOutcome;
        outcomes[slot] = outcome;
        count += 1;
    }
    if (outcomes[0] == null or outcomes[1] == null or count != 2) return error.IncompleteDeadlineOutcomes;
    const trace = try rootBytes(fixture, root, support.trace);
    defer fixture.allocator.free(trace);
    var invocations: [2]oracle.ScriptInvocation = undefined;
    for (outcomes, 0..) |entry, index| {
        const script = (entry orelse return error.IncompleteDeadlineOutcomes).value;
        invocations[index] = .{
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
    }
    try oracle.validateScriptTrace(fixture.allocator, trace, &invocations);
    var repeated = try expectedReport(try invoke(fixture, driver, root, arch, "deadline-script/repeat", .{
        .operation = "recover",
        .deadline_ms = 30_000,
    }), "recovery_required", "script_outcome_unknown");
    defer repeated.deinit();
    try unchanged(fixture, root, before);
    const selected = [_]foundation.PackageIdentity{.{ .name = "debz-recovery-absent", .architecture = arch }};
    var blocked = try expectedReport(try invoke(fixture, driver, root, arch, "deadline-script/blocked", .{
        .operation = "purge",
        .packages = &selected,
    }), "recovery_required", null);
    defer blocked.deinit();
    try unchanged(fixture, root, before);
    const proof_after = try rootBytes(fixture, root, provenance_path);
    defer fixture.allocator.free(proof_after);
    if (!std.mem.eql(u8, proof_before, proof_after)) return error.BlockedOperationReplacedReceipt;
    const later_markers = try rootBytes(fixture, root, "deadline-markers");
    defer fixture.allocator.free(later_markers);
    if (!std.mem.eql(u8, markers, later_markers)) return error.CancelledScriptWasReplayed;
    std.debug.print("deadline cumulative: cancelled postinst retained, unknown outcome failed closed\n", .{});
}

fn namespaceGate(allocator: std.mem.Allocator, io: std.Io) !void {
    const check = try std.process.run(allocator, io, .{
        .argv = &.{ "/usr/bin/unshare", "--mount", "--", "/bin/true" },
        .stdout_limit = .limited(1024),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer allocator.free(check.stdout);
    defer allocator.free(check.stderr);
    if (check.term != .exited or check.term.exited != 0) return error.RequiresMountNamespace;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var arguments = init.minimal.args.iterate();
    _ = arguments.next();
    const driver = arguments.next() orelse return error.MissingNativeDriver;
    var pinned: ?[]const u8 = null;
    var core_only = false;
    var deadline_only = false;
    while (arguments.next()) |argument| {
        if (std.mem.eql(u8, argument, "--reference-dpkg")) {
            if (pinned != null) return error.DuplicateReference;
            pinned = arguments.next() orelse return error.MissingReferencePath;
        } else if (std.mem.eql(u8, argument, "--core-only")) {
            core_only = true;
        } else if (std.mem.eql(u8, argument, "--deadline-only")) {
            deadline_only = true;
        } else return error.InvalidArguments;
    }
    if (core_only and deadline_only) return error.ConflictingSelectors;
    const reference = try support.prerequisites(init, allocator, pinned);
    defer allocator.free(reference.architecture);
    try namespaceGate(allocator, init.io);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed after acceptance failure: {s}\n", .{@errorName(err)});
    if (!deadline_only) {
        try coreCases(&fixture, driver, reference.executable, reference.architecture);
        try coreScriptOutcomes(&fixture, driver, reference.executable, reference.architecture);
    }
    if (!core_only) {
        try deadlineStartup(&fixture, driver, reference.architecture);
        try deadlinePersisted(&fixture, driver, reference.executable, reference.architecture);
        try deadlineCancellation(&fixture, driver, reference.architecture);
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
