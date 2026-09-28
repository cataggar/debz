const std = @import("std");
const debz = @import("debz");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");

const helper_path = "usr/bin/dpkg-trigger";
const config_slot = "var/lib/dpkg/tmp.ci/config";
const config_marker = "config-was-executed";
const first_config = "#!/bin/sh\nprintf first > /" ++ config_marker ++ "\n";
const second_config = "#!/bin/sh\nprintf second > /" ++ config_marker ++ "\n";
const intent_path = debz.native_recovery.intent_path;
const operation_path = "var/lib/debz/root-operation-v1.json";
const completion_path = "var/lib/debz/root-operation-completion-v1.json";
const provenance_path = debz.native_provenance.legacy_document_path;
const payload = "package-owned dpkg-trigger for fresh Zig bootstrap\n";
const recoverable = [_][]const u8{
    "after_execution_intent",           "during_filesystem_publication",
    "during_database_publication",      "after_helper_source_prepared",
    "during_helper_source_publication", "after_helper_source_publication",
    "after_helper_probe_prepared",      "after_helper_probe_outcome",
    "after_helper_probe_completed",     "after_provenance",
};
const unknown_probe = [_][]const u8{
    "after_helper_probe_in_flight", "after_helper_probe_return_before_outcome",
};
const cleanup = [_][]const u8{
    "after_helper_cleanup_prepared", "during_helper_cleanup", "after_helper_cleanup_completed",
};
const script_known = [_][]const u8{ "after_script_prepared", "after_script_outcome" };
const config_boundaries = [_][]const u8{
    "after_execution_intent",
    "during_bootstrap_config_staging",
    "after_bootstrap_config_stage",
    "after_subsequent_bootstrap_config_stage",
    "after_bootstrap_payload_before_config_cleanup",
    "during_bootstrap_config_cleanup",
    "after_bootstrap_config_cleanup",
};

const Report = struct {
    outcome: []const u8,
    detail: []const u8 = "",
    attempt_id: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
};

const Call = struct {
    operation: []const u8,
    archive: ?[]const u8 = null,
    archives: []const []const u8 = &.{},
    ordered_actions: ?[]const support.Action = null,
    packages: []const foundation.PackageIdentity = &.{},
    crash: ?[]const u8 = null,
    expectation: ?[]const u8 = null,
    acknowledge: bool = false,
};

fn path(fixture: *foundation.Fixture, root: []const u8, name: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, root, fixture.path) or root.len <= fixture.path.len or
        root[fixture.path.len] != '/') return error.InvalidBootstrapRoot;
    return support.path(fixture.allocator, root[fixture.path.len + 1 ..], name);
}

fn read(fixture: *foundation.Fixture, root: []const u8, name: []const u8, limit: usize) ![]u8 {
    return support.read(fixture, try path(fixture, root, name), limit);
}

fn absent(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !void {
    try support.absent(fixture, try path(fixture, root, name));
}

fn equal(actual: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, actual, expected)) {
        std.debug.print("bootstrap evidence: expected ({d} bytes) {s}; got ({d} bytes) {s}\n", .{
            expected.len, expected[0..@min(expected.len, 512)],
            actual.len,   actual[0..@min(actual.len, 512)],
        });
        return error.BootstrapEvidenceMismatch;
    }
}

fn text(value: std.json.Value, key: []const u8) ![]const u8 {
    if (value != .object) return error.InvalidBootstrapEvidence;
    const entry = value.object.get(key) orelse return error.MissingBootstrapEvidence;
    if (entry != .string) return error.InvalidBootstrapEvidence;
    return entry.string;
}

fn invoke(fixture: *foundation.Fixture, driver: []const u8, root: []const u8, arch: []const u8, destination: []const u8, call: Call) !?std.json.Parsed(Report) {
    var guarded = try foundation.guardedRoot(fixture.io, root);
    guarded.close(fixture.io);
    if (std.mem.eql(u8, call.operation, "recover") and
        (call.archive != null or call.archives.len != 0 or call.packages.len != 0 or call.ordered_actions != null))
        return error.RecoveryMustUsePersistedEvidence;
    try fixture.directory(destination);
    const request_name = try support.path(fixture.allocator, destination, "native.request.json");
    const report_name = try support.path(fixture.allocator, destination, "native.report.json");
    try support.absent(fixture, report_name);
    const report_path = try fixture.absolute(report_name);
    const request_path = try fixture.absolute(request_name);
    if (call.archive != null and call.archives.len != 0) return error.DuplicateBootstrapArchives;
    const archives: []const []const u8 = if (call.archive) |archive| &.{archive} else call.archives;
    const actions: ?[]const support.Action = if (call.ordered_actions) |ordered| ordered else if (call.archive != null) &.{
        .{ .sequence = 0, .kind = "bootstrap_extract", .package = "dpkg", .architecture = arch },
        .{ .sequence = 1, .kind = "unpack", .package = "dpkg", .architecture = arch },
        .{ .sequence = 2, .kind = "configure_pending", .package = "dpkg", .architecture = arch },
    } else null;
    const encoded = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = root,
        .architecture = arch,
        .operation = call.operation,
        .archives = archives,
        .packages = call.packages,
        .report = report_path,
        .recovery = true,
        .caller_owned = true,
        .isolated_helper = true,
        .ordered_actions = actions,
        .acknowledge_native = call.acknowledge,
        .crash_at = call.crash,
        .helper_bootstrap_expectation = call.expectation,
    }, .{});
    try fixture.write(request_name, encoded, 0o600);
    try fixture.environment.put("DEBZ_NATIVE_LIFECYCLE_REQUEST", request_path);
    const result = std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", driver },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    }) catch |err| {
        std.debug.print("{s}: process {s}; fixture {s}\n", .{ destination, @errorName(err), fixture.path });
        return err;
    };
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const combined = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    try fixture.write(try support.path(fixture.allocator, destination, "native.log"), combined, 0o644);
    const expected: u8 = if (call.crash != null) 86 else 0;
    if (result.term != .exited or result.term.exited != expected) {
        std.debug.print("{s}: exit {any}, expected {d}; {s}\n", .{
            destination, result.term, expected, combined[combined.len - @min(combined.len, 12_000) ..],
        });
        return error.UnexpectedBootstrapProcessExit;
    }
    if (call.crash != null) {
        try support.absent(fixture, report_name);
        return null;
    }
    const raw = try support.read(fixture, report_name, 64 * 1024);
    return try std.json.parseFromSlice(Report, fixture.allocator, raw, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}

fn expectReport(report: ?std.json.Parsed(Report), expected: []const u8, detail: ?[]const u8) !void {
    var owned = report orelse return error.MissingBootstrapReport;
    defer owned.deinit();
    try equal(owned.value.outcome, expected);
    if (detail) |message| try equal(owned.value.detail, message);
}

fn makeArchive(fixture: *foundation.Fixture, name: []const u8, arch: []const u8, script: bool) ![]u8 {
    const directory = try support.path(fixture.allocator, name, "package");
    const original = try fixture.makePackageWith(arch, "1", .data, .{
        .workspace = directory,
        .name = "dpkg",
        .extra_files = &.{.{ .path = helper_path, .content = payload, .mode = 0o755 }},
        .control_fields = "Essential: yes\n",
    });
    if (!script) return original;
    const source = try support.path(fixture.allocator, directory, "dpkg_1_data.source");
    try fixture.write(try support.path(fixture.allocator, source, "DEBIAN/postinst"), "#!/bin/sh\nexit 0\n", 0o755);
    const rebuilt = try fixture.buildPackage(source, try support.path(fixture.allocator, directory, "dpkg_1_data.deb"), .{});
    fixture.allocator.free(rebuilt);
    return original;
}

const Evidence = struct {
    request: debz.native_execution_request.OwnedRequest,
    intent: debz.native_recovery.OwnedIntent,
    bootstrap: debz.native_helper.Bootstrap,

    fn deinit(self: *Evidence) void {
        self.request.deinit();
        self.intent.deinit();
    }
};

fn evidence(fixture: *foundation.Fixture, root: []const u8) !Evidence {
    const raw = try read(fixture, root, intent_path, 16 * 1024 * 1024);
    var intent = try debz.native_recovery.decodeIntent(fixture.allocator, raw);
    errdefer intent.deinit();
    const record = for (intent.intent.blobs) |blob| {
        if (blob.kind == .request) break blob;
    } else return error.MissingPersistedBootstrapRequest;
    const original = try read(fixture, root, record.storage_path, 16 * 1024 * 1024);
    if (record.size != original.len) return error.PersistedBootstrapRequestChanged;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(original, &digest, .{});
    try equal(&record.sha256, &std.fmt.bytesToHex(digest, .lower));
    var request = try debz.native_execution_request.decodePersisted(fixture.allocator, original);
    errdefer request.deinit();
    const bootstrap = request.bootstrap() orelse return error.MissingHelperBootstrapAuthority;
    const helper = request.helper() orelse return error.MissingIsolatedHelper;
    try equal(&bootstrap.attempt_id, &intent.intent.attempt_id);
    try equal(bootstrap.target.path, helper_path);
    try equal(helper.source_path, bootstrap.helper.source_path);
    if (std.mem.eql(u8, &bootstrap.target.sha256, &bootstrap.helper.sha256))
        return error.BootstrapHelperIdentityConflated;
    const owner = bootstrap.owner;
    try equal(owner.package, "dpkg");
    try equal(owner.architecture, request.execution().architecture);
    try equal(request.execution().install_root, root);
    return .{ .request = request, .intent = intent, .bootstrap = bootstrap };
}

fn snapshot(fixture: *foundation.Fixture, root: []const u8) ![]u8 {
    return foundation.capture(fixture.allocator, fixture.io, root);
}

fn unchanged(fixture: *foundation.Fixture, root: []const u8, before: []const u8) !void {
    const after = try snapshot(fixture, root);
    if (!std.mem.eql(u8, after, before)) return error.BlockedBootstrapMutatedPackageState;
}

fn helperState(fixture: *foundation.Fixture, root: []const u8, bootstrap: debz.native_helper.Bootstrap, active: bool) !void {
    var guarded = try foundation.guardedRoot(fixture.io, root);
    defer guarded.close(fixture.io);
    const fs: debz.root_fs.Root = .init(fixture.io, guarded);
    try debz.native_helper.verifyBootstrapCompletionState(fixture.allocator, fs, bootstrap, active);
    const actual = try read(fixture, root, helper_path, 8 * 1024 * 1024);
    try equal(actual, payload);
    try absent(fixture, root, "usr/bin/dpkg");
    try absent(fixture, root, "usr/bin/dpkg-deb");
    const list = try read(fixture, root, "var/lib/dpkg/info/dpkg.list", 1024 * 1024);
    if (std.mem.indexOf(u8, list, "/usr/bin/dpkg-trigger\n") == null)
        return error.BootstrapHelperNotPackageOwned;
}

fn progress(fixture: *foundation.Fixture, root: []const u8, authority: debz.native_helper.Bootstrap, source_stage: ?debz.native_recovery.Stage, probe_stage: ?debz.native_recovery.Stage, script_stage: ?debz.native_recovery.Stage) !void {
    var guarded = try foundation.guardedRoot(fixture.io, root);
    defer guarded.close(fixture.io);
    const fs: debz.root_fs.Root = .init(fixture.io, guarded);
    var observed = try debz.native_recovery.readProgress(fixture.allocator, fs);
    defer observed.deinit();
    try debz.native_recovery.validateHelperActions(observed.document, authority);
    for ([_]struct { substep: u16, expected: ?debz.native_recovery.Stage }{
        .{ .substep = debz.native_recovery.helper_source_substep, .expected = source_stage },
        .{ .substep = debz.native_recovery.helper_probe_substep, .expected = probe_stage },
    }) |entry| {
        const action: debz.native_recovery.Action = .{ .kind = .helper, .program_step = authority.owner.program_step, .substep = entry.substep, .ordinal = 0 };
        const latest = debz.native_recovery.latest(observed.document, action);
        if (entry.expected) |stage| {
            if (latest == null or latest.?.stage != stage) return error.BootstrapProgressChanged;
        } else if (latest != null) return error.BootstrapProgressChanged;
    }
    if (script_stage) |stage| {
        var found = false;
        for (observed.document.records) |record| {
            if (record.action.kind == .script and record.stage == stage) found = true;
        }
        if (!found) return error.BootstrapScriptProgressMissing;
    }
}

fn recovered(fixture: *foundation.Fixture, driver: []const u8, reference: []const u8, arch: []const u8, name: []const u8, boundary: []const u8, script: bool, cleanup_crash: ?[]const u8) !void {
    const ref_name = try support.path(fixture.allocator, name, "reference");
    const root_name = try support.path(fixture.allocator, name, "native");
    const expected = try fixture.makeRoot(ref_name, arch);
    const root = try fixture.makeRoot(root_name, arch);
    for ([_][]const u8{ ref_name, root_name }) |relative| {
        try support.copyProgram(fixture, relative, "/bin/sh", "/bin/sh");
        try fixture.directory(try support.path(fixture.allocator, relative, "var/log"));
    }
    try absent(fixture, root, helper_path);
    const archive = try makeArchive(fixture, name, arch, script);
    const reference_log = try support.path(fixture.allocator, name, "reference-run");
    try fixture.directory(reference_log);
    if (try support.reference(fixture, reference, expected, .{ .operation = "install", .archives = &.{archive} }, reference_log) != 0)
        return error.BootstrapReferenceInstallFailed;
    _ = try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "crash"), .{
        .operation = "install",
        .archive = archive,
        .crash = boundary,
    });
    var retained = try evidence(fixture, root);
    defer retained.deinit();
    const intent_before = try read(fixture, root, intent_path, 16 * 1024 * 1024);
    const request_record = for (retained.intent.intent.blobs) |blob| {
        if (blob.kind == .request) break blob;
    } else return error.MissingPersistedBootstrapRequest;
    const request_before = try read(fixture, root, request_record.storage_path, 16 * 1024 * 1024);
    const archive_relative = archive[fixture.path.len + 1 ..];
    try fixture.dir.deleteFile(fixture.io, archive_relative);
    try support.absent(fixture, archive_relative);
    try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "recover"), .{
        .operation = "recover",
        .expectation = if (script) "script_completed" else "completed",
    }), "applied", null);
    try helperState(fixture, root, retained.bootstrap, true);
    try progress(fixture, root, retained.bootstrap, .completed, .completed, if (script) .completed else null);
    const comparison = try support.path(fixture.allocator, name, "comparison");
    try fixture.directory(comparison);
    try foundation.compare(fixture.*, expected, root, comparison);
    const proof_before = try read(fixture, root, provenance_path, 16 * 1024 * 1024);
    var proof = try debz.native_provenance.decode(fixture.allocator, proof_before);
    defer proof.deinit();
    if (proof.document.outcome != .succeeded) return error.IncorrectBootstrapReceipt;
    const state = try snapshot(fixture, root);
    try absent(fixture, root, completion_path);
    if (cleanup_crash) |seam| {
        _ = try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "ack-crash"), .{
            .operation = "recover",
            .acknowledge = true,
            .crash = seam,
        });
    } else {
        try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "repeat"), .{
            .operation = "recover",
            .expectation = if (script) "script_completed" else "completed",
        }), "applied", null);
        try unchanged(fixture, root, state);
        try equal(try read(fixture, root, intent_path, 16 * 1024 * 1024), intent_before);
        try equal(try read(fixture, root, request_record.storage_path, 16 * 1024 * 1024), request_before);
    }
    try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "ack"), .{
        .operation = "recover",
        .acknowledge = true,
        .expectation = "cleaned",
    }), "applied", null);
    try helperState(fixture, root, retained.bootstrap, false);
    try absent(fixture, root, operation_path);
    try absent(fixture, root, intent_path);
    try absent(fixture, root, request_record.storage_path);
    const proof_after = try read(fixture, root, provenance_path, 16 * 1024 * 1024);
    try equal(proof_after, proof_before);
    const completion_bytes = try read(fixture, root, completion_path, 64 * 1024);
    var completion = try std.json.parseFromSlice(std.json.Value, fixture.allocator, completion_bytes, .{});
    defer completion.deinit();
    const attempt = completion.value.object.get("attempt_id") orelse return error.InvalidBootstrapCompletion;
    if (attempt != .string) return error.InvalidBootstrapCompletion;
    try equal(attempt.string, &retained.bootstrap.attempt_id);
    try foundation.compare(fixture.*, expected, root, comparison);
    std.debug.print("{s}: real fresh-helper publication, recovery, owner and pinned-dpkg parity passed\n", .{name});
}

const Block = enum { probe, ambient_target, ambient_source, script };

fn blocked(fixture: *foundation.Fixture, driver: []const u8, helper: []const u8, arch: []const u8, name: []const u8, boundary: []const u8, reason: Block) !void {
    const root_name = try support.path(fixture.allocator, name, "native");
    const root = try fixture.makeRoot(root_name, arch);
    try support.copyProgram(fixture, root_name, "/bin/sh", "/bin/sh");
    try fixture.directory(try support.path(fixture.allocator, root_name, "var/log"));
    try absent(fixture, root, helper_path);
    const archive = try makeArchive(fixture, name, arch, reason == .script);
    _ = try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "crash"), .{
        .operation = "install",
        .archive = archive,
        .crash = boundary,
    });
    var retained = try evidence(fixture, root);
    defer retained.deinit();
    const intent_before = try read(fixture, root, intent_path, 16 * 1024 * 1024);
    const request_record = for (retained.intent.intent.blobs) |blob| {
        if (blob.kind == .request) break blob;
    } else return error.MissingPersistedBootstrapRequest;
    const request_before = try read(fixture, root, request_record.storage_path, 16 * 1024 * 1024);
    const archive_relative = archive[fixture.path.len + 1 ..];
    try fixture.dir.deleteFile(fixture.io, archive_relative);
    try support.absent(fixture, archive_relative);
    if (reason == .ambient_target) {
        try fixture.write(try path(fixture, root, helper_path), payload, 0o755);
    } else if (reason == .ambient_source) {
        const source = try std.Io.Dir.cwd().openFile(fixture.io, helper, .{});
        defer source.close(fixture.io);
        var reader = source.reader(fixture.io, &.{});
        const raw = try reader.interface.allocRemaining(fixture.allocator, .limited(8 * 1024 * 1024));
        try fixture.write(try path(fixture, root, retained.bootstrap.helper.source_path), raw, 0o500);
    }
    const before = try snapshot(fixture, root);
    const expectation: []const u8 = switch (reason) {
        .probe => "outcome_unknown",
        .ambient_target => "ambient_target_rejected",
        .ambient_source => "ambient_source_rejected",
        .script => "script_outcome_unknown",
    };
    const detail: []const u8 = switch (reason) {
        .probe => "native_helper_outcome_unknown",
        .ambient_target, .ambient_source => "MutationEvidenceRequired",
        .script => "script_outcome_unknown",
    };
    for (0..2) |index| {
        const output = try std.fmt.allocPrint(fixture.allocator, "{s}/blocked-{d}", .{ name, index });
        try expectReport(try invoke(fixture, driver, root, arch, output, .{
            .operation = "recover",
            .expectation = expectation,
        }), "recovery_required", detail);
        try unchanged(fixture, root, before);
        try equal(try read(fixture, root, intent_path, 16 * 1024 * 1024), intent_before);
        try equal(try read(fixture, root, request_record.storage_path, 16 * 1024 * 1024), request_before);
        try absent(fixture, root, completion_path);
    }
    if (reason == .probe or reason == .script) {
        try helperState(fixture, root, retained.bootstrap, true);
        try progress(fixture, root, retained.bootstrap, .completed, if (reason == .probe) .in_flight else .completed, if (reason == .script) .in_flight else null);
    } else {
        try progress(fixture, root, retained.bootstrap, null, null, null);
        if (reason == .ambient_target) try absent(fixture, root, retained.bootstrap.helper.source_path) else try absent(fixture, root, helper_path);
    }
    std.debug.print("{s}: real blocked helper state and repeated no-mutation refusal passed\n", .{name});
}

fn configArchive(
    fixture: *foundation.Fixture,
    name: []const u8,
    arch: []const u8,
    package: []const u8,
    config: []const u8,
    postinst: bool,
) ![]u8 {
    const workspace = try support.path(fixture.allocator, name, package);
    const first = std.mem.eql(u8, package, "dpkg");
    const archive = try fixture.makePackageWith(arch, "1", .data, .{
        .workspace = workspace,
        .name = package,
        .extra_files = if (first) &.{.{ .path = helper_path, .content = payload, .mode = 0o755 }} else &.{},
        .control_fields = if (first) "Essential: yes\n" else "",
    });
    const source = try support.path(fixture.allocator, workspace, try std.fmt.allocPrint(
        fixture.allocator,
        "{s}_1_data.source",
        .{package},
    ));
    try fixture.write(try support.path(fixture.allocator, source, "DEBIAN/config"), config, 0o755);
    if (postinst) try fixture.write(
        try support.path(fixture.allocator, source, "DEBIAN/postinst"),
        "#!/bin/sh\nprintf 'invoked\\n' >> /var/log/config-postinst-invoked\n",
        0o755,
    );
    const rebuilt = try fixture.buildPackage(source, try support.path(
        fixture.allocator,
        workspace,
        try std.fmt.allocPrint(fixture.allocator, "{s}_1_data.deb", .{package}),
    ), .{});
    fixture.allocator.free(rebuilt);
    return archive;
}

const config_actions = [_]support.Action{
    .{ .sequence = 0, .kind = "bootstrap_extract", .package = "dpkg", .architecture = "" },
    .{ .sequence = 1, .kind = "bootstrap_extract", .package = "debz-bootstrap-config", .architecture = "" },
    .{ .sequence = 2, .kind = "unpack", .package = "dpkg", .architecture = "" },
    .{ .sequence = 3, .kind = "configure_pending", .package = "dpkg", .architecture = "" },
    .{ .sequence = 4, .kind = "unpack", .package = "debz-bootstrap-config", .architecture = "" },
    .{ .sequence = 5, .kind = "configure_pending", .package = "debz-bootstrap-config", .architecture = "" },
};

fn configActions(arch: []const u8) [config_actions.len]support.Action {
    var actions = config_actions;
    for (&actions) |*action| action.architecture = arch;
    return actions;
}

fn configClaim(fixture: *foundation.Fixture, root: []const u8) ![]u8 {
    var claim = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try read(fixture, root, operation_path, 64 * 1024), .{});
    defer claim.deinit();
    if (claim.value != .object) return error.InvalidBootstrapEvidence;
    for ([_][]const u8{ "generation", "state", "phase", "step", "updated_unix", "digest_sha256" }) |changing|
        if (!claim.value.object.swapRemove(changing)) return error.InvalidBootstrapEvidence;
    return std.json.Stringify.valueAlloc(fixture.allocator, claim.value, .{});
}

fn configProgress(fixture: *foundation.Fixture, root: []const u8, boundary: []const u8, intent_sha256: []const u8) !void {
    var guarded = try foundation.guardedRoot(fixture.io, root);
    defer guarded.close(fixture.io);
    var progress_state = try debz.native_recovery.readProgress(fixture.allocator, debz.root_fs.Root.init(fixture.io, guarded));
    defer progress_state.deinit();
    try equal(&progress_state.document.intent_sha256, intent_sha256);
    const expected: [3]usize = if (std.mem.eql(u8, boundary, "after_execution_intent") or
        std.mem.eql(u8, boundary, "during_bootstrap_config_staging"))
        .{ 0, 0, 0 }
    else if (std.mem.eql(u8, boundary, "after_bootstrap_config_stage"))
        .{ 1, 0, 0 }
    else if (std.mem.eql(u8, boundary, "after_subsequent_bootstrap_config_stage"))
        .{ 2, 1, 1 }
    else if (std.mem.eql(u8, boundary, "after_bootstrap_payload_before_config_cleanup") or
        std.mem.eql(u8, boundary, "during_bootstrap_config_cleanup"))
        .{ 1, 1, 0 }
    else
        .{ 1, 1, 1 };
    var completed: [3]usize = .{ 0, 0, 0 };
    var prepared: [3]usize = .{ 0, 0, 0 };
    for (progress_state.document.records) |record| {
        const action = record.action;
        const index: usize = if (action.kind == .database and action.substep == 0)
            0
        else if (action.kind == .filesystem and action.substep == 1)
            1
        else if (action.kind == .database and action.substep == 2)
            2
        else
            continue;
        if (record.stage == .completed)
            completed[index] += 1
        else if (record.stage == .prepared)
            prepared[index] += 1;
    }
    for (completed, expected) |actual, want|
        if (actual != want) return error.ConfigTransitionNotReached;
    const pending: usize = if (std.mem.eql(u8, boundary, "during_bootstrap_config_staging"))
        0
    else if (std.mem.eql(u8, boundary, "during_bootstrap_config_cleanup"))
        2
    else
        return;
    if (prepared[pending] != 1 or completed[pending] != 0)
        return error.ConfigMutationNotPrepared;
}

fn assertConfigReceipt(
    fixture: *foundation.Fixture,
    root: []const u8,
    expected: []const u8,
    attempt: []const u8,
) ![]u8 {
    var proof = try evidence(fixture, root);
    defer proof.deinit();
    try equal(&proof.intent.intent.attempt_id, attempt);
    try equal(try read(fixture, root, "var/lib/dpkg/info/dpkg.config", 64 * 1024), first_config);
    try equal(try read(fixture, root, "var/lib/dpkg/info/debz-bootstrap-config.config", 64 * 1024), second_config);
    try absent(fixture, root, config_slot);
    try absent(fixture, root, config_marker);
    const receipt = try read(fixture, root, provenance_path, 16 * 1024 * 1024);
    var decoded = try debz.native_provenance.decode(fixture.allocator, receipt);
    defer decoded.deinit();
    if (decoded.document.outcome != .succeeded) return error.IncorrectConfigReceipt;
    try equal(&decoded.document.attempt_id, attempt);
    try equal(expected, &decoded.document.program_sha256);
    try absent(fixture, root, completion_path);
    return receipt;
}

fn configCase(
    fixture: *foundation.Fixture,
    driver: []const u8,
    reference: []const u8,
    arch: []const u8,
    boundary: []const u8,
) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "config-{s}", .{boundary});
    const ref_relative = try support.path(fixture.allocator, name, "reference");
    const root_relative = try support.path(fixture.allocator, name, "native");
    const expected = try fixture.makeRoot(ref_relative, arch);
    const root = try fixture.makeRoot(root_relative, arch);
    for ([_][]const u8{ ref_relative, root_relative }) |relative| {
        try support.copyProgram(fixture, relative, "/bin/sh", "/bin/sh");
        try fixture.directory(try support.path(fixture.allocator, relative, "var/log"));
    }
    const first = try configArchive(fixture, name, arch, "dpkg", first_config, false);
    const second = try configArchive(fixture, name, arch, "debz-bootstrap-config", second_config, false);
    const archives = [_][]const u8{ first, second };
    const actions = configActions(arch);
    for ([_]struct { phase: []const u8, archive: ?[]const u8 }{
        .{ .phase = "install", .archive = first },
        .{ .phase = "unpack", .archive = second },
        .{ .phase = "configure", .archive = null },
    }, 0..) |phase, index| {
        const reference_log = try std.fmt.allocPrint(fixture.allocator, "{s}/reference-{d}", .{ name, index });
        try fixture.directory(reference_log);
        const selected = [_]foundation.PackageIdentity{.{ .name = "debz-bootstrap-config", .architecture = arch }};
        if (try support.reference(fixture, reference, expected, .{
            .operation = phase.phase,
            .archives = if (phase.archive) |archive| &.{archive} else &.{},
            .packages = if (phase.archive == null) &selected else &.{},
        }, reference_log) != 0) return error.ConfigReferenceInstallFailed;
    }
    const before = try snapshot(fixture, root);
    _ = try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "crash"), .{
        .operation = "install",
        .archives = &archives,
        .ordered_actions = &actions,
        .crash = boundary,
    });
    if (std.mem.eql(u8, boundary, "after_execution_intent"))
        try unchanged(fixture, root, before);
    var retained = try evidence(fixture, root);
    defer retained.deinit();
    const attempt_id = retained.intent.intent.attempt_id;
    const program_sha256 = retained.intent.intent.program_sha256;
    const original_intent = try read(fixture, root, intent_path, 16 * 1024 * 1024);
    var owner = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try read(fixture, root, operation_path, 64 * 1024), .{});
    defer owner.deinit();
    try equal(try text(owner.value, "attempt_id"), &attempt_id);
    try equal(try text(owner.value, "backend"), "native");
    try equal(try text(owner.value, "surface"), "repository_bootstrap");
    try equal(try text(owner.value, "operation"), "add");
    const started = owner.value.object.get("mutation_started") orelse return error.MissingBootstrapEvidence;
    if (started != .bool or started.bool == std.mem.eql(u8, boundary, "after_execution_intent"))
        return error.IncorrectConfigMutationOwnership;
    try configProgress(fixture, root, boundary, &retained.intent.intent.digest_sha256);
    try absent(fixture, root, config_marker);
    if (std.mem.eql(u8, boundary, "after_bootstrap_config_stage")) {
        try equal(try read(fixture, root, config_slot, 64 * 1024), first_config);
        try absent(fixture, root, "var/lib/dpkg/info/dpkg.config");
    } else if (std.mem.eql(u8, boundary, "after_subsequent_bootstrap_config_stage")) {
        try equal(try read(fixture, root, config_slot, 64 * 1024), second_config);
        try equal(try read(fixture, root, "var/lib/dpkg/info/dpkg.config", 64 * 1024), first_config);
    }
    if (std.mem.eql(u8, boundary, "during_bootstrap_config_staging") or
        std.mem.eql(u8, boundary, "during_bootstrap_config_cleanup"))
    {
        const journal_bytes = try read(fixture, root, debz.root_mutation.journal_path, 16 * 1024 * 1024);
        var journal = try debz.root_mutation.decode(fixture.allocator, journal_bytes, debz.root_mutation.maximum_document_bytes);
        defer journal.deinit();
        const digest = debz.native_recovery.parseDigest(program_sha256) orelse return error.InvalidConfigProgram;
        const journal_attempt = debz.native_recovery.parseDigest(attempt_id) orelse return error.InvalidConfigAttempt;
        if (!std.mem.eql(u8, &journal.journal.attempt_id, &journal_attempt))
            return error.ConfigJournalHasWrongOwner;
        if (journal.journal.evidence.program_sha256 == null or
            !std.mem.eql(u8, &journal.journal.evidence.program_sha256.?, &digest))
            return error.ConfigJournalHasWrongProgram;
        var owns_slot = false;
        for (journal.journal.steps) |mutation| {
            if (std.mem.eql(u8, mutation.path, config_slot)) owns_slot = true;
        }
        if (!owns_slot) return error.ConfigJournalDoesNotOwnSlot;
    }
    for (archives) |archive| {
        try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
        try support.absent(fixture, archive[fixture.path.len + 1 ..]);
    }
    const blocked_state = try snapshot(fixture, root);
    const original_claim = try configClaim(fixture, root);
    const unowned = [_]foundation.PackageIdentity{.{ .name = "debz-unowned-second", .architecture = arch }};
    try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "blocked-purge"), .{
        .operation = "purge",
        .packages = &unowned,
    }), "recovery_required", null);
    try unchanged(fixture, root, blocked_state);
    try equal(try configClaim(fixture, root), original_claim);
    try equal(try read(fixture, root, intent_path, 16 * 1024 * 1024), original_intent);
    try absent(fixture, root, completion_path);
    try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "recover"), .{
        .operation = "recover",
        .expectation = "completed",
    }), "applied", null);
    const receipt = try assertConfigReceipt(fixture, root, &program_sha256, &attempt_id);
    const comparison = try support.path(fixture.allocator, name, "comparison");
    try fixture.directory(comparison);
    try foundation.compare(fixture.*, expected, root, comparison);
    const completed = try snapshot(fixture, root);
    const completed_claim = try configClaim(fixture, root);
    try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "recover-again"), .{
        .operation = "recover",
        .expectation = "completed",
    }), "applied", null);
    try unchanged(fixture, root, completed);
    try equal(try configClaim(fixture, root), completed_claim);
    try equal(try read(fixture, root, provenance_path, 16 * 1024 * 1024), receipt);
    try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "blocked-before-ack"), .{
        .operation = "purge",
        .packages = &unowned,
    }), "recovery_required", null);
    try unchanged(fixture, root, completed);
    try equal(try configClaim(fixture, root), completed_claim);
    try equal(try read(fixture, root, provenance_path, 16 * 1024 * 1024), receipt);
    try absent(fixture, root, completion_path);
    try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "acknowledge"), .{
        .operation = "recover",
        .acknowledge = true,
        .expectation = "cleaned",
    }), "applied", null);
    try absent(fixture, root, intent_path);
    try absent(fixture, root, operation_path);
    try equal(try read(fixture, root, provenance_path, 16 * 1024 * 1024), receipt);
    var completion = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try read(fixture, root, completion_path, 64 * 1024), .{});
    defer completion.deinit();
    try equal(try text(completion.value, "attempt_id"), &attempt_id);
    try foundation.compare(fixture.*, expected, root, comparison);
    std.debug.print("{s}: real config transition exit 86, owned recovery, receipt and dpkg parity passed\n", .{name});
}

const ConfigRefusal = enum { changed_slot, corrupt_journal, forged_journal, unknown_script };

fn forgeConfigJournal(fixture: *foundation.Fixture, root: []const u8) !void {
    const bytes = try read(fixture, root, debz.root_mutation.journal_path, debz.root_mutation.maximum_document_bytes);
    const owner_field = "\"attempt_id\":\"";
    const owner_start = (std.mem.indexOf(u8, bytes, owner_field) orelse return error.MissingConfigJournalOwner) + owner_field.len;
    if (owner_start + 64 > bytes.len) return error.InvalidConfigJournalOwner;
    @memset(bytes[owner_start..][0..64], 'f');
    const digest_field = ",\"digest_sha256\":\"";
    const digest_start = std.mem.lastIndexOf(u8, bytes, digest_field) orelse return error.MissingConfigJournalDigest;
    const digest_value = digest_start + digest_field.len;
    if (digest_value + 64 > bytes.len) return error.InvalidConfigJournalDigest;
    const payload_bytes = try std.mem.concat(fixture.allocator, u8, &.{ bytes[0..digest_start], "}" });
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload_bytes, &digest, .{});
    const sealed = std.fmt.bytesToHex(digest, .lower);
    @memcpy(bytes[digest_value..][0..64], &sealed);
    var forged = try debz.root_mutation.decode(fixture.allocator, bytes, debz.root_mutation.maximum_document_bytes);
    defer forged.deinit();
    if (!std.mem.eql(u8, &forged.journal.attempt_id, &([_]u8{0xff} ** 32)))
        return error.ConfigJournalForgeryNotCanonical;
    try fixture.write(try path(fixture, root, debz.root_mutation.journal_path), bytes, 0o600);
}

fn configRefusal(
    fixture: *foundation.Fixture,
    driver: []const u8,
    arch: []const u8,
    reason: ConfigRefusal,
) !void {
    const name = switch (reason) {
        .changed_slot => "config-changed-slot",
        .corrupt_journal => "config-corrupt-journal",
        .forged_journal => "config-forged-journal",
        .unknown_script => "config-unknown-script",
    };
    const root_relative = try support.path(fixture.allocator, name, "native");
    const root = try fixture.makeRoot(root_relative, arch);
    try support.copyProgram(fixture, root_relative, "/bin/sh", "/bin/sh");
    try fixture.directory(try support.path(fixture.allocator, root_relative, "var/log"));
    const first = try configArchive(fixture, name, arch, "dpkg", first_config, reason == .unknown_script);
    const second = try configArchive(fixture, name, arch, "debz-bootstrap-config", second_config, false);
    const archives = [_][]const u8{ first, second };
    const actions = configActions(arch);
    const boundary: []const u8 = switch (reason) {
        .changed_slot => "after_bootstrap_config_stage",
        .corrupt_journal, .forged_journal => "during_bootstrap_config_staging",
        .unknown_script => "after_script_return_before_outcome",
    };
    _ = try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "crash"), .{
        .operation = "install",
        .archives = &archives,
        .ordered_actions = &actions,
        .crash = boundary,
    });
    var retained = try evidence(fixture, root);
    defer retained.deinit();
    const intent = try read(fixture, root, intent_path, 16 * 1024 * 1024);
    if (reason == .corrupt_journal or reason == .forged_journal or reason == .unknown_script)
        try absent(fixture, root, config_slot)
    else
        try equal(try read(fixture, root, config_slot, 64 * 1024), first_config);
    if (reason == .unknown_script) {
        try equal(try read(fixture, root, "var/lib/dpkg/info/dpkg.config", 64 * 1024), first_config);
        try equal(try read(fixture, root, "var/lib/dpkg/info/debz-bootstrap-config.config", 64 * 1024), second_config);
    } else try absent(fixture, root, "var/lib/dpkg/info/debz-bootstrap-config.config");
    try absent(fixture, root, config_marker);
    if (reason == .changed_slot)
        try fixture.write(try path(fixture, root, config_slot), "forged config\n", 0o755);
    if (reason == .corrupt_journal)
        try fixture.write(try path(fixture, root, debz.root_mutation.journal_path), "{\"forged\":true}\n", 0o600);
    if (reason == .forged_journal)
        try forgeConfigJournal(fixture, root);
    if (reason == .unknown_script) {
        try equal(try read(fixture, root, "var/log/config-postinst-invoked", 64), "invoked\n");
        var active = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try read(fixture, root, "var/lib/debz/native-lifecycle-script-v1.json", 1024 * 1024), .{});
        defer active.deinit();
        try equal(try text(active.value, "outcome"), "in_flight");
    }
    for (archives) |archive| {
        try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
        try support.absent(fixture, archive[fixture.path.len + 1 ..]);
    }
    const before = try snapshot(fixture, root);
    const original_claim = try configClaim(fixture, root);
    for (0..2) |index| {
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/refused-{d}", .{ name, index });
        try expectReport(try invoke(fixture, driver, root, arch, destination, .{
            .operation = "recover",
        }), "recovery_required", switch (reason) {
            .changed_slot => "FileNotFound",
            .corrupt_journal => "JournalCorrupt",
            .forged_journal => "AttemptMismatch",
            .unknown_script => "script_outcome_unknown",
        });
        try unchanged(fixture, root, before);
        try equal(try configClaim(fixture, root), original_claim);
        try equal(try read(fixture, root, intent_path, 16 * 1024 * 1024), intent);
        try absent(fixture, root, completion_path);
        try absent(fixture, root, config_marker);
        if (reason == .unknown_script)
            try equal(try read(fixture, root, "var/log/config-postinst-invoked", 64), "invoked\n");
        var owner = try std.json.parseFromSlice(std.json.Value, fixture.allocator, try read(fixture, root, operation_path, 64 * 1024), .{});
        defer owner.deinit();
        try equal(try text(owner.value, "attempt_id"), &retained.intent.intent.attempt_id);
        try equal(try text(owner.value, "backend"), "native");
    }
    const unowned = [_]foundation.PackageIdentity{.{ .name = "debz-unowned-second", .architecture = arch }};
    try expectReport(try invoke(fixture, driver, root, arch, try support.path(fixture.allocator, name, "blocked-purge"), .{
        .operation = "purge",
        .packages = &unowned,
    }), "recovery_required", null);
    try unchanged(fixture, root, before);
    try equal(try configClaim(fixture, root), original_claim);
    try equal(try read(fixture, root, intent_path, 16 * 1024 * 1024), intent);
    try absent(fixture, root, completion_path);
    std.debug.print("{s}: real exit 86, repeated typed refusal and no new mutation passed\n", .{name});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    const helper = args.next() orelse return error.MissingNativeHelper;
    var pinned: ?[]const u8 = null;
    var selected: ?[]const u8 = null;
    while (args.next()) |argument| {
        if (std.mem.eql(u8, argument, "--reference-dpkg")) {
            if (pinned != null) return error.DuplicateReference;
            pinned = args.next() orelse return error.MissingReferencePath;
        } else if (std.mem.eql(u8, argument, "--case")) {
            if (selected != null) return error.DuplicateBootstrapCase;
            selected = args.next() orelse return error.MissingBootstrapCase;
        } else return error.InvalidArguments;
    }
    const reference = try support.prerequisites(init, allocator, pinned orelse return error.PinnedReferenceRequired);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed after bootstrap failure: {s}\n", .{@errorName(err)});
    var matched = false;
    for (recoverable) |boundary| {
        if (selected != null and !std.mem.eql(u8, selected.?, boundary)) continue;
        matched = true;
        try recovered(&fixture, driver, reference.executable, reference.architecture, boundary, boundary, false, null);
    }
    for (unknown_probe) |boundary| {
        if (selected != null and !std.mem.eql(u8, selected.?, boundary)) continue;
        matched = true;
        try blocked(&fixture, driver, helper, reference.architecture, boundary, boundary, .probe);
    }
    for ([_]struct { name: []const u8, reason: Block }{
        .{ .name = "ambient-target", .reason = .ambient_target },
        .{ .name = "ambient-source", .reason = .ambient_source },
    }) |scenario| {
        if (selected != null and !std.mem.eql(u8, selected.?, scenario.name)) continue;
        matched = true;
        try blocked(&fixture, driver, helper, reference.architecture, scenario.name, "after_execution_intent", scenario.reason);
    }
    for (cleanup) |boundary| {
        const name = try std.fmt.allocPrint(allocator, "cleanup-{s}", .{boundary});
        if (selected != null and !std.mem.eql(u8, selected.?, name)) continue;
        matched = true;
        try recovered(&fixture, driver, reference.executable, reference.architecture, name, "after_helper_probe_completed", false, boundary);
    }
    for (script_known) |boundary| {
        const name = try std.fmt.allocPrint(allocator, "script-{s}", .{boundary});
        if (selected != null and !std.mem.eql(u8, selected.?, name)) continue;
        matched = true;
        try recovered(&fixture, driver, reference.executable, reference.architecture, name, boundary, true, null);
    }
    const script_unknown = "script-after_script_return_before_outcome";
    if (selected == null or std.mem.eql(u8, selected.?, script_unknown)) {
        matched = true;
        try blocked(&fixture, driver, helper, reference.architecture, script_unknown, "after_script_return_before_outcome", .script);
    }
    for (config_boundaries) |boundary| {
        const name = try std.fmt.allocPrint(allocator, "config-{s}", .{boundary});
        if (selected != null and !std.mem.eql(u8, selected.?, name)) continue;
        matched = true;
        try configCase(&fixture, driver, reference.executable, reference.architecture, boundary);
    }
    for ([_]ConfigRefusal{ .changed_slot, .corrupt_journal, .forged_journal, .unknown_script }) |reason| {
        const name = switch (reason) {
            .changed_slot => "config-changed-slot",
            .corrupt_journal => "config-corrupt-journal",
            .forged_journal => "config-forged-journal",
            .unknown_script => "config-unknown-script",
        };
        if (selected != null and !std.mem.eql(u8, selected.?, name)) continue;
        matched = true;
        try configRefusal(&fixture, driver, reference.architecture, reason);
    }
    if (!matched) return error.InvalidBootstrapCase;
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
