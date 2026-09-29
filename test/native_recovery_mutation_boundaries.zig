const std = @import("std");
const debz = @import("debz");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");
const mutation = debz.root_mutation;
const root_fs = debz.root_fs;

const package = "mutation-boundary-fixture";
const payload_path = "usr/share/" ++ package ++ "/data";
const namespace = "var/lib/debz/";
const owner_path = namespace ++ "root-operation-v1.json";
const intent_path = namespace ++ "native-execution-intent-v1.json";
const completion_path = namespace ++ "root-operation-completion-v1.json";
const case_table_version: u32 = 1;

const boundaries = [_]mutation.Boundary{
    .journal_write,
    .journal_sync,
    .progress_append,
    .progress_sync,
    .progress_truncate,
    .workspace_create,
    .stage_create,
    .stage_write,
    .stage_sync,
    .stage_metadata,
    .stage_dir_sync,
    .backup_link,
    .backup_dir_sync,
};

comptime {
    if (boundaries.len != 13) @compileError("all thirteen journal/staging boundaries must be selected");
    for (boundaries, 0..) |boundary, index| {
        for (boundaries[0..index]) |previous|
            if (boundary == previous) @compileError("duplicate root-mutation crash selector");
    }
}

const Report = struct {
    outcome: []const u8,
    detail: []const u8 = "",
    attempt_id: ?[]const u8 = null,
    program_sha256: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
};

const Call = struct {
    operation: []const u8,
    archive: ?[]const u8 = null,
    boundary: ?mutation.Boundary = null,
    crash_at: ?[]const u8 = null,
    acknowledge: bool = false,
};

fn path(f: *foundation.Fixture, root: []const u8, name: []const u8) ![]u8 {
    if (root.len <= f.path.len or !std.mem.startsWith(u8, root, f.path) or root[f.path.len] != '/')
        return error.NotDisposableRoot;
    return support.path(f.allocator, root[f.path.len + 1 ..], name);
}

fn read(f: *foundation.Fixture, root: []const u8, name: []const u8) ![]u8 {
    return support.read(f, try path(f, root, name), 16 * 1024 * 1024);
}

fn document(f: *foundation.Fixture, root: []const u8, name: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(std.json.Value, f.allocator, try read(f, root, name), .{
        .allocate = .alloc_always,
    });
}

fn text(value: std.json.Value, key: []const u8) ![]const u8 {
    if (value != .object) return error.InvalidMutationEvidence;
    const found = value.object.get(key) orelse return error.MissingMutationEvidence;
    if (found != .string) return error.InvalidMutationEvidence;
    return found.string;
}

fn field(value: std.json.Value, key: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidMutationEvidence;
    return value.object.get(key) orelse error.MissingMutationEvidence;
}

fn same(actual: []const u8, expected: []const u8) !void {
    if (std.mem.eql(u8, actual, expected)) return;
    std.debug.print("mutation evidence: expected {s}, got {s}\n", .{ expected, actual });
    return error.MutationEvidenceMismatch;
}

fn entry(f: *foundation.Fixture, root: []const u8, name: []const u8) !root_fs.Entry {
    var guarded = try foundation.guardedRoot(f.io, root);
    defer guarded.close(f.io);
    return (root_fs.Root.init(f.io, guarded)).entry(try root_fs.Path.init(name));
}

fn checkWorkspace(
    f: *foundation.Fixture,
    root: root_fs.Root,
    journal: mutation.Journal,
    boundary: mutation.Boundary,
) !void {
    const backup = boundary == .backup_dir_sync;
    if (!backup and boundary != .stage_dir_sync) return;
    for (journal.steps) |step| {
        const name = (if (backup) step.backup_entry else step.staging_entry) orelse continue;
        const location = try std.fmt.allocPrint(f.allocator, "{s}/{s}", .{
            if (backup) mutation.backup_path else mutation.staging_path, name,
        });
        const stored = try root.entryIfExists(try root_fs.Path.init(location)) orelse continue;
        const recorded = switch (if (backup) step.expected else step.desired) {
            .present => |value| value,
            .absent => continue,
        };
        if (stored.kind != .file or recorded.kind != .regular) continue;
        const bytes = try root.readFileAlloc(f.allocator, try root_fs.Path.init(location), 16 * 1024 * 1024);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
        if (!std.mem.eql(u8, &(recorded.content_sha256 orelse return error.MissingWorkspaceDigest), &digest) or
            stored.size != recorded.size or stored.mode != recorded.metadata.mode or
            stored.uid != recorded.metadata.uid or stored.gid != recorded.metadata.gid or
            stored.modified_nanoseconds != recorded.metadata.modified_nanoseconds)
            return error.WorkspaceDidNotPreserveRecordedBytesAndOwnership;
        if (backup) {
            const target = try root.entry(try root_fs.Path.init(step.path));
            if (stored.inode != target.inode or stored.inode != recorded.inode or
                stored.link_count < 2)
                return error.BackupDidNotPinOriginalInode;
        }
        return;
    }
    return error.MissingPhysicalWorkspaceEvidence;
}

fn invoke(
    f: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    arch: []const u8,
    destination: []const u8,
    call: Call,
) !?std.json.Parsed(Report) {
    var guarded = try foundation.guardedRoot(f.io, root);
    guarded.close(f.io);
    if (std.mem.eql(u8, call.operation, "recover") and
        (call.archive != null or call.boundary != null or call.crash_at != null))
        return error.RecoveryMustUseRetainedEvidence;
    try f.directory(destination);
    const request = try support.path(f.allocator, destination, "request.json");
    const response = try support.path(f.allocator, destination, "report.json");
    try support.absent(f, response);
    const request_absolute = try f.absolute(request);
    const response_absolute = try f.absolute(response);
    const packages = [_]foundation.PackageIdentity{.{ .name = package, .architecture = arch }};
    const payload = try std.json.Stringify.valueAlloc(f.allocator, .{
        .root = root,
        .architecture = arch,
        .operation = call.operation,
        .archives = if (call.archive) |archive| &.{archive} else &.{},
        .packages = if (std.mem.eql(u8, call.operation, "purge")) &packages else &.{},
        .report = response_absolute,
        .recovery = true,
        .caller_owned = true,
        .isolated_helper = true,
        .acknowledge_native = call.acknowledge,
        .root_mutation_crash = call.boundary,
        .crash_at = call.crash_at,
    }, .{});
    try f.write(request, payload, 0o600);
    try f.environment.put("DEBZ_NATIVE_LIFECYCLE_REQUEST", request_absolute);
    const result = try std.process.run(f.allocator, f.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", driver },
        .environ_map = &f.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    });
    defer f.allocator.free(result.stdout);
    defer f.allocator.free(result.stderr);
    const output = try std.mem.concat(f.allocator, u8, &.{ result.stdout, result.stderr });
    const log = try support.path(f.allocator, destination, "native.log");
    try f.write(log, output, 0o644);
    const expected: u8 = if (call.boundary != null or call.crash_at != null) 86 else 0;
    if (result.term != .exited or result.term.exited != expected) {
        std.debug.print("{s}: native exit {any}, expected {d}; {s}\n", .{
            destination, result.term, expected, output[output.len - @min(output.len, 12_000) ..],
        });
        return error.UnexpectedMutationChildExit;
    }
    if (expected == 86) {
        try support.absent(f, response);
        return null;
    }
    const bytes = try support.read(f, response, 64 * 1024);
    return try std.json.parseFromSlice(Report, f.allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
}

fn expectReport(report: ?std.json.Parsed(Report), outcome: []const u8) !void {
    var owned = report orelse return error.MissingMutationReport;
    defer owned.deinit();
    try same(owned.value.outcome, outcome);
}

fn checkEvidence(
    f: *foundation.Fixture,
    root: []const u8,
    boundary: mutation.Boundary,
    old_bytes: []const u8,
    old_entry: root_fs.Entry,
    old_status: []const u8,
) ![]u8 {
    var owner = try document(f, root, owner_path);
    defer owner.deinit();
    var intent = try document(f, root, intent_path);
    defer intent.deinit();
    const attempt_id = try f.allocator.dupe(u8, try text(owner.value, "attempt_id"));
    try same(try text(intent.value, "attempt_id"), attempt_id);
    try same(try text(owner.value, "backend"), "native");
    try same(try text(intent.value, "operation"), "upgrade");
    try same(try text(intent.value, "install_root"), root);
    for ([_][]const u8{ "program_sha256", "authorization_sha256", "artifact_evidence_sha256" }) |key|
        try same(try text(owner.value, key), try text(intent.value, key));
    const lock = try field(owner.value, "exact_lock");
    try same(try text(lock, "digest_sha256"), try text(intent.value, "exact_lock_sha256"));
    const program_path = try support.path(f.allocator, namespace[0 .. namespace.len - 1], try text(intent.value, "program_path"));
    var program = try document(f, root, program_path);
    defer program.deinit();
    try same(try text(program.value, "digest_sha256"), try text(intent.value, "program_sha256"));
    if (boundary == .workspace_create or boundary == .journal_write) {
        try support.absent(f, try path(f, root, mutation.journal_path));
        if (boundary == .workspace_create)
            try support.absent(f, try path(f, root, mutation.workspace_path));
    } else {
        var guarded = try foundation.guardedRoot(f.io, root);
        defer guarded.close(f.io);
        const confined = root_fs.Root.init(f.io, guarded);
        const raw = try confined.readFileAlloc(f.allocator, try root_fs.Path.init(mutation.journal_path), mutation.maximum_document_bytes);
        var journal = try mutation.decode(f.allocator, raw, mutation.maximum_document_bytes);
        defer journal.deinit();
        try same(&std.fmt.bytesToHex(journal.journal.attempt_id, .lower), attempt_id);
        try same(journal.journal.install_root, root);
        try same(&std.fmt.bytesToHex(journal.journal.evidence.program_sha256 orelse return error.MissingJournalBinding, .lower), try text(intent.value, "program_sha256"));
        try same(&std.fmt.bytesToHex(journal.journal.evidence.authorization_sha256 orelse return error.MissingJournalBinding, .lower), try text(intent.value, "authorization_sha256"));
        const bound_lock = journal.journal.evidence.exact_lock orelse return error.MissingJournalBinding;
        try same(&std.fmt.bytesToHex(bound_lock.digest_sha256, .lower), try text(intent.value, "exact_lock_sha256"));
        if (journal.journal.evidence.plan_sha256 == null or journal.journal.steps.len == 0)
            return error.MissingJournalPlan;
        var old_step = false;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(old_bytes, &digest, .{});
        for (journal.journal.steps) |step| {
            if (!std.mem.eql(u8, step.path, payload_path)) continue;
            const old = switch (step.expected) {
                .present => |value| value,
                .absent => return error.MissingRecordedOldFile,
            };
            if (old.kind != .regular or !std.mem.eql(u8, &(old.content_sha256 orelse return error.MissingRecordedOldFile), &digest) or
                old.metadata.mode != old_entry.mode or old.metadata.uid != old_entry.uid or
                old.metadata.gid != old_entry.gid or old.metadata.modified_nanoseconds != old_entry.modified_nanoseconds or
                old.inode != old_entry.inode)
                return error.OldPayloadJournalBindingChanged;
            old_step = true;
            break;
        }
        if (!old_step) return error.MissingRecordedOldFile;
        const progress_bytes = try (mutation.Store.init(confined)).readProgressBytes(f.allocator);
        var progress = try mutation.replayProgress(f.allocator, journal.journal, progress_bytes);
        defer progress.deinit();
        if (progress.stage != .prepared and progress.stage != .applying)
            return error.UnexpectedMutationJournalDirection;
        if (boundary == .progress_truncate and progress.accepted_bytes >= progress_bytes.len)
            return error.MissingTornProgressTail;
        try checkWorkspace(f, confined, journal.journal, boundary);
    }
    const target = try entry(f, root, payload_path);
    const current = try read(f, root, payload_path);
    if (!std.mem.eql(u8, old_bytes, current) or target.mode != old_entry.mode or
        target.uid != old_entry.uid or target.gid != old_entry.gid or
        target.modified_nanoseconds != old_entry.modified_nanoseconds or target.inode != old_entry.inode)
        return error.PackagePayloadChangedBeforeMutationBoundary;
    if (boundary == .workspace_create or boundary == .journal_write or boundary == .journal_sync or
        boundary == .progress_append or boundary == .progress_sync or boundary == .progress_truncate)
    {
        try same(try read(f, root, "var/lib/dpkg/status"), old_status);
    }
    return attempt_id;
}

fn corruptBackup(f: *foundation.Fixture, root: []const u8) !void {
    var guarded = try foundation.guardedRoot(f.io, root);
    defer guarded.close(f.io);
    const confined = root_fs.Root.init(f.io, guarded);
    var journal = (try (mutation.Store.init(confined)).readJournal(f.allocator)) orelse
        return error.MissingMutationJournal;
    defer journal.deinit();
    for (journal.journal.steps) |step| {
        const backup = step.backup_entry orelse continue;
        const location = try std.fmt.allocPrint(f.allocator, "{s}/{s}", .{ mutation.backup_path, backup });
        if (try confined.entryIfExists(try root_fs.Path.init(location))) |stored| {
            if (stored.kind != .file) continue;
            try f.write(try path(f, root, location), "external backup replacement\n", 0o600);
            return;
        }
    }
    return error.MissingCapturedBackupToChange;
}

fn runCase(f: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, boundary: mutation.Boundary, drift: bool) !void {
    const name = try std.fmt.allocPrint(f.allocator, "mutation-{s}{s}", .{
        @tagName(boundary), if (drift) "-backup-drift" else "",
    });
    var scenario = try support.Scenario.init(f, name, driver, dpkg, arch, true);
    defer scenario.deinit();
    const first = try support.makePackage(f, arch, "1", package, try support.path(f.allocator, name, "packages"), .{
        .full_payload = true,
        .no_scripts = true,
    });
    const second = try support.makePackage(f, arch, "2", package, try support.path(f.allocator, name, "packages"), .{
        .full_payload = true,
        .no_scripts = true,
    });
    try scenario.seed(first);
    const old_bytes = try read(f, scenario.native_root, payload_path);
    const old_entry = try entry(f, scenario.native_root, payload_path);
    const old_status = try read(f, scenario.native_root, "var/lib/dpkg/status");
    const reference_log = try support.path(f.allocator, name, "reference-upgrade");
    try f.directory(reference_log);
    if (try support.reference(f, dpkg, scenario.reference_root, .{
        .operation = "upgrade",
        .archives = &.{second},
        .triggers = true,
    }, reference_log) != 0) return error.PinnedDpkgUpgradeFailed;
    const crash_log = try support.path(f.allocator, name, "crash");
    if (try invoke(f, driver, scenario.native_root, arch, crash_log, .{
        .operation = "upgrade",
        .archive = second,
        .boundary = boundary,
    })) |unexpected| {
        var report = unexpected;
        report.deinit();
        return error.MissingRealMutationCrash;
    }
    const attempt_id = try checkEvidence(f, scenario.native_root, boundary, old_bytes, old_entry, old_status);
    try f.dir.deleteFile(f.io, first[f.path.len + 1 ..]);
    try f.dir.deleteFile(f.io, second[f.path.len + 1 ..]);
    try support.absent(f, first[f.path.len + 1 ..]);
    try support.absent(f, second[f.path.len + 1 ..]);
    if (drift) {
        try corruptBackup(f, scenario.native_root);
        const changed = try foundation.capture(f.allocator, f.io, scenario.native_root);
        const old_intent = try read(f, scenario.native_root, intent_path);
        const old_journal = try read(f, scenario.native_root, mutation.journal_path);
        var first_detail: ?[]const u8 = null;
        for (0..2) |index| {
            const destination = try std.fmt.allocPrint(f.allocator, "{s}/refusal-{d}", .{ name, index });
            var refused = (try invoke(f, driver, scenario.native_root, arch, destination, .{
                .operation = "recover",
            })) orelse return error.MissingMutationRefusal;
            defer refused.deinit();
            try same(refused.value.outcome, "recovery_required");
            if (refused.value.detail.len == 0) return error.UntypedMutationRefusal;
            if (first_detail) |detail| try same(refused.value.detail, detail) else first_detail = try f.allocator.dupe(u8, refused.value.detail);
            if (!std.mem.eql(u8, changed, try foundation.capture(f.allocator, f.io, scenario.native_root)) or
                !std.mem.eql(u8, old_intent, try read(f, scenario.native_root, intent_path)) or
                !std.mem.eql(u8, old_journal, try read(f, scenario.native_root, mutation.journal_path)))
                return error.MutationRefusalChangedEvidence;
            var owner = try document(f, scenario.native_root, owner_path);
            defer owner.deinit();
            try same(try text(owner.value, "attempt_id"), attempt_id);
        }
        try expectReport(try invoke(f, driver, scenario.native_root, arch, try support.path(f.allocator, name, "blocked-refusal"), .{
            .operation = "purge",
        }), "recovery_required");
        if (!std.mem.eql(u8, changed, try foundation.capture(f.allocator, f.io, scenario.native_root)))
            return error.SecondMutationChangedRefusedRoot;
        std.debug.print("root-mutation {s} backup drift: real exit 86, two immutable typed refusals ({s})\n", .{
            @tagName(boundary), first_detail orelse return error.MissingMutationRefusal,
        });
        return;
    }
    const blocked = try support.path(f.allocator, name, "blocked-before-recovery");
    const crashed = try foundation.capture(f.allocator, f.io, scenario.native_root);
    try expectReport(try invoke(f, driver, scenario.native_root, arch, blocked, .{ .operation = "purge" }), "recovery_required");
    if (!std.mem.eql(u8, crashed, try foundation.capture(f.allocator, f.io, scenario.native_root)))
        return error.SecondMutationChangedRoot;
    var recovered = (try invoke(f, driver, scenario.native_root, arch, try support.path(f.allocator, name, "fresh-recovery"), .{
        .operation = "recover",
    })) orelse return error.MissingMutationRecovery;
    defer recovered.deinit();
    try same(recovered.value.outcome, "applied");
    try same(recovered.value.attempt_id orelse return error.MissingMutationRecovery, attempt_id);
    var retained_owner = try document(f, scenario.native_root, owner_path);
    defer retained_owner.deinit();
    try same(try text(retained_owner.value, "attempt_id"), attempt_id);
    var receipt = try document(f, scenario.native_root, debz.native_provenance.legacy_document_path);
    defer receipt.deinit();
    try same(try text(receipt.value, "attempt_id"), attempt_id);
    try same(try text(receipt.value, "program_sha256"), recovered.value.program_sha256 orelse return error.MissingMutationRecovery);
    const comparison = try support.path(f.allocator, name, "comparison");
    try f.directory(comparison);
    try support.compare(f, scenario.reference_root, scenario.native_root, comparison, true);
    const settled = try foundation.capture(f.allocator, f.io, scenario.native_root);
    try expectReport(try invoke(f, driver, scenario.native_root, arch, try support.path(f.allocator, name, "repeat"), .{
        .operation = "recover",
    }), "applied");
    if (!std.mem.eql(u8, settled, try foundation.capture(f.allocator, f.io, scenario.native_root)))
        return error.RepeatRecoveryChangedPackageState;
    try expectReport(try invoke(f, driver, scenario.native_root, arch, try support.path(f.allocator, name, "blocked-before-ack"), .{
        .operation = "purge",
    }), "recovery_required");
    if (!std.mem.eql(u8, settled, try foundation.capture(f.allocator, f.io, scenario.native_root)))
        return error.SecondMutationBeforeAckChangedRoot;
    try expectReport(try invoke(f, driver, scenario.native_root, arch, try support.path(f.allocator, name, "acknowledge"), .{
        .operation = "recover",
        .acknowledge = true,
    }), "applied");
    var completed = try document(f, scenario.native_root, completion_path);
    defer completed.deinit();
    try same(try text(completed.value, "attempt_id"), attempt_id);
    try support.absent(f, try path(f, scenario.native_root, owner_path));
    try support.absent(f, try path(f, scenario.native_root, intent_path));
    try support.compare(f, scenario.reference_root, scenario.native_root, comparison, true);
    std.debug.print("root-mutation {s}: real exit 86, journal binding, eviction, owner through ack, dpkg parity\n", .{@tagName(boundary)});
}

fn beforeIntentControl(f: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const name = "mutation-before-intent-control";
    var scenario = try support.Scenario.init(f, name, driver, dpkg, arch, true);
    defer scenario.deinit();
    const first = try support.makePackage(f, arch, "1", package, name ++ "/packages", .{
        .full_payload = true,
        .no_scripts = true,
    });
    const second = try support.makePackage(f, arch, "2", package, name ++ "/packages", .{
        .full_payload = true,
        .no_scripts = true,
    });
    try scenario.seed(first);
    const before = try foundation.capture(f.allocator, f.io, scenario.native_root);
    const old_entry = try entry(f, scenario.native_root, payload_path);
    const old_bytes = try read(f, scenario.native_root, payload_path);
    if (try invoke(f, driver, scenario.native_root, arch, name ++ "/after-execution-intent", .{
        .operation = "upgrade",
        .archive = second,
        .crash_at = "after_execution_intent",
    })) |unexpected| {
        var report = unexpected;
        report.deinit();
        return error.MissingBeforeIntentControlCrash;
    }
    const after = try foundation.capture(f.allocator, f.io, scenario.native_root);
    if (!std.mem.eql(u8, before, after) or
        !std.meta.eql(old_entry, try entry(f, scenario.native_root, payload_path)) or
        !std.mem.eql(u8, old_bytes, try read(f, scenario.native_root, payload_path)))
        return error.PackageMutationPrecededNativeIntent;
    var owner = try document(f, scenario.native_root, owner_path);
    defer owner.deinit();
    var intent = try document(f, scenario.native_root, intent_path);
    defer intent.deinit();
    try same(try text(owner.value, "attempt_id"), try text(intent.value, "attempt_id"));
    try support.absent(f, try path(f, scenario.native_root, mutation.journal_path));
    std.debug.print("before-intent control: exit 86, native intent durable, no package mutation\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    var pinned: ?[]const u8 = null;
    var selected: ?mutation.Boundary = null;
    while (args.next()) |argument| {
        if (std.mem.eql(u8, argument, "--reference-dpkg")) {
            if (pinned != null) return error.DuplicatePinnedReference;
            pinned = args.next() orelse return error.MissingPinnedReference;
        } else if (std.mem.eql(u8, argument, "--case")) {
            if (selected != null) return error.DuplicateMutationSelector;
            selected = std.meta.stringToEnum(mutation.Boundary, args.next() orelse return error.MissingMutationSelector) orelse
                return error.UnknownMutationSelector;
        } else return error.InvalidArguments;
    }
    const reference = try support.prerequisites(init, allocator, pinned orelse return error.PinnedDpkgRequired);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed: {s}\n", .{@errorName(err)});
    var count: usize = 0;
    if (selected == null)
        try beforeIntentControl(&fixture, driver, reference.executable, reference.architecture);
    for (boundaries) |boundary| {
        if (selected != null and selected.? != boundary) continue;
        runCase(&fixture, driver, reference.executable, reference.architecture, boundary, false) catch |err| {
            std.debug.print("{s}: {s}; fixture {s}\n", .{ @tagName(boundary), @errorName(err), fixture.path });
            return err;
        };
        count += 1;
    }
    if (selected == null)
        try runCase(&fixture, driver, reference.executable, reference.architecture, .backup_dir_sync, true);
    if (count != (if (selected != null) @as(usize, 1) else boundaries.len))
        return error.MutationSelectorAccountingMismatch;
    try support.assertHostUnchanged(allocator, init.io, reference.before);
    std.debug.print("root-mutation journal/staging v{d}: {d}/{d} named real child kills\n", .{
        case_table_version, count, boundaries.len,
    });
}
