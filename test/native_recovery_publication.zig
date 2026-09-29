const std = @import("std");
const debz = @import("debz");
const root_fs = debz.root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const process = @import("native_recovery_scriptless.zig");
const options = @import("native_test_options");

const package = "publication-syscalls";
const payload = "usr/share/" ++ package ++ "/";
const namespace = "var/lib/debz/";
const operation_path = namespace ++ "root-operation-v1.json";
const intent_path = namespace ++ "native-execution-intent-v1.json";
const journal_path = namespace ++ "root-mutation-v1.json";
const completion_path = namespace ++ "root-operation-completion-v1.json";

const Case = struct {
    boundary: []const u8,
    operation: []const u8 = "install",
    stage: []const u8 = "applying",
    drift: enum { none, bytes, mode, journal } = .none,
};

const cases = [_]Case{
    .{ .boundary = "precondition_check" },
    .{ .boundary = "target_remove", .operation = "upgrade" },
    .{ .boundary = "publish_rename", .operation = "upgrade" },
    .{ .boundary = "publish_create" },
    .{ .boundary = "metadata_apply" },
    .{ .boundary = "metadata_chown" },
    .{ .boundary = "metadata_chmod" },
    .{ .boundary = "metadata_utimens" },
    .{ .boundary = "parent_sync" },
    .{ .boundary = "verify" },
    .{ .boundary = "release_staging", .operation = "upgrade", .stage = "completing" },
    .{ .boundary = "release_backup", .operation = "upgrade", .stage = "completing" },
    .{ .boundary = "restore_rename", .operation = "upgrade", .stage = "rolling_back" },
    .{ .boundary = "restore_create", .operation = "upgrade", .stage = "rolling_back" },
    .{ .boundary = "release_backup_rollback", .operation = "upgrade", .stage = "releasing_rollback" },
    .{ .boundary = "publish_rename", .operation = "upgrade", .drift = .bytes },
    .{ .boundary = "publish_rename", .operation = "upgrade", .drift = .mode },
    .{ .boundary = "publish_rename", .operation = "upgrade", .drift = .journal },
};

fn retained(fixture: *foundation.Fixture, root: []const u8, original: std.json.Value, intent: std.json.Value, forged: bool) !void {
    var owner = try process.rootDocument(fixture, root, operation_path);
    defer owner.deinit();
    var execution = try process.rootDocument(fixture, root, intent_path);
    defer execution.deinit();
    for ([_][]const u8{ "attempt_id", "exact_lock_sha256", "authorization_sha256", "program_sha256" }) |field| {
        if (std.mem.eql(u8, field, "attempt_id")) {
            try process.same(try process.text(owner.value, field), try process.text(original, field));
        } else {
            try process.same(try process.text(execution.value, field), try process.text(intent, field));
        }
    }
    try process.same(try process.text(execution.value, "attempt_id"), try process.text(original, "attempt_id"));
    try process.same(try process.text(owner.value, "backend"), "native");
    for ([_][]const u8{ "program_sha256", "authorization_sha256" }) |field|
        try process.same(try process.text(owner.value, field), try process.text(intent, field));
    try process.same(try process.text(try process.field(owner.value, "exact_lock"), "digest_sha256"), try process.text(intent, "exact_lock_sha256"));
    const active = try process.rootBytes(fixture, root, journal_path);
    defer fixture.allocator.free(active);
    var journal = try std.json.parseFromSlice(std.json.Value, fixture.allocator, active, .{});
    defer journal.deinit();
    if (forged) {
        try process.same(try process.text(journal.value, "attempt_id"), &([_]u8{'f'} ** 64));
    } else {
        try process.same(try process.text(journal.value, "attempt_id"), try process.text(original, "attempt_id"));
    }
    try process.same(try process.text(journal.value, "program_sha256"), try process.text(intent, "program_sha256"));
    try process.same(try process.text(try process.field(journal.value, "exact_lock"), "digest_sha256"), try process.text(intent, "exact_lock_sha256"));
}

fn forgeJournal(fixture: *foundation.Fixture, root: []const u8) !void {
    const bytes = try process.rootBytes(fixture, root, journal_path);
    defer fixture.allocator.free(bytes);
    const owner = "\"attempt_id\":\"";
    const owner_start = (std.mem.indexOf(u8, bytes, owner) orelse return error.MissingJournalOwner) + owner.len;
    if (owner_start + 64 > bytes.len) return error.InvalidJournalOwner;
    @memset(bytes[owner_start..][0..64], 'f');
    const digest_field = ",\"digest_sha256\":\"";
    const digest_start = std.mem.lastIndexOf(u8, bytes, digest_field) orelse return error.MissingJournalDigest;
    const digest_value = digest_start + digest_field.len;
    if (digest_value + 64 > bytes.len) return error.InvalidJournalDigest;
    const payload_bytes = try std.mem.concat(fixture.allocator, u8, &.{ bytes[0..digest_start], "}" });
    defer fixture.allocator.free(payload_bytes);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload_bytes, &digest, .{});
    const sealed = std.fmt.bytesToHex(digest, .lower);
    @memcpy(bytes[digest_value..][0..64], &sealed);
    var decoded = try debz.root_mutation.decode(fixture.allocator, bytes, debz.root_mutation.maximum_document_bytes);
    defer decoded.deinit();
    if (!std.mem.eql(u8, &decoded.journal.attempt_id, &([_]u8{0xff} ** 32)))
        return error.JournalForgeryNotCanonical;
    const destination = try process.rootPath(fixture, root, journal_path);
    defer fixture.allocator.free(destination);
    try support.fixtureFile(fixture, destination, bytes, 0o600);
}

fn checkPayload(
    fixture: *foundation.Fixture,
    root: []const u8,
    journal: std.json.Value,
    state: []const u8,
    path: []const u8,
) !void {
    const steps = try process.field(journal, "steps");
    if (steps != .array) return error.InvalidMutationSteps;
    for (steps.array.items) |step| {
        if (!std.mem.eql(u8, try process.text(step, "path"), path)) continue;
        if (std.mem.eql(u8, state, "desired") and std.mem.eql(u8, path, payload ++ "empty") and
            !std.mem.eql(u8, try process.text(step, "kind"), "set_metadata")) continue;
        const expected = try process.field(step, state);
        if (expected == .null) {
            try process.rootAbsent(fixture, root, path);
            return;
        }
        if (expected != .object) return error.InvalidMutationState;
        var guarded = try foundation.guardedRoot(fixture.io, root);
        defer guarded.close(fixture.io);
        const confined: root_fs.Root = .init(fixture.io, guarded);
        const entry = try confined.entry(try root_fs.Path.initPackage(path));
        const mode = try process.field(expected, "mode");
        const uid = try process.field(expected, "uid");
        const gid = try process.field(expected, "gid");
        const timestamp = try process.field(expected, "modified_nanoseconds");
        if (mode != .integer or uid != .integer or gid != .integer or timestamp != .integer or
            entry.mode != mode.integer or entry.uid != uid.integer or entry.gid != gid.integer or
            (timestamp.integer != 0 and entry.modified_nanoseconds != timestamp.integer))
            return error.IncorrectPayloadMetadata;
        const kind = try process.text(expected, "kind");
        if (std.mem.eql(u8, kind, "regular")) {
            const bytes = try process.rootBytes(fixture, root, path);
            defer fixture.allocator.free(bytes);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
            try process.same(try process.text(expected, "content_sha256"), &std.fmt.bytesToHex(digest, .lower));
        } else if (std.mem.eql(u8, kind, "symlink")) {
            var buffer: [4096]u8 = undefined;
            try process.same(try confined.readSymbolicLink(try root_fs.Path.initPackage(path), &buffer), try process.text(expected, "link_target"));
        } else if (!std.mem.eql(u8, kind, "directory")) return error.InvalidMutationState;
        return;
    }
    return error.MissingMutationStep;
}

fn checkMetadataBoundary(fixture: *foundation.Fixture, root: []const u8, boundary: []const u8) !void {
    if (!std.mem.eql(u8, boundary, "metadata_chown") and
        !std.mem.eql(u8, boundary, "metadata_chmod") and
        !std.mem.eql(u8, boundary, "metadata_utimens")) return;
    var guarded = try foundation.guardedRoot(fixture.io, root);
    defer guarded.close(fixture.io);
    const entry = try (root_fs.Root.init(fixture.io, guarded)).entry(
        try root_fs.Path.initPackage(payload ++ "empty"),
    );
    const chown = std.mem.eql(u8, boundary, "metadata_chown");
    const utimens = std.mem.eql(u8, boundary, "metadata_utimens");
    if (entry.kind != .directory or
        entry.uid != (if (chown) @as(u32, 0) else 42420) or
        entry.gid != (if (chown) @as(u32, 0) else 42421) or
        entry.mode != (if (utimens) @as(u32, 0o2555) else 0o2755) or
        entry.modified_nanoseconds == foundation.epoch * std.time.ns_per_s)
        return error.IncorrectInterruptedMetadata;
}

fn checkDirectoryPlan(journal: std.json.Value) !void {
    const steps = try process.field(journal, "steps");
    if (steps != .array) return error.InvalidMutationSteps;
    for (steps.array.items) |step| {
        if (!std.mem.eql(u8, try process.text(step, "path"), payload ++ "empty") or
            !std.mem.eql(u8, try process.text(step, "kind"), "set_metadata")) continue;
        const desired = try process.field(step, "desired");
        try process.same(try process.text(desired, "kind"), "directory");
        for ([_]struct { field: []const u8, value: i64 }{
            .{ .field = "uid", .value = 42420 },
            .{ .field = "gid", .value = 42421 },
            .{ .field = "mode", .value = 0o2555 },
        }) |expected| {
            const actual = try process.field(desired, expected.field);
            if (actual != .integer or actual.integer != expected.value)
                return error.WrongPlannedMetadata;
        }
        return;
    }
    return error.MissingMetadataStep;
}

fn invoke(fixture: *foundation.Fixture, driver: []const u8, root: []const u8, arch: []const u8, name: []const u8, input: process.Invocation) !std.json.Parsed(process.Report) {
    const log = try support.path(fixture.allocator, name, "log");
    defer fixture.allocator.free(log);
    return (try process.invoke(fixture, driver, root, arch, log, input)) orelse error.MissingNativeReport;
}

fn runCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, entry: Case, first: []const u8, second: []const u8) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "mutation-{s}{s}", .{
        entry.boundary,
        if (entry.drift == .none) "" else switch (entry.drift) {
            .none => unreachable,
            .bytes => "-bytes-drift",
            .mode => "-mode-drift",
            .journal => "-forged-journal",
        },
    });
    defer fixture.allocator.free(name);
    var scenario = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer scenario.deinit();
    const archive_directory = try support.path(fixture.allocator, name, "archives");
    defer fixture.allocator.free(archive_directory);
    const first_copy = try support.path(fixture.allocator, archive_directory, "first.deb");
    defer fixture.allocator.free(first_copy);
    const second_copy = try support.path(fixture.allocator, archive_directory, "second.deb");
    defer fixture.allocator.free(second_copy);
    const first_bytes = try support.read(fixture, first[fixture.path.len + 1 ..], 16 * 1024 * 1024);
    defer fixture.allocator.free(first_bytes);
    const second_bytes = try support.read(fixture, second[fixture.path.len + 1 ..], 16 * 1024 * 1024);
    defer fixture.allocator.free(second_bytes);
    try support.fixtureFile(fixture, first_copy, first_bytes, 0o644);
    try support.fixtureFile(fixture, second_copy, second_bytes, 0o644);
    const first_absolute = try fixture.absolute(first_copy);
    defer fixture.allocator.free(first_absolute);
    const second_absolute = try fixture.absolute(second_copy);
    defer fixture.allocator.free(second_absolute);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const base = try support.path(fixture.allocator, name, side);
        defer fixture.allocator.free(base);
        const records = try support.path(fixture.allocator, base, "var/lib/dpkg/statoverride");
        defer fixture.allocator.free(records);
        try support.fixtureFile(fixture, records, "#42420 #42421 2555 /" ++ payload ++ "empty\n", 0o644);
    }
    if (!std.mem.eql(u8, entry.operation, "install")) try scenario.seed(first_absolute);
    const selected = [_]foundation.PackageIdentity{.{ .name = package, .architecture = arch }};
    const archives: []const []const u8 = if (std.mem.eql(u8, entry.operation, "install"))
        &.{first_absolute}
    else if (std.mem.eql(u8, entry.operation, "upgrade"))
        &.{second_absolute}
    else
        &.{};
    const reference_log = try support.path(fixture.allocator, name, "reference-run");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    if (try support.reference(fixture, dpkg, scenario.reference_root, .{
        .operation = entry.operation,
        .archives = archives,
        .packages = &selected,
        .triggers = false,
    }, reference_log) != 0) return error.ReferenceMutationFailed;

    const crash_at = try std.fmt.allocPrint(fixture.allocator, "mutation_{s}", .{entry.boundary});
    defer fixture.allocator.free(crash_at);
    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, scenario.native_root, arch, crash_log, .{
        .operation = entry.operation,
        .archives = archives,
        .packages = &selected,
        .crash_at = crash_at,
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) |report| {
        var unexpected = report;
        unexpected.deinit();
        return error.MissingMutationCrash;
    }
    var original = try process.rootDocument(fixture, scenario.native_root, operation_path);
    defer original.deinit();
    var intent = try process.rootDocument(fixture, scenario.native_root, intent_path);
    defer intent.deinit();
    try retained(fixture, scenario.native_root, original.value, intent.value, false);
    var journal = try process.rootDocument(fixture, scenario.native_root, journal_path);
    defer journal.deinit();
    const steps = try process.field(journal.value, "steps");
    if (steps != .array or steps.array.items.len == 0) return error.MissingMutationStep;
    if (std.mem.startsWith(u8, entry.boundary, "metadata_") or std.mem.eql(u8, entry.boundary, "publish_create"))
        try checkDirectoryPlan(journal.value);
    try checkMetadataBoundary(fixture, scenario.native_root, entry.boundary);
    if (std.mem.eql(u8, entry.boundary, "publish_create"))
        try checkPayload(fixture, scenario.native_root, journal.value, "expected", payload ++ "empty");
    const progress = try process.rootBytes(fixture, scenario.native_root, debz.root_mutation.progress_path);
    defer fixture.allocator.free(progress);
    if (std.mem.indexOf(u8, progress, entry.stage) == null) return error.WrongMutationStage;
    if (std.mem.eql(u8, entry.stage, "completing"))
        try checkPayload(fixture, scenario.native_root, journal.value, "desired", payload ++ "data");
    if (std.mem.eql(u8, entry.stage, "releasing_rollback"))
        try checkPayload(fixture, scenario.native_root, journal.value, "expected", payload ++ "data");
    if (std.mem.eql(u8, entry.stage, "rolling_back"))
        try checkPayload(fixture, scenario.native_root, journal.value, "desired", if (std.mem.eql(u8, entry.boundary, "restore_rename")) payload ++ "data" else payload ++ "current");
    if (std.mem.eql(u8, entry.boundary, "publish_rename"))
        try checkPayload(fixture, scenario.native_root, journal.value, "expected", payload ++ "data");
    try fixture.dir.deleteFile(fixture.io, first_copy);
    try fixture.dir.deleteFile(fixture.io, second_copy);
    try support.absent(fixture, first_copy);
    try support.absent(fixture, second_copy);

    if (entry.drift == .none) {
        const before_second = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
        defer fixture.allocator.free(before_second);
        const blocked_log = try support.path(fixture.allocator, name, "blocked-before-recovery");
        defer fixture.allocator.free(blocked_log);
        const unrelated = [_]foundation.PackageIdentity{.{ .name = "publication-unrelated", .architecture = arch }};
        var blocked = try invoke(fixture, driver, scenario.native_root, arch, blocked_log, .{
            .operation = "purge",
            .packages = &unrelated,
            .triggers = false,
            .caller_owned = true,
            .isolated_helper = true,
            .core_product = true,
        });
        defer blocked.deinit();
        if (!std.mem.eql(u8, blocked.value.outcome, "recovery_required") and
            !std.mem.eql(u8, blocked.value.outcome, "refused")) return error.SecondMutationWasAccepted;
        try retained(fixture, scenario.native_root, original.value, intent.value, false);
        const after_second = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
        defer fixture.allocator.free(after_second);
        if (!std.mem.eql(u8, before_second, after_second)) return error.SecondMutationChangedRoot;
    }

    if (entry.drift != .none) {
        switch (entry.drift) {
            .bytes => {
                const target = try process.rootPath(fixture, scenario.native_root, payload ++ "data");
                defer fixture.allocator.free(target);
                try support.fixtureFile(fixture, target, "contradictory publication bytes\n", 0o644);
            },
            .mode => {
                var guarded = try foundation.guardedRoot(fixture.io, scenario.native_root);
                defer guarded.close(fixture.io);
                try (root_fs.Root.init(fixture.io, guarded)).applyMetadata(
                    try root_fs.Path.initPackage(payload ++ "data"),
                    .{ .mode = 0o600 },
                );
            },
            .journal => try forgeJournal(fixture, scenario.native_root),
            .none => unreachable,
        }
        const intent_before = try process.rootBytes(fixture, scenario.native_root, intent_path);
        defer fixture.allocator.free(intent_before);
        const journal_before = try process.rootBytes(fixture, scenario.native_root, journal_path);
        defer fixture.allocator.free(journal_before);
        const before = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
        defer fixture.allocator.free(before);
        for (0..2) |iteration| {
            const refusal_log = try std.fmt.allocPrint(fixture.allocator, "{s}/refusal-{d}", .{ name, iteration });
            defer fixture.allocator.free(refusal_log);
            var refusal = try invoke(fixture, driver, scenario.native_root, arch, refusal_log, .{
                .operation = "recover",
                .caller_owned = true,
                .isolated_helper = true,
                .core_product = true,
            });
            defer refusal.deinit();
            try process.same(refusal.value.outcome, "recovery_required");
            if (std.mem.indexOf(u8, refusal.value.detail, if (entry.drift == .journal) "AttemptMismatch" else "recovery_required") == null)
                return error.MissingTypedMutationRefusal;
            try retained(fixture, scenario.native_root, original.value, intent.value, entry.drift == .journal);
            const intent_after = try process.rootBytes(fixture, scenario.native_root, intent_path);
            defer fixture.allocator.free(intent_after);
            const journal_after = try process.rootBytes(fixture, scenario.native_root, journal_path);
            defer fixture.allocator.free(journal_after);
            if (!std.mem.eql(u8, journal_before, journal_after) or !std.mem.eql(u8, intent_before, intent_after))
                return error.RefusalChangedOriginalEvidence;
            const after = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
            defer fixture.allocator.free(after);
            if (!std.mem.eql(u8, before, after)) return error.RefusalMutatedRoot;
        }
        const block_log = try support.path(fixture.allocator, name, "blocked-mutation");
        defer fixture.allocator.free(block_log);
        var blocked = try invoke(fixture, driver, scenario.native_root, arch, block_log, .{
            .operation = "purge",
            .packages = &selected,
            .triggers = false,
            .caller_owned = true,
            .isolated_helper = true,
            .core_product = true,
        });
        defer blocked.deinit();
        if (!std.mem.eql(u8, blocked.value.outcome, "refused") and
            !std.mem.eql(u8, blocked.value.outcome, "recovery_required")) return error.SecondMutationWasAccepted;
        try retained(fixture, scenario.native_root, original.value, intent.value, entry.drift == .journal);
        return;
    }

    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var recovered = try invoke(fixture, driver, scenario.native_root, arch, recovery_log, .{
        .operation = "recover",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    });
    defer recovered.deinit();
    try process.same(recovered.value.outcome, "applied");
    try process.same(recovered.value.attempt_id orelse return error.MissingAttempt, try process.text(original.value, "attempt_id"));
    try process.same(recovered.value.program_sha256 orelse return error.MissingProgram, try process.text(intent.value, "program_sha256"));
    if (std.mem.eql(u8, entry.operation, "install"))
        try checkPayload(fixture, scenario.native_root, journal.value, "desired", payload ++ "empty");
    const comparison = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(comparison);
    try fixture.directory(comparison);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, comparison, true);
    var completion = try process.rootDocument(fixture, scenario.native_root, completion_path);
    defer completion.deinit();
    try process.same(try process.text(completion.value, "attempt_id"), try process.text(original.value, "attempt_id"));
    const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);
    var proof = try process.rootDocument(fixture, scenario.native_root, proof_path);
    defer proof.deinit();
    try process.same(try process.text(proof.value, "attempt_id"), try process.text(original.value, "attempt_id"));
    try process.same(try process.text(proof.value, "program_sha256"), try process.text(intent.value, "program_sha256"));
    try process.same(try process.text(proof.value, "exact_lock_sha256"), try process.text(intent.value, "exact_lock_sha256"));
    try process.same(try process.text(try process.field(completion.value, "transaction_provenance"), "document_sha256"), try process.text(proof.value, "digest_sha256"));
    try process.rootAbsent(fixture, scenario.native_root, operation_path);
    try process.rootAbsent(fixture, scenario.native_root, intent_path);
    try process.rootAbsent(fixture, scenario.native_root, journal_path);
    const settled = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
    defer fixture.allocator.free(settled);
    const repeat_log = try support.path(fixture.allocator, name, "recover-again");
    defer fixture.allocator.free(repeat_log);
    var repeated = try invoke(fixture, driver, scenario.native_root, arch, repeat_log, .{
        .operation = "recover",
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    });
    defer repeated.deinit();
    try process.same(repeated.value.outcome, "applied");
    const after = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, settled, after)) return error.RepeatedRecoveryMutatedRoot;
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    var pinned: ?[]const u8 = null;
    while (args.next()) |argument| {
        if (!std.mem.eql(u8, argument, "--reference-dpkg") or pinned != null) return error.InvalidArguments;
        pinned = args.next() orelse return error.MissingReferencePath;
    }
    const reference = try support.prerequisites(init, allocator, pinned);
    defer allocator.free(reference.architecture);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    const workspace = "publication-packages";
    const first = try support.makePackage(&fixture, reference.architecture, "1", package, workspace, .{
        .no_scripts = true,
        .full_payload = true,
    });
    defer allocator.free(first);
    const second = try support.makePackage(&fixture, reference.architecture, "2", package, workspace, .{
        .no_scripts = true,
        .full_payload = true,
    });
    defer allocator.free(second);
    const link = try support.path(allocator, workspace, package ++ "_2_data.source/" ++ payload ++ "current");
    defer allocator.free(link);
    try fixture.dir.deleteFile(fixture.io, link);
    try fixture.dir.symLink(fixture.io, "mode", link, .{});
    try fixture.dir.deleteFile(fixture.io, second[fixture.path.len + 1 ..]);
    const source = try support.path(allocator, workspace, package ++ "_2_data.source");
    defer allocator.free(source);
    const output = try support.path(allocator, workspace, package ++ "_2_data.deb");
    defer allocator.free(output);
    const rebuilt = try fixture.buildPackage(source, output, .{});
    defer allocator.free(rebuilt);
    for (cases) |entry| {
        try runCase(&fixture, driver, reference.executable, reference.architecture, entry, first, rebuilt);
        std.debug.print("mutation {s}/{s}/{s}: {s}\n", .{
            entry.operation, entry.boundary, @tagName(entry.drift), if (entry.drift != .none) "refused" else "recovered",
        });
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
