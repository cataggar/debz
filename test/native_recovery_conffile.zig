const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const conffile = @import("native_lifecycle_conffile_scripts.zig");
const process = @import("native_recovery_scriptless.zig");
const options = @import("native_test_options");

const namespace = "var/lib/debz/";
const Case = struct {
    label: []const u8,
    operation: []const u8,
    boundary: []const u8,
    failure: bool = false,
    drift: bool = false,
    upgrading: bool = false,
    deferred: bool = false,
    activate_helper: bool = false,
};
const cases = [_]Case{
    .{ .label = "purge", .operation = "purge", .boundary = "after_execution_intent" },
    .{ .label = "purge", .operation = "purge", .boundary = "during_database_publication" },
    .{ .label = "purge", .operation = "purge", .boundary = "after_script_prepared" },
    .{ .label = "purge", .operation = "purge", .boundary = "after_script_outcome" },
    .{ .label = "purge", .operation = "purge", .boundary = "after_failure_outcome", .failure = true },
    .{ .label = "purge", .operation = "purge", .boundary = "after_trigger_outcome", .failure = true },
    .{ .label = "purge-deferred", .operation = "purge", .boundary = "after_failure_outcome", .failure = true, .deferred = true },
    .{ .label = "purge-helper", .operation = "purge", .boundary = "after_failure_outcome", .failure = true, .activate_helper = true },
    .{ .label = "purge-helper", .operation = "purge", .boundary = "after_trigger_outcome", .failure = true, .activate_helper = true },
    .{ .label = "purge-helper-deferred", .operation = "purge", .boundary = "after_failure_outcome", .failure = true, .deferred = true, .activate_helper = true },
    .{ .label = "purge", .operation = "purge", .boundary = "after_script_return_before_outcome" },
    .{ .label = "purge", .operation = "purge", .boundary = "after_script_prepared", .drift = true },
    .{ .label = "configure", .operation = "configure", .boundary = "after_script_prepared" },
    .{ .label = "configure", .operation = "configure", .boundary = "during_database_publication" },
    .{ .label = "configure", .operation = "configure", .boundary = "during_database_publication", .drift = true },
    .{ .label = "configure", .operation = "configure", .boundary = "after_script_outcome" },
    .{ .label = "configure", .operation = "configure", .boundary = "after_script_prepared", .drift = true },
    .{ .label = "configure-upgrade", .operation = "configure", .boundary = "after_script_prepared", .upgrading = true },
    .{ .label = "configure-upgrade", .operation = "configure", .boundary = "after_script_outcome", .upgrading = true },
    .{ .label = "configure-upgrade", .operation = "configure", .boundary = "during_database_publication", .upgrading = true },
};

fn helperUnchanged(fixture: *foundation.Fixture, root: []const u8, original: []const u8, inode: u64) !void {
    const path = try process.rootPath(fixture, root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(path);
    const after = try process.rootBytes(fixture, root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(after);
    if ((try fixture.dir.statFile(fixture.io, path, .{ .follow_symlinks = false })).inode != inode or
        !std.mem.eql(u8, original, after))
        return error.PackageOwnedHelperChanged;
}

fn runCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, entry: Case) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "conffile-{s}-{s}{s}{s}", .{
        entry.label, entry.boundary, if (entry.failure) "-failure" else "", if (entry.drift) "-drift" else "",
    });
    defer fixture.allocator.free(name);
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    const workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(workspace);
    const first = try conffile.archiveAt(fixture, arch, "1", false, workspace);
    defer fixture.allocator.free(first);
    const second = try conffile.archiveAt(fixture, arch, "2", false, workspace);
    defer fixture.allocator.free(second);
    const receiver_workspace = try support.path(fixture.allocator, name, "receiver");
    defer fixture.allocator.free(receiver_workspace);
    const receiver = try support.makePackage(fixture, arch, "1", "conffile-receiver", receiver_workspace, .{
        .declarations = "interest-noawait /" ++ conffile.paths[0] ++ "\n" ++
            "interest-noawait " ++ conffile.trigger ++ "\n",
    });
    defer fixture.allocator.free(receiver);
    const helper_workspace = try support.path(fixture.allocator, name, "helper");
    defer fixture.allocator.free(helper_workspace);
    const helper_bytes = try process.rootBytes(fixture, case.reference_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_bytes);
    const helper = try support.makePackage(fixture, arch, "1", "conffile-helper-target", helper_workspace, .{
        .no_scripts = true,
        .extra_files = &.{.{ .path = "usr/bin/dpkg-trigger", .content = helper_bytes, .mode = 0o755 }},
    });
    defer fixture.allocator.free(helper);
    try case.seed(receiver);
    try case.seed(helper);
    const selected = [_]foundation.PackageIdentity{.{ .name = conffile.name, .architecture = arch }};
    const version: []const u8 = if (entry.upgrading) "2" else "1";
    if (std.mem.eql(u8, entry.operation, "purge") or entry.upgrading) try case.seed(first);
    if (std.mem.eql(u8, entry.operation, "purge")) {
        try case.phase(.{ .operation = "remove", .packages = &selected, .triggers = true }, false);
    } else {
        try conffile.markers(&case, true, version);
        try case.phase(.{
            .operation = if (entry.upgrading) "upgrade" else "install",
            .archives = if (entry.upgrading) &.{second} else &.{first},
            .packages = &selected,
            .triggers = true,
        }, true);
        try conffile.markers(&case, false, "");
        for (conffile.paths) |path|
            try conffile.editBoth(&case, path, "administrator configuration after failure\n");
    }
    if (entry.failure) {
        try conffile.markers(&case, true, "purge");
        if (entry.activate_helper) try conffile.editBoth(&case, "conffile-activate", "");
    }
    const helper_path = try process.rootPath(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_path);
    const helper_inode = (try fixture.dir.statFile(fixture.io, helper_path, .{ .follow_symlinks = false })).inode;
    const helper_before = try process.rootBytes(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_before);
    const archives: []const []const u8 = if (std.mem.eql(u8, entry.operation, "configure"))
        (if (entry.upgrading) &.{second} else &.{first})
    else
        &.{};
    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    const reference_status = try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = entry.operation,
        .archives = archives,
        .packages = &selected,
        .triggers = true,
        .defer_triggers = entry.deferred,
    }, reference_log);
    if (reference_status != (if (entry.failure) @as(u8, 1) else @as(u8, 0)))
        return error.UnexpectedReferenceConffileOutcome;
    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = entry.operation,
        .archives = archives,
        .packages = &selected,
        .crash_at = entry.boundary,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
        .defer_triggers = entry.deferred,
    })) |unexpected| {
        var invalid = unexpected;
        invalid.deinit();
        return error.MissingConffileCrash;
    }
    if (std.mem.eql(u8, entry.operation, "purge") and
        std.mem.eql(u8, entry.boundary, "during_database_publication"))
    {
        var absent: usize = 0;
        for (conffile.paths) |path| {
            const candidate = try process.rootPath(fixture, case.native_root, path);
            defer fixture.allocator.free(candidate);
            if (fixture.dir.statFile(fixture.io, candidate, .{ .follow_symlinks = false })) |_|
                continue
            else |err| {
                if (err != error.FileNotFound) return err;
                absent += 1;
            }
        }
        if (absent == 0) return error.PurgeDidNotPublishConffileRemovals;
    }
    for ([_][]const u8{ first, second }) |archive| {
        try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
        try support.absent(fixture, archive[fixture.path.len + 1 ..]);
    }
    if (entry.drift) {
        const target = try process.rootPath(fixture, case.native_root, conffile.paths[0]);
        defer fixture.allocator.free(target);
        try support.fixtureFile(fixture, target, "changed during interruption\n", 0o644);
    }
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var recovered = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover", .caller_owned = true, .isolated_helper = true, .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer recovered.deinit();
    try helperUnchanged(fixture, case.native_root, helper_before, helper_inode);
    const unknown = std.mem.eql(u8, entry.boundary, "after_script_return_before_outcome");
    if (entry.drift or unknown) {
        if (!std.mem.eql(u8, recovered.value.outcome, "recovery_required") and
            !std.mem.eql(u8, recovered.value.outcome, "refused"))
            return error.ConffileDriftOrUnknownWasAccepted;
        if (unknown) try process.same(recovered.value.detail, "native recovery_required: script_outcome_unknown");
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.BlockedConffileRecoveryMutatedRoot;
        if (unknown) {
            const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);
            var proof = try process.rootDocument(fixture, case.native_root, proof_path);
            defer proof.deinit();
            try process.same(try process.text(proof.value, "attempt_id"),
                recovered.value.attempt_id orelse return error.MissingRecoveryProof);
        }
        return;
    }
    try process.same(recovered.value.outcome, if (entry.failure) "script_failed" else "applied");
    const comparison = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(comparison);
    try fixture.directory(comparison);
    try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
    const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);
    var proof = try process.rootDocument(fixture, case.native_root, proof_path);
    defer proof.deinit();
    try process.same(try process.text(proof.value, "outcome"), if (entry.failure) "failed" else "succeeded");
    try process.same(try process.text(proof.value, "attempt_id"), recovered.value.attempt_id orelse return error.MissingRecoveryProof);
    try process.same(try process.text(proof.value, "program_sha256"), recovered.value.program_sha256 orelse return error.MissingRecoveryProof);
    var completion = try process.rootDocument(fixture, case.native_root, namespace ++ "root-operation-completion-v1.json");
    defer completion.deinit();
    try process.same(try process.text(completion.value, "outcome"),
        if (entry.failure) "failed_after_mutation" else "succeeded");
    try process.same(try process.text(completion.value, "attempt_id"), try process.text(proof.value, "attempt_id"));
    try process.same(try process.text(try process.field(completion.value, "transaction_provenance"), "document_sha256"),
        try process.text(proof.value, "digest_sha256"));
    try process.rootAbsent(fixture, case.native_root, namespace ++ "root-operation-v1.json");
    try process.rootAbsent(fixture, case.native_root, namespace ++ "native-execution-intent-v1.json");
    const proof_before = try process.rootBytes(fixture, case.native_root, proof_path);
    defer fixture.allocator.free(proof_before);
    const completion_before = try process.rootBytes(fixture, case.native_root, namespace ++ "root-operation-completion-v1.json");
    defer fixture.allocator.free(completion_before);
    const settled = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(settled);
    const repeat_log = try support.path(fixture.allocator, name, "recover-again");
    defer fixture.allocator.free(repeat_log);
    var repeated = (try process.invoke(fixture, driver, case.native_root, arch, repeat_log, .{
        .operation = "recover", .caller_owned = true, .isolated_helper = true, .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer repeated.deinit();
    try process.same(repeated.value.outcome, "applied");
    try process.same(repeated.value.detail, "no native execution requires recovery");
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, settled, after)) return error.RepeatedConffileRecoveryMutatedRoot;
    const proof_after = try process.rootBytes(fixture, case.native_root, proof_path);
    defer fixture.allocator.free(proof_after);
    const completion_after = try process.rootBytes(fixture, case.native_root, namespace ++ "root-operation-completion-v1.json");
    defer fixture.allocator.free(completion_after);
    if (!std.mem.eql(u8, proof_before, proof_after) or !std.mem.eql(u8, completion_before, completion_after))
        return error.RepeatedConffileRecoveryReplacedReceipt;
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
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed after conffile failure: {s}\n", .{@errorName(err)});
    for (cases) |entry| {
        try runCase(&fixture, driver, reference.executable, reference.architecture, entry);
        std.debug.print("conffile {s}/{s}/failure={}/drift={}: recovered or blocked\n", .{
            entry.label, entry.boundary, entry.failure, entry.drift,
        });
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
