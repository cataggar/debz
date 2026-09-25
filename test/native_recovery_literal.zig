const std = @import("std");
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const metadata = @import("native_lifecycle_metadata.zig");
const process = @import("native_recovery_scriptless.zig");
const options = @import("native_test_options");

const namespace = "var/lib/debz/";
const trigger = "/usr/share/literal\\directory";
const cases = [_]struct {
    version: []const u8,
    boundary: []const u8,
    drift: ?enum { conffile, staged_script } = null,
}{
    .{ .version = "1", .boundary = "during_filesystem_publication" },
    .{ .version = "1", .boundary = "after_trigger_outcome" },
    .{ .version = "2", .boundary = "after_trigger_outcome" },
    .{ .version = "1", .boundary = "after_trigger_outcome", .drift = .conffile },
    .{ .version = "2", .boundary = "after_trigger_outcome", .drift = .staged_script },
};

fn checkRetained(fixture: *foundation.Fixture, root: []const u8, proof: std.json.Value) !void {
    const files = try process.field(proof, "evidence_files");
    if (files != .array) return error.InvalidRetainedEvidence;
    var trigger_authorized = false;
    var literal_path_retained = false;
    for (files.array.items) |entry| {
        const kind = try process.text(entry, "kind");
        if (!std.mem.eql(u8, kind, "authorization") and !std.mem.eql(u8, kind, "managed_state"))
            continue;
        const path = try process.text(entry, "path");
        if (!std.mem.startsWith(u8, path, namespace ++ "native-receipts-v1/"))
            return error.UnboundRetainedEvidence;
        var retained = try process.rootDocument(fixture, root, path);
        defer retained.deinit();
        if (std.mem.eql(u8, kind, "authorization")) {
            const authority = try process.field(retained.value, "trigger_authority");
            const allowed = try process.field(authority, "allowed_triggers");
            if (allowed != .array) return error.InvalidRetainedEvidence;
            for (allowed.array.items) |item| {
                if (item != .string) return error.InvalidRetainedEvidence;
                if (std.mem.eql(u8, item.string, trigger)) trigger_authorized = true;
            }
        } else {
            for ([_][]const u8{ "stable", "transient" }) |side| {
                const state = try process.field(retained.value, side);
                if (state == .null) continue;
                const entries = try process.field(state, "entries");
                if (entries != .array) return error.InvalidRetainedEvidence;
                for (entries.array.items) |member| {
                    if (std.mem.indexOfScalar(u8, try process.text(member, "path"), '\\') != null)
                        literal_path_retained = true;
                }
            }
        }
    }
    if (!trigger_authorized or !literal_path_retained) return error.MissingLiteralPathRecoveryEvidence;
}

fn caseRun(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, entry: @TypeOf(cases[0])) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "literal-paths-v{s}-{s}{s}", .{
        entry.version, entry.boundary, if (entry.drift) |drift| switch (drift) {
            .conffile => "-conffile-drift",
            .staged_script => "-staged-script-drift",
        } else "",
    });
    defer fixture.allocator.free(name);
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    const package_workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(package_workspace);
    const first = try metadata.literalArchiveAt(fixture, arch, "1", package_workspace);
    defer fixture.allocator.free(first);
    const second = try metadata.literalArchiveAt(fixture, arch, "2", package_workspace);
    defer fixture.allocator.free(second);
    const receiver_workspace = try support.path(fixture.allocator, name, "receiver");
    defer fixture.allocator.free(receiver_workspace);
    const receiver = try support.makePackage(fixture, arch, "1", "literal-receiver", receiver_workspace, .{
        .declarations = "interest-noawait " ++ trigger ++ "\n",
    });
    defer fixture.allocator.free(receiver);
    const helper_workspace = try support.path(fixture.allocator, name, "helper");
    defer fixture.allocator.free(helper_workspace);
    const helper_bytes = try process.rootBytes(fixture, case.reference_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_bytes);
    const helper = try support.makePackage(fixture, arch, "1", "literal-helper-target", helper_workspace, .{
        .no_scripts = true,
        .extra_files = &.{.{ .path = "usr/bin/dpkg-trigger", .content = helper_bytes, .mode = 0o755 }},
    });
    defer fixture.allocator.free(helper);
    try case.seed(receiver);
    try case.seed(helper);
    const upgrading = std.mem.eql(u8, entry.version, "2");
    if (upgrading) {
        try case.seed(first);
        for ([_][]const u8{ case.reference_root, case.native_root }) |root| {
            const path = try process.rootPath(fixture, root, metadata.literal_conf);
            defer fixture.allocator.free(path);
            try support.fixtureFile(fixture, path, "locally edited literal conffile\n", 0o644);
            var dir = try foundation.guardedRoot(fixture.io, root);
            defer dir.close(fixture.io);
            try (root_fs.Root.init(fixture.io, dir)).applyMetadata(
                try root_fs.Path.initPackage(metadata.literal_conf),
                .{ .modified_nanoseconds = 946_684_800 * std.time.ns_per_s },
            );
        }
    }
    const helper_path = try process.rootPath(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_path);
    const helper_inode = (try fixture.dir.statFile(fixture.io, helper_path, .{ .follow_symlinks = false })).inode;
    const before_helper = try process.rootBytes(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(before_helper);
    const archive = if (upgrading) second else first;
    const operation = if (upgrading) "upgrade" else "install";
    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = operation, .archives = &.{archive}, .triggers = true,
    }, reference_log) != 0) return error.ReferenceLiteralOperationFailed;
    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = operation, .archives = &.{archive}, .crash_at = entry.boundary,
        .caller_owned = true, .isolated_helper = true, .core_product = true,
    })) |unexpected| {
        var report = unexpected;
        report.deinit();
        return error.MissingLiteralCrash;
    }
    try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
    try support.absent(fixture, archive[fixture.path.len + 1 ..]);
    if (entry.drift) |drift| {
        const path = try process.rootPath(fixture, case.native_root, switch (drift) {
            .conffile => metadata.literal_conf,
            .staged_script => try std.fmt.allocPrint(fixture.allocator, "var/lib/debz-lifecycle-scripts/{s}:{s}.prerm", .{ metadata.literal, arch }),
        });
        defer fixture.allocator.free(path);
        const original = try support.read(fixture, path, 64 * 1024);
        defer fixture.allocator.free(original);
        try support.fixtureFile(fixture, path, "changed after interruption\n", 0o644);
    }
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var recovered = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover", .caller_owned = true, .isolated_helper = true, .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer recovered.deinit();
    const after_helper = try process.rootBytes(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(after_helper);
    const after_inode = (try fixture.dir.statFile(fixture.io, helper_path, .{ .follow_symlinks = false })).inode;
    if (after_inode != helper_inode or !std.mem.eql(u8, before_helper, after_helper))
        return error.PackageOwnedHelperChanged;
    if (entry.drift != null) {
        if (!std.mem.eql(u8, recovered.value.outcome, "recovery_required") and
            !std.mem.eql(u8, recovered.value.outcome, "refused"))
            return error.LiteralDriftWasAccepted;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.BlockedLiteralRecoveryMutatedRoot;
        return;
    }
    try process.same(recovered.value.outcome, "applied");
    const comparison = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(comparison);
    try fixture.directory(comparison);
    try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
    const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);
    var proof = try process.rootDocument(fixture, case.native_root, proof_path);
    defer proof.deinit();
    try process.same(try process.text(proof.value, "attempt_id"), recovered.value.attempt_id orelse return error.MissingRecoveryProof);
    try process.same(try process.text(proof.value, "program_sha256"), recovered.value.program_sha256 orelse return error.MissingRecoveryProof);
    try process.same(try process.text(proof.value, "install_root"), case.native_root);
    try checkRetained(fixture, case.native_root, proof.value);
    var completion = try process.rootDocument(fixture, case.native_root, namespace ++ "root-operation-completion-v1.json");
    defer completion.deinit();
    try process.same(try process.text(completion.value, "attempt_id"), try process.text(proof.value, "attempt_id"));
    try process.same(try process.text(try process.field(completion.value, "transaction_provenance"), "document_sha256"),
        try process.text(proof.value, "digest_sha256"));
    try process.rootAbsent(fixture, case.native_root, namespace ++ "root-operation-v1.json");
    try process.rootAbsent(fixture, case.native_root, namespace ++ "native-execution-intent-v1.json");
    const proof_before = try process.rootBytes(fixture, case.native_root, proof_path);
    defer fixture.allocator.free(proof_before);
    const settled = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(settled);
    const repeat_log = try support.path(fixture.allocator, name, "recover-again");
    defer fixture.allocator.free(repeat_log);
    var repeated = (try process.invoke(fixture, driver, case.native_root, arch, repeat_log, .{
        .operation = "recover", .caller_owned = true, .isolated_helper = true, .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer repeated.deinit();
    try process.same(repeated.value.outcome, "applied");
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, settled, after)) return error.RepeatedLiteralRecoveryMutatedRoot;
    const proof_after = try process.rootBytes(fixture, case.native_root, proof_path);
    defer fixture.allocator.free(proof_after);
    if (!std.mem.eql(u8, proof_before, proof_after)) return error.RepeatedLiteralRecoveryReplacedProof;
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
        std.debug.print("host dpkg status changed after literal-path failure: {s}\n", .{@errorName(err)});
    for (cases) |entry| {
        try caseRun(&fixture, driver, reference.executable, reference.architecture, entry);
        std.debug.print("literal paths v{s}/{s}/drift={}: recovered or blocked\n", .{
            entry.version, entry.boundary, entry.drift != null,
        });
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
