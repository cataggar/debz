const std = @import("std");
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const metadata = @import("native_lifecycle_metadata.zig");
const process = @import("native_recovery_scriptless.zig");
const options = @import("native_test_options");

const namespace = "var/lib/debz/";
const Drift = enum { symbols_bytes, symbols_mode, symbols_missing, config_bytes, config_mode, config_owner, config_missing };
const Case = struct {
    operation: []const u8,
    boundary: []const u8,
    drift: ?Drift = null,
};
const cases = [_]Case{
    .{ .operation = "install", .boundary = "during_filesystem_publication" },
    .{ .operation = "upgrade", .boundary = "after_trigger_outcome" },
    .{ .operation = "remove", .boundary = "after_script_outcome" },
    .{ .operation = "purge", .boundary = "after_script_outcome" },
    .{ .operation = "install", .boundary = "after_trigger_outcome", .drift = .symbols_bytes },
    .{ .operation = "install", .boundary = "after_trigger_outcome", .drift = .symbols_mode },
    .{ .operation = "install", .boundary = "after_trigger_outcome", .drift = .symbols_missing },
    .{ .operation = "install", .boundary = "after_trigger_outcome", .drift = .config_bytes },
    .{ .operation = "install", .boundary = "after_trigger_outcome", .drift = .config_mode },
    .{ .operation = "install", .boundary = "after_trigger_outcome", .drift = .config_owner },
    .{ .operation = "install", .boundary = "after_trigger_outcome", .drift = .config_missing },
};

fn verifyOriginalBlobs(
    fixture: *foundation.Fixture,
    root: []const u8,
    proof: std.json.Value,
    workspace: []const u8,
) !void {
    const files = try process.field(proof, "evidence_files");
    if (files != .array) return error.InvalidRecoveryEvidence;
    var matched: [2]bool = .{ false, false };
    for (files.array.items) |entry| {
        if (!std.mem.eql(u8, try process.text(entry, "kind"), "intent")) continue;
        const path = try process.text(entry, "path");
        if (!std.mem.startsWith(u8, path, namespace ++ "native-receipts-v1/"))
            return error.UnboundRetainedIntent;
        var intent = try process.rootDocument(fixture, root, path);
        defer intent.deinit();
        const blobs = try process.field(intent.value, "blobs");
        if (blobs != .array) return error.InvalidRecoveryEvidence;
        for (blobs.array.items) |blob| {
            if (!std.mem.eql(u8, try process.text(blob, "kind"), "database")) continue;
            const logical = try process.text(blob, "logical_path");
            for ([_][]const u8{ "config", "symbols" }, 0..) |member, index| {
                const tail = try std.fmt.allocPrint(fixture.allocator, "{s}.{s}", .{ metadata.metadata, member });
                defer fixture.allocator.free(tail);
                if (!std.mem.endsWith(u8, logical, tail)) continue;
                const source = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_1_data.source/DEBIAN/{s}", .{
                    workspace, metadata.metadata, member,
                });
                defer fixture.allocator.free(source);
                const original = try support.read(fixture, source, 64 * 1024);
                defer fixture.allocator.free(original);
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(original, &digest, .{});
                try process.same(try process.text(blob, "sha256"), &std.fmt.bytesToHex(digest, .lower));
                const size = try process.field(blob, "size");
                if (size != .integer or size.integer != original.len or matched[index])
                    return error.IncorrectOriginalMetadataBlob;
                matched[index] = true;
            }
        }
    }
    if (!matched[0] or !matched[1]) return error.MissingOriginalMetadataBlob;
}

fn applyDrift(fixture: *foundation.Fixture, root: []const u8, drift: Drift) !void {
    const member: []const u8 = switch (drift) {
        .symbols_bytes, .symbols_mode, .symbols_missing => "symbols",
        else => "config",
    };
    const target = try std.fmt.allocPrint(fixture.allocator, "var/lib/dpkg/info/{s}.{s}", .{ metadata.metadata, member });
    defer fixture.allocator.free(target);
    const relative = try process.rootPath(fixture, root, target);
    defer fixture.allocator.free(relative);
    var dir = try foundation.guardedRoot(fixture.io, root);
    defer dir.close(fixture.io);
    const confined = root_fs.Root.init(fixture.io, dir);
    const path = try root_fs.Path.initPackage(target);
    const before = try confined.entry(path);
    if (before.kind != .file) return error.MissingInstalledMetadataMember;
    switch (drift) {
        .symbols_bytes, .config_bytes =>
            try support.fixtureFile(fixture, relative, "changed during interruption\n", before.mode),
        .symbols_mode => try confined.applyMetadata(path, .{ .mode = 0o640 }),
        .config_mode => try confined.applyMetadata(path, .{ .mode = 0o700 }),
        .config_owner => try confined.applyMetadata(path, .{ .uid = 1, .gid = 1 }),
        .symbols_missing, .config_missing => try fixture.dir.deleteFile(fixture.io, relative),
    }
}

fn runCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, entry: Case) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "metadata-{s}-{s}{s}", .{
        entry.operation, entry.boundary, if (entry.drift) |drift| switch (drift) {
            .symbols_bytes => "-bytes-drift",
            .symbols_mode => "-mode-drift",
            .symbols_missing => "-missing-drift",
            .config_bytes => "-config-bytes-drift",
            .config_mode => "-config-mode-drift",
            .config_owner => "-config-owner-drift",
            .config_missing => "-config-missing-drift",
        } else "",
    });
    defer fixture.allocator.free(name);
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    const workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(workspace);
    const first = try metadata.metadataArchiveAt(fixture, arch, "1", false, true, workspace);
    defer fixture.allocator.free(first);
    const second = try metadata.metadataArchiveAt(fixture, arch, "2", false, true, workspace);
    defer fixture.allocator.free(second);
    const receiver_workspace = try support.path(fixture.allocator, name, "receiver");
    defer fixture.allocator.free(receiver_workspace);
    const receiver = try support.makePackage(fixture, arch, "1", "metadata-receiver", receiver_workspace, .{
        .declarations = "interest-noawait /usr/share/" ++ metadata.metadata ++ "\n",
    });
    defer fixture.allocator.free(receiver);
    const helper_workspace = try support.path(fixture.allocator, name, "helper");
    defer fixture.allocator.free(helper_workspace);
    const helper_bytes = try process.rootBytes(fixture, case.reference_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_bytes);
    const helper = try support.makePackage(fixture, arch, "1", "metadata-helper-target", helper_workspace, .{
        .no_scripts = true,
        .extra_files = &.{.{ .path = "usr/bin/dpkg-trigger", .content = helper_bytes, .mode = 0o755 }},
    });
    defer fixture.allocator.free(helper);
    try case.seed(receiver);
    try case.seed(helper);
    if (!std.mem.eql(u8, entry.operation, "install")) try case.seed(first);
    const helper_path = try process.rootPath(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_path);
    const helper_inode = (try fixture.dir.statFile(fixture.io, helper_path, .{ .follow_symlinks = false })).inode;
    const helper_before = try process.rootBytes(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_before);
    const archive: []const []const u8 = if (std.mem.eql(u8, entry.operation, "install"))
        &.{first}
    else if (std.mem.eql(u8, entry.operation, "upgrade"))
        &.{second}
    else
        &.{};
    const selected = [_]foundation.PackageIdentity{.{ .name = metadata.metadata, .architecture = arch }};
    const packages: []const foundation.PackageIdentity = if (archive.len != 0) &.{} else &selected;
    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = entry.operation, .archives = archive, .packages = packages, .triggers = true,
    }, reference_log) != 0) return error.ReferenceMetadataOperationFailed;
    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = entry.operation, .archives = archive, .packages = packages, .crash_at = entry.boundary,
        .caller_owned = true, .isolated_helper = true, .core_product = true,
    })) |unexpected| {
        var invalid = unexpected;
        invalid.deinit();
        return error.MissingMetadataCrash;
    }
    for ([_][]const u8{ first, second }) |archive_path| {
        try fixture.dir.deleteFile(fixture.io, archive_path[fixture.path.len + 1 ..]);
        try support.absent(fixture, archive_path[fixture.path.len + 1 ..]);
    }
    if (entry.drift) |drift| try applyDrift(fixture, case.native_root, drift);
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var recovered = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover", .caller_owned = true, .isolated_helper = true, .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer recovered.deinit();
    const helper_after = try process.rootBytes(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_after);
    if ((try fixture.dir.statFile(fixture.io, helper_path, .{ .follow_symlinks = false })).inode != helper_inode or
        !std.mem.eql(u8, helper_before, helper_after)) return error.PackageOwnedHelperChanged;
    if (entry.drift != null) {
        if (!std.mem.eql(u8, recovered.value.outcome, "recovery_required") and
            !std.mem.eql(u8, recovered.value.outcome, "refused"))
            return error.MetadataDriftWasAccepted;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.BlockedMetadataRecoveryMutatedRoot;
        return;
    }
    try process.same(recovered.value.outcome, "applied");
    const comparison = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(comparison);
    try fixture.directory(comparison);
    try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
    const proof_path = recovered.value.provenance_path orelse return error.MissingRecoveryProof;
    var proof = try process.rootDocument(fixture, case.native_root, proof_path);
    defer proof.deinit();
    try process.same(try process.text(proof.value, "attempt_id"), recovered.value.attempt_id orelse return error.MissingRecoveryProof);
    try process.same(try process.text(proof.value, "program_sha256"), recovered.value.program_sha256 orelse return error.MissingRecoveryProof);
    try process.same(try process.text(proof.value, "install_root"), case.native_root);
    if (std.mem.eql(u8, entry.operation, "upgrade") or std.mem.eql(u8, entry.operation, "remove"))
        try verifyOriginalBlobs(fixture, case.native_root, proof.value, workspace);
    var completion = try process.rootDocument(fixture, case.native_root, namespace ++ "root-operation-completion-v1.json");
    defer completion.deinit();
    try process.same(try process.text(completion.value, "attempt_id"), try process.text(proof.value, "attempt_id"));
    try process.same(try process.text(try process.field(completion.value, "transaction_provenance"), "document_sha256"),
        try process.text(proof.value, "digest_sha256"));
    try process.rootAbsent(fixture, case.native_root, namespace ++ "root-operation-v1.json");
    try process.rootAbsent(fixture, case.native_root, namespace ++ "native-execution-intent-v1.json");
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
    if (!std.mem.eql(u8, settled, after)) return error.RepeatedMetadataRecoveryMutatedRoot;
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
        std.debug.print("host dpkg status changed after metadata failure: {s}\n", .{@errorName(err)});
    for (cases) |entry| {
        try runCase(&fixture, driver, reference.executable, reference.architecture, entry);
        std.debug.print("metadata {s}/{s}/drift={}: recovered or blocked\n", .{
            entry.operation, entry.boundary, entry.drift != null,
        });
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
