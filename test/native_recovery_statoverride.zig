const std = @import("std");
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const statoverride = @import("native_lifecycle_statoverride.zig");
const process = @import("native_recovery_scriptless.zig");
const options = @import("native_test_options");

const namespace = "var/lib/debz/";
const operation_path = namespace ++ "root-operation-v1.json";
const intent_path = namespace ++ "native-execution-intent-v1.json";
const completion_path = namespace ++ "root-operation-completion-v1.json";

const Replacement = enum { account, override, created };
const Drift = enum { passwd_blob, missing_group_blob, passwd, group, statoverride, owner };
const IdentityBlobs = struct { passwd: ?[]const u8 = null, group: ?[]const u8 = null };

const Case = struct {
    operation: []const u8,
    boundary: []const u8,
    replacement: ?Replacement = null,
    drift: ?Drift = null,
};

const cases = [_]Case{
    .{ .operation = "install", .boundary = "after_execution_intent" },
    .{ .operation = "install", .boundary = "during_filesystem_publication" },
    .{ .operation = "install", .boundary = "after_script_outcome" },
    .{ .operation = "install", .boundary = "after_failure_outcome" },
    .{ .operation = "upgrade", .boundary = "during_filesystem_publication" },
    .{ .operation = "upgrade", .boundary = "after_script_outcome" },
    .{ .operation = "remove", .boundary = "after_script_outcome" },
    .{ .operation = "purge", .boundary = "after_script_prepared" },
    .{ .operation = "install", .boundary = "after_script_outcome", .replacement = .account },
    .{ .operation = "install", .boundary = "after_script_outcome", .replacement = .override },
    .{ .operation = "install", .boundary = "after_script_outcome", .replacement = .created },
    .{ .operation = "install", .boundary = "after_execution_intent", .drift = .passwd_blob },
    .{ .operation = "install", .boundary = "after_execution_intent", .drift = .missing_group_blob },
    .{ .operation = "install", .boundary = "after_execution_intent", .drift = .passwd },
    .{ .operation = "install", .boundary = "during_filesystem_publication", .drift = .group },
    .{ .operation = "install", .boundary = "after_script_prepared", .drift = .statoverride },
    .{ .operation = "upgrade", .boundary = "after_trigger_outcome", .drift = .owner },
};

fn nameFor(fixture: *foundation.Fixture, entry: Case) ![]u8 {
    return std.fmt.allocPrint(fixture.allocator, "statoverride-{s}{s}-{s}{s}", .{
        entry.operation,
        if (entry.replacement) |replacement| switch (replacement) {
            .account => "-account",
            .override => "-override",
            .created => "-created",
        } else "",
        entry.boundary,
        if (entry.drift) |drift| switch (drift) {
            .passwd_blob => "-passwd-blob-drift",
            .missing_group_blob => "-group-blob-missing-drift",
            .passwd => "-passwd-drift",
            .group => "-group-drift",
            .statoverride => "-statoverride-drift",
            .owner => "-owner-drift",
        } else "",
    });
}

fn compareHelper(fixture: *foundation.Fixture, root: []const u8, before: []const u8, inode: u64) !void {
    const path = try process.rootPath(fixture, root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(path);
    const metadata = try fixture.dir.statFile(fixture.io, path, .{ .follow_symlinks = false });
    const after = try process.rootBytes(fixture, root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(after);
    if (metadata.inode != inode or !std.mem.eql(u8, before, after))
        return error.PackageOwnedHelperChanged;
}

fn checkIdentityBlobs(
    fixture: *foundation.Fixture,
    root: []const u8,
    value: std.json.Value,
    created: bool,
) !IdentityBlobs {
    const blobs = try process.field(value, "blobs");
    if (blobs != .array) return error.InvalidRecoveryIntent;
    var found: IdentityBlobs = .{};
    for (blobs.array.items) |blob| {
        const key = try process.text(blob, "key");
        if (!std.mem.startsWith(u8, key, "statoverride-")) continue;
        const expected_path, const expected_bytes = if (std.mem.eql(u8, key, "statoverride-passwd"))
            .{ "etc/passwd", statoverride.passwd }
        else if (std.mem.eql(u8, key, "statoverride-group"))
            .{ "etc/group", statoverride.group }
        else return error.UnexpectedStatoverrideIdentityBlob;
        try process.same(try process.text(blob, "kind"), "database");
        try process.same(try process.text(blob, "entry_kind"), "regular");
        try process.same(try process.text(blob, "logical_path"), expected_path);
        const bytes = try process.rootBytes(fixture, root, try process.text(blob, "storage_path"));
        defer fixture.allocator.free(bytes);
        if (!std.mem.eql(u8, bytes, expected_bytes)) return error.ChangedStatoverrideIdentityBlob;
        const stored_path = try process.text(blob, "storage_path");
        if (std.mem.eql(u8, key, "statoverride-passwd")) {
            if (found.passwd != null) return error.DuplicateStatoverrideIdentityBlob;
            found.passwd = stored_path;
        } else {
            if (found.group != null) return error.DuplicateStatoverrideIdentityBlob;
            found.group = stored_path;
        }
    }
    if (created != (found.passwd == null and found.group == null) or
        !created and (found.passwd == null or found.group == null))
        return error.MissingStatoverrideIdentityBlob;
    return found;
}

fn driftRoot(
    fixture: *foundation.Fixture,
    root: []const u8,
    drift: Drift,
    blobs: IdentityBlobs,
) !void {
    const alternate_passwd = "root:x:0:0:root:/root:/bin/sh\n_debzstat:x:42422:42421:fixture:/:/bin/sh\n";
    const alternate_group = "root:x:0:\n_debzstat:x:42423:\n";
    switch (drift) {
        .owner => {
            var dir = try foundation.guardedRoot(fixture.io, root);
            defer dir.close(fixture.io);
            try (root_fs.Root.init(fixture.io, dir)).applyMetadata(
                try root_fs.Path.initPackage(statoverride.base ++ "/mode"),
                .{ .uid = 42422, .gid = 42423 },
            );
        },
        .missing_group_blob => {
            const path = try process.rootPath(fixture, root, blobs.group orelse return error.MissingStatoverrideIdentityBlob);
            defer fixture.allocator.free(path);
            try fixture.dir.deleteFile(fixture.io, path);
        },
        else => {
            const path, const bytes = switch (drift) {
                .passwd_blob => .{ blobs.passwd orelse return error.MissingStatoverrideIdentityBlob, alternate_passwd },
                .passwd => .{ "etc/passwd", alternate_passwd },
                .group => .{ "etc/group", alternate_group },
                .statoverride => .{ "var/lib/dpkg/statoverride", "_debzstat _debzstat 0750 /" ++ statoverride.base ++ "/mode\n" ++
                    "#42420 #42421 0640 /" ++ statoverride.literal ++ "\n" ++
                    "_debzstat _debzstat 0640 /etc/debz-native.conf\n" },
                else => unreachable,
            };
            const relative = try process.rootPath(fixture, root, path);
            defer fixture.allocator.free(relative);
            try support.fixtureFile(fixture, relative, bytes, 0o644);
        },
    }
}

fn runCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, entry: Case) !void {
    const name = try nameFor(fixture, entry);
    defer fixture.allocator.free(name);
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    const records = "_debzstat _debzstat 4750 /" ++ statoverride.base ++ "/mode\n" ++
        "#42420 #42421 0640 /" ++ statoverride.literal ++ "\n" ++
        "_debzstat _debzstat 0640 /etc/debz-native.conf\n";
    try statoverride.seed(&case, if (entry.replacement == .created) "" else records);

    const receiver_workspace = try support.path(fixture.allocator, name, "receiver");
    defer fixture.allocator.free(receiver_workspace);
    const receiver_archive = try support.makePackage(fixture, arch, "1", "statoverride-receiver", receiver_workspace, .{
        .declarations = "interest-noawait /" ++ statoverride.base ++ "\n",
    });
    defer fixture.allocator.free(receiver_archive);
    const helper_workspace = try support.path(fixture.allocator, name, "helper");
    defer fixture.allocator.free(helper_workspace);
    const helper_bytes = try process.rootBytes(fixture, case.reference_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_bytes);
    const helper_archive = try support.makePackage(fixture, arch, "1", "statoverride-helper-target", helper_workspace, .{
        .no_scripts = true,
        .extra_files = &.{.{ .path = "usr/bin/dpkg-trigger", .content = helper_bytes, .mode = 0o755 }},
    });
    defer fixture.allocator.free(helper_archive);
    const package_workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(package_workspace);
    const first = try statoverride.archiveAt(fixture, arch, "1", package_workspace);
    defer fixture.allocator.free(first);
    const second = try statoverride.archiveAt(fixture, arch, "2", package_workspace);
    defer fixture.allocator.free(second);
    try case.seed(receiver_archive);
    try case.seed(helper_archive);
    if (!std.mem.eql(u8, entry.operation, "install")) try case.seed(first);
    if (entry.replacement) |replacement| {
        const alternate_passwd = "root:x:0:0:root:/root:/bin/sh\n_debzstat:x:42422:42421:fixture:/:/bin/sh\n";
        const alternate_override = "_debzstat _debzstat 0750 /" ++ statoverride.base ++ "/mode\n" ++
            "#42420 #42421 0640 /" ++ statoverride.literal ++ "\n" ++
            "_debzstat _debzstat 0640 /etc/debz-native.conf\n";
        try statoverride.replace(&case, if (replacement == .account) "statoverride-passwd-replace" else "statoverride-preinst-replace", switch (replacement) {
            .account => alternate_passwd,
            .override => alternate_override,
            .created => records,
        });
    }
    const selected = [_]foundation.PackageIdentity{.{ .name = statoverride.name, .architecture = arch }};
    if (std.mem.eql(u8, entry.operation, "purge"))
        try case.phase(.{ .operation = "remove", .packages = &selected, .triggers = true }, false);
    const failure = std.mem.eql(u8, entry.boundary, "after_failure_outcome");
    if (failure) try statoverride.both(&case, support.failure, statoverride.name ++ "@1:postinst:configure\n");
    const helper_before = try process.rootBytes(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_before);
    const helper_relative = try process.rootPath(fixture, case.native_root, "usr/bin/dpkg-trigger");
    defer fixture.allocator.free(helper_relative);
    const helper_inode = (try fixture.dir.statFile(fixture.io, helper_relative, .{ .follow_symlinks = false })).inode;

    const archive: []const []const u8 = if (std.mem.eql(u8, entry.operation, "install"))
        &.{first}
    else if (std.mem.eql(u8, entry.operation, "upgrade"))
        &.{second}
    else
        &.{};
    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    const reference_status = try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = entry.operation,
        .archives = archive,
        .packages = &selected,
        .triggers = true,
    }, reference_log);
    if (reference_status != (if (failure) @as(u8, 1) else @as(u8, 0)))
        return error.UnexpectedReferenceOutcome;
    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = entry.operation,
        .archives = archive,
        .packages = &selected,
        .crash_at = entry.boundary,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) |value| {
        var invalid = value;
        invalid.deinit();
        return error.MissingCrash;
    }
    var intent = try process.rootDocument(fixture, case.native_root, intent_path);
    defer intent.deinit();
    const blobs = try checkIdentityBlobs(fixture, case.native_root, intent.value, entry.replacement == .created);
    for ([_][]const u8{ first, second }) |path| {
        try fixture.dir.deleteFile(fixture.io, path[fixture.path.len + 1 ..]);
        try support.absent(fixture, path[fixture.path.len + 1 ..]);
    }
    if (entry.drift) |drift| try driftRoot(fixture, case.native_root, drift, blobs);
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var report = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover",
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer report.deinit();
    try compareHelper(fixture, case.native_root, helper_before, helper_inode);
    if (entry.drift != null) {
        if (!std.mem.eql(u8, report.value.outcome, "recovery_required") and
            !std.mem.eql(u8, report.value.outcome, "refused"))
            return error.StatoverrideDriftWasAccepted;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.BlockedRecoveryMutatedRoot;
        return;
    }
    try process.same(report.value.outcome, if (failure) "script_failed" else "applied");
    const comparison = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(comparison);
    try fixture.directory(comparison);
    try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
    const proof_path = try process.reportProvenancePath(report.value.provenance_path);
    var proof = try process.rootDocument(fixture, case.native_root, proof_path);
    defer proof.deinit();
    try process.same(try process.text(proof.value, "attempt_id"), report.value.attempt_id orelse return error.MissingRecoveryProof);
    try process.same(try process.text(proof.value, "program_sha256"), report.value.program_sha256 orelse return error.MissingRecoveryProof);
    try process.same(try process.text(proof.value, "install_root"), case.native_root);
    var completion = try process.rootDocument(fixture, case.native_root, completion_path);
    defer completion.deinit();
    try process.same(try process.text(completion.value, "outcome"), if (failure) "failed_after_mutation" else "succeeded");
    try process.same(try process.text(completion.value, "attempt_id"), try process.text(proof.value, "attempt_id"));
    try process.rootAbsent(fixture, case.native_root, operation_path);
    try process.rootAbsent(fixture, case.native_root, intent_path);
    const proof_before = try process.rootBytes(fixture, case.native_root, proof_path);
    defer fixture.allocator.free(proof_before);
    const completion_before = try process.rootBytes(fixture, case.native_root, completion_path);
    defer fixture.allocator.free(completion_before);
    const settled = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(settled);
    const repeat_log = try support.path(fixture.allocator, name, "recover-again");
    defer fixture.allocator.free(repeat_log);
    var repeated = (try process.invoke(fixture, driver, case.native_root, arch, repeat_log, .{
        .operation = "recover",
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer repeated.deinit();
    try process.same(repeated.value.outcome, "applied");
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, settled, after)) return error.RepeatedRecoveryMutatedRoot;
    const proof_after = try process.rootBytes(fixture, case.native_root, proof_path);
    defer fixture.allocator.free(proof_after);
    const completion_after = try process.rootBytes(fixture, case.native_root, completion_path);
    defer fixture.allocator.free(completion_after);
    if (!std.mem.eql(u8, proof_before, proof_after) or !std.mem.eql(u8, completion_before, completion_after))
        return error.RepeatedRecoveryReplacedReceipt;
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
        std.debug.print("host dpkg status changed after statoverride failure: {s}\n", .{@errorName(err)});
    for (cases) |entry| {
        try runCase(&fixture, driver, reference.executable, reference.architecture, entry);
        std.debug.print("statoverride {s}/{s}: recovered or blocked\n", .{ entry.operation, entry.boundary });
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
