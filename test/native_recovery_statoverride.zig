const std = @import("std");
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const statoverride = @import("native_lifecycle_statoverride.zig");
const process = @import("native_recovery_scriptless.zig");
const options = @import("native_test_options");
const debz = @import("debz");

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

const refresh_provider = "statoverride-refresh-provider";
const refresh_consumer = "statoverride-refresh-consumer";
const refresh_target = "usr/share/statoverride-refresh-consumer/mode";

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
        else
            return error.UnexpectedStatoverrideIdentityBlob;
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

fn installDpkgStatoverride(case: *support.Scenario, dpkg: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const root_path = try support.path(case.fixture.allocator, case.name, side);
        defer case.fixture.allocator.free(root_path);
        try support.copyReferenceTool(case.fixture, root_path, dpkg, "dpkg-statoverride", "/usr/bin/dpkg-statoverride");
    }
}

fn expectRefreshMetadata(fixture: *foundation.Fixture, root_path: []const u8) !void {
    var dir = try foundation.guardedRoot(fixture.io, root_path);
    defer dir.close(fixture.io);
    const entry = try (root_fs.Root.init(fixture.io, dir)).entry(try root_fs.Path.initPackage(refresh_target));
    if (entry.mode != 0o4750 or entry.uid != 42420 or entry.gid != 42421)
        return error.WrongRecoveredStatoverrideMetadata;
}

fn makeRefreshPackages(
    fixture: *foundation.Fixture,
    arch: []const u8,
    workspace: []const u8,
) !struct { provider: []u8, consumer: []u8 } {
    const provider_script = try std.fmt.allocPrint(fixture.allocator,
        \\if [ "$1" = configure ]; then
        \\    /usr/bin/dpkg-statoverride --update --add _debzstat _debzstat 4750 /{s} || exit 31
        \\fi
        \\
    , .{refresh_target});
    defer fixture.allocator.free(provider_script);
    const provider_workspace = try support.path(fixture.allocator, workspace, "provider");
    defer fixture.allocator.free(provider_workspace);
    const provider_archive = try support.makePackage(fixture, arch, "1", refresh_provider, provider_workspace, .{
        .scripts = .{ .only_postinst = true },
        .postinst_append = provider_script,
    });
    errdefer fixture.allocator.free(provider_archive);
    const consumer_workspace = try support.path(fixture.allocator, workspace, "consumer");
    defer fixture.allocator.free(consumer_workspace);
    const consumer_archive = try support.makePackage(fixture, arch, "1", refresh_consumer, consumer_workspace, .{
        .control_fields = "Pre-Depends: " ++ refresh_provider ++ " (= 1)\n",
        .no_scripts = true,
        .extra_files = &.{.{ .path = refresh_target, .content = "permission-sensitive payload\n" }},
    });
    errdefer fixture.allocator.free(consumer_archive);
    return .{ .provider = provider_archive, .consumer = consumer_archive };
}

fn refreshActions(arch: []const u8) [4]support.Action {
    return .{
        .{ .sequence = 0, .kind = "unpack", .package = refresh_provider, .architecture = arch },
        .{ .sequence = 1, .kind = "configure_pending", .package = refresh_consumer, .architecture = arch },
        .{ .sequence = 2, .kind = "unpack", .package = refresh_consumer, .architecture = arch },
        .{ .sequence = 3, .kind = "configure_pending", .package = refresh_consumer, .architecture = arch },
    };
}

fn runRefreshCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, tamper: bool) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "statoverride-refresh-recovery{s}", .{
        if (tamper) "-tamper" else "",
    });
    defer fixture.allocator.free(name);
    const package_workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(package_workspace);
    const archives = try makeRefreshPackages(fixture, arch, package_workspace);
    defer fixture.allocator.free(archives.provider);
    defer fixture.allocator.free(archives.consumer);
    const archive_list = [_][]const u8{ archives.provider, archives.consumer };
    const selected = [_]foundation.PackageIdentity{
        .{ .name = refresh_provider, .architecture = arch },
        .{ .name = refresh_consumer, .architecture = arch },
    };
    const actions = refreshActions(arch);
    const groups = [_][]const []const u8{ &.{archives.provider}, &.{archives.consumer} };

    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    try statoverride.seed(&case, "");
    try installDpkgStatoverride(&case, dpkg);

    if (!tamper) {
        const control_name = try std.fmt.allocPrint(fixture.allocator, "{s}-uncrashed", .{name});
        defer fixture.allocator.free(control_name);
        var control = try support.Scenario.init(fixture, control_name, driver, dpkg, arch, true);
        defer control.deinit();
        try statoverride.seed(&control, "");
        try installDpkgStatoverride(&control, dpkg);
        try control.phase(.{
            .operation = "install",
            .archives = &archive_list,
            .reference_groups = &groups,
            .packages = &selected,
            .ordered_actions = &actions,
            .triggers = false,
        }, false);
        try expectRefreshMetadata(fixture, control.native_root);
    }

    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    for (groups, 0..) |group, index| {
        const group_log = try std.fmt.allocPrint(fixture.allocator, "{s}/group-{d}", .{ reference_log, index });
        defer fixture.allocator.free(group_log);
        try fixture.directory(group_log);
        const reference_status = try support.reference(fixture, dpkg, case.reference_root, .{
            .operation = "install",
            .archives = group,
            .packages = &selected,
            .triggers = false,
        }, group_log);
        if (reference_status != 0) return error.UnexpectedReferenceOutcome;
    }

    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = "install",
        .archives = &archive_list,
        .packages = &selected,
        .ordered_actions = &actions,
        .crash_at = "after_script_outcome",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) |value| {
        var invalid = value;
        invalid.deinit();
        return error.MissingCrash;
    }
    for (archive_list) |path| {
        try fixture.dir.deleteFile(fixture.io, path[fixture.path.len + 1 ..]);
        try support.absent(fixture, path[fixture.path.len + 1 ..]);
    }
    if (tamper) {
        const path = try process.rootPath(fixture, case.native_root, "var/lib/dpkg/statoverride");
        defer fixture.allocator.free(path);
        try support.fixtureFile(fixture, path, "#42422 #42423 0640 /" ++ refresh_target ++ "\n", 0o644);
    }
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var report = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer report.deinit();
    if (tamper) {
        if (!std.mem.eql(u8, report.value.outcome, "recovery_required") or
            std.mem.indexOf(u8, report.value.detail, "managed_state_changed") == null)
            return error.StatoverrideRefreshTamperAccepted;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.BlockedRecoveryMutatedRoot;
        return;
    }
    try process.same(report.value.outcome, "applied");
    const comparison = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(comparison);
    try fixture.directory(comparison);
    try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
    try expectRefreshMetadata(fixture, case.native_root);
    try support.assertDatabaseBytes(&case, "statoverride");
    try support.assertDatabaseBytes(&case, "statoverride-old");
}

/// Crash boundaries of the unpack invocation whose old prerm edits the
/// statoverride database (`statoverride.edit_marker`). `prerm_outcome` uses
/// a scriptless provider so its first script outcome is that prerm;
/// `intent_prerm_outcome` is the single invocation the intent froze.
const InvocationCase = enum {
    capture_recover,
    capture_tampered,
    capture_deleted,
    capture_database_drift,
    provider_outcome,
    prerm_outcome,
    intent_prerm_outcome,
};

fn expectUnpackStatOverrideInput(
    fixture: *foundation.Fixture,
    root_path: []const u8,
    expected: []const struct { path: []const u8, mode: i64, uid: i64, gid: i64 },
) ![]u8 {
    const path = (try statoverride.unpackStatOverrideInput(fixture, root_path)) orelse
        return error.MissingUnpackStatOverrideInput;
    errdefer fixture.allocator.free(path);
    var document = try process.rootDocument(fixture, root_path, path);
    defer document.deinit();
    const step = try process.field(document.value, "program_step");
    if (step != .integer) return error.WrongUnpackStatOverrideInput;
    var name_buffer: [128]u8 = undefined;
    if (!std.mem.eql(u8, path, try debz.native_recovery.unpackStatOverridePath(@intCast(step.integer), &name_buffer)))
        return error.WrongUnpackStatOverrideInput;
    const entries = try process.field(document.value, "entries");
    if (entries != .array or entries.array.items.len != expected.len) return error.WrongUnpackStatOverrideInput;
    for (entries.array.items, expected) |item, want| {
        try process.same(try process.text(item, "path"), want.path);
        for ([_][]const u8{ "mode", "uid", "gid" }, [_]i64{ want.mode, want.uid, want.gid }) |key, value| {
            const actual = try process.field(item, key);
            if (actual != .integer or actual.integer != value) return error.WrongUnpackStatOverrideInput;
        }
    }
    var dir = try foundation.guardedRoot(fixture.io, root_path);
    defer dir.close(fixture.io);
    const entry = try (root_fs.Root.init(fixture.io, dir)).entry(try root_fs.Path.init(path));
    if (entry.kind != .file or entry.mode != 0o600 or entry.uid != 0 or entry.gid != 0)
        return error.WrongUnpackStatOverrideInput;
    return path;
}

/// dpkg resolves statoverrides once per invocation, so a crash inside the
/// second invocation must replay its persisted input instead of re-reading
/// the database that the old prerm edited before the unpack.
fn runInvocationCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, kind: InvocationCase) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "statoverride-invocation-{s}", .{@tagName(kind)});
    defer fixture.allocator.free(name);
    const package_workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(package_workspace);
    const single = kind == .intent_prerm_outcome;
    const archives = try statoverride.invocationArchives(fixture, arch, package_workspace, kind != .prerm_outcome);
    defer for (archives) |bytes| fixture.allocator.free(bytes);
    const both_selected = [_]foundation.PackageIdentity{
        .{ .name = statoverride.invocation_provider, .architecture = arch },
        .{ .name = statoverride.name, .architecture = arch },
    };
    const selected: []const foundation.PackageIdentity = if (single) both_selected[1..] else &both_selected;
    const actions = statoverride.invocationActions(arch);
    const provider_group = [_][]const u8{archives[1]};
    const lifecycle_group = [_][]const u8{archives[3]};
    const both_groups = [_][]const []const u8{ &provider_group, &lifecycle_group };
    const groups: []const []const []const u8 = if (single) both_groups[1..] else &both_groups;
    const both_archives = [_][]const u8{ archives[1], archives[3] };
    const native_archives: []const []const u8 = if (single) &lifecycle_group else &both_archives;

    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    try statoverride.seed(&case, "");
    try installDpkgStatoverride(&case, dpkg);
    try statoverride.replace(&case, statoverride.edit_marker, "prerm:upgrade --update --update\n");
    if (!single) try case.seed(archives[0]);
    try case.seed(archives[2]);

    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    for (groups, 0..) |group, index| {
        const group_log = try std.fmt.allocPrint(fixture.allocator, "{s}/group-{d}", .{ reference_log, index });
        defer fixture.allocator.free(group_log);
        try fixture.directory(group_log);
        if (try support.reference(fixture, dpkg, case.reference_root, .{
            .operation = "upgrade",
            .archives = group,
            .packages = selected,
            .triggers = false,
        }, group_log) != 0) return error.UnexpectedReferenceOutcome;
    }

    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = "upgrade",
        .archives = native_archives,
        .packages = selected,
        .ordered_actions = if (single) null else &actions,
        .crash_at = switch (kind) {
            .capture_recover, .capture_tampered, .capture_deleted, .capture_database_drift => "after_unpack_statoverride_capture",
            .provider_outcome, .prerm_outcome, .intent_prerm_outcome => "after_script_outcome",
        },
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) |value| {
        var invalid = value;
        invalid.deinit();
        return error.MissingCrash;
    }
    for (archives) |path| {
        try fixture.dir.deleteFile(fixture.io, path[fixture.path.len + 1 ..]);
        try support.absent(fixture, path[fixture.path.len + 1 ..]);
    }
    switch (kind) {
        .capture_recover, .capture_tampered, .capture_deleted, .capture_database_drift => {
            const input = try expectUnpackStatOverrideInput(fixture, case.native_root, &.{
                .{ .path = statoverride.invocation_target, .mode = 0o600, .uid = 42420, .gid = 42421 },
            });
            defer fixture.allocator.free(input);
            const location = try process.rootPath(fixture, case.native_root, input);
            defer fixture.allocator.free(location);
            switch (kind) {
                .capture_tampered => {
                    const original = try process.rootBytes(fixture, case.native_root, input);
                    defer fixture.allocator.free(original);
                    const tampered = try std.mem.replaceOwned(u8, fixture.allocator, original, "\"mode\":384", "\"mode\":420");
                    defer fixture.allocator.free(tampered);
                    if (std.mem.eql(u8, original, tampered)) return error.WrongUnpackStatOverrideInput;
                    try support.fixtureFile(fixture, location, tampered, 0o600);
                },
                .capture_deleted => try fixture.dir.deleteFile(fixture.io, location),
                .capture_database_drift => {
                    const database = try process.rootPath(fixture, case.native_root, "var/lib/dpkg/statoverride");
                    defer fixture.allocator.free(database);
                    try support.fixtureFile(fixture, database, "#42422 #42423 0640 /" ++ statoverride.invocation_target ++ "\n", 0o644);
                },
                else => {},
            }
        },
        .prerm_outcome => {
            // The old prerm already edited the live database; the input predates it.
            const input = try expectUnpackStatOverrideInput(fixture, case.native_root, &.{});
            fixture.allocator.free(input);
            const database = try process.rootBytes(fixture, case.native_root, "var/lib/dpkg/statoverride");
            defer fixture.allocator.free(database);
            if (std.mem.indexOf(u8, database, " /" ++ statoverride.base ++ "/mode\n") == null)
                return error.StatoverrideEditNotObserved;
        },
        .provider_outcome, .intent_prerm_outcome => if (try statoverride.unpackStatOverrideInput(fixture, case.native_root)) |path| {
            fixture.allocator.free(path);
            return error.PrematureUnpackStatOverrideInput;
        },
    }

    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var report = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer report.deinit();
    switch (kind) {
        .capture_tampered, .capture_deleted, .capture_database_drift => {
            if (!std.mem.eql(u8, report.value.outcome, "recovery_required") or
                std.mem.indexOf(u8, report.value.detail, "managed_state_changed") == null)
                return error.UnpackStatOverrideInputDriftAccepted;
            const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
            defer fixture.allocator.free(after);
            if (!std.mem.eql(u8, before, after)) return error.BlockedRecoveryMutatedRoot;
            return;
        },
        else => {},
    }
    try process.same(report.value.outcome, "applied");
    const comparison = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(comparison);
    try fixture.directory(comparison);
    try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
    try statoverride.expectEditApplied(&case);
    try statoverride.expectObserved(&case, statoverride.base ++ "/mode", statoverride.packaged_mode);
    try statoverride.expectObserved(&case, statoverride.conffile_path, statoverride.updated_conffile);
    switch (kind) {
        .prerm_outcome => try statoverride.expectObserved(&case, statoverride.invocation_target, .{ .mode = 0o644, .uid = 0, .gid = 0 }),
        .intent_prerm_outcome => {},
        else => try statoverride.expectObserved(&case, statoverride.invocation_target, .{ .mode = 0o600, .uid = 42420, .gid = 42421 }),
    }
    try support.assertDatabaseBytes(&case, "statoverride");
    try support.assertDatabaseBytes(&case, "statoverride-old");
    try statoverride.expectNoUnpackStatOverrideInput(&case);
}

/// A maintainer script that ends itself with a signal fails exactly like one
/// that exits nonzero (lib/dpkg/subproc.c:139-157). In `preinst`, a fresh
/// install's preinst adds override records and is then terminated: dpkg runs
/// `postrm abort-install`, exits 1 and keeps the records. In `postrm`, an
/// upgrade's old postrm adds records and is then killed: dpkg runs the new
/// `postrm failed-upgrade` and completes the upgrade (src/main/script.c:328-392).
/// Native crashes just after persisting the signalled outcome, and
/// archive-evicted recovery must end like dpkg. `postrm_forged` rewrites that
/// outcome as a clean exit and reseals it; the journal still binds the
/// signalled outcome, so recovery must refuse without mutating the root.
const SignalCase = enum { preinst, postrm, postrm_forged };

fn canonicalJson(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    errdefer output.deinit();
    try std.json.Stringify.value(value, .{ .whitespace = .minified }, &output.writer);
    try output.writer.writeByte('\n');
    return output.toOwnedSlice();
}

/// Returns the root-relative path of the one persisted script outcome under
/// `root` that records a signal. It must be `kind`'s own `signal`, not a
/// termination that native imposed.
fn signaledOutcome(fixture: *foundation.Fixture, root: []const u8, kind: debz.maintainer_script.Kind, signal: u32) ![]u8 {
    const directory = try process.rootPath(fixture, root, "var/lib/debz");
    defer fixture.allocator.free(directory);
    var dir = try fixture.dir.openDir(fixture.io, directory, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(fixture.io);
    var iterator = dir.iterate();
    var found: ?[]u8 = null;
    errdefer if (found) |path| fixture.allocator.free(path);
    while (try iterator.next(fixture.io)) |entry| {
        if (!std.mem.startsWith(u8, entry.name, debz.native_recovery.script_outcome_prefix)) continue;
        if (entry.kind != .file) return error.WrongScriptOutcome;
        const path = try std.fmt.allocPrint(fixture.allocator, "var/lib/debz/{s}", .{entry.name});
        var kept = false;
        defer if (!kept) fixture.allocator.free(path);
        const bytes = try process.rootBytes(fixture, root, path);
        defer fixture.allocator.free(bytes);
        var parsed = try std.json.parseFromSlice(debz.native_recovery.ScriptOutcome, fixture.allocator, bytes, .{
            .allocate = .alloc_always,
        });
        defer parsed.deinit();
        const outcome = parsed.value;
        if (outcome.disposition != .signaled) continue;
        if (found != null) return error.AmbiguousSignaledOutcome;
        if (outcome.kind != kind or (outcome.signal orelse 0) != signal or outcome.exit_code != null or
            !outcome.spawned or outcome.terminated_process_group or outcome.escalated_to_kill)
        {
            std.debug.print("{s}: {s} signal {?d} exit {?d} spawned {} group {} escalated {}, expected {s} signal {d}\n", .{
                path,                             @tagName(outcome.kind),    outcome.signal, outcome.exit_code, outcome.spawned,
                outcome.terminated_process_group, outcome.escalated_to_kill, @tagName(kind), signal,
            });
            return error.WrongSignaledOutcome;
        }
        kept = true;
        found = path;
    }
    return found orelse error.MissingSignaledOutcome;
}

/// Rewrites the signalled outcome at `path` in place as a sealed, canonical
/// exit 0 and returns the forged bytes.
fn forgeExitedOutcome(fixture: *foundation.Fixture, root: []const u8, path: []const u8) ![]u8 {
    const bytes = try process.rootBytes(fixture, root, path);
    defer fixture.allocator.free(bytes);
    var parsed = try std.json.parseFromSlice(debz.native_recovery.ScriptOutcome, fixture.allocator, bytes, .{
        .allocate = .alloc_always,
    });
    defer parsed.deinit();
    const original = try canonicalJson(fixture.allocator, parsed.value);
    defer fixture.allocator.free(original);
    // Only the claimed termination may differ from what native wrote.
    if (!std.mem.eql(u8, bytes, original)) return error.NonCanonicalScriptOutcome;
    var forged = parsed.value;
    forged.disposition = .exited;
    forged.exit_code = 0;
    forged.signal = null;
    debz.native_recovery.sealScriptOutcome(&forged);
    try debz.native_recovery.validateScriptOutcome(forged);
    const encoded = try canonicalJson(fixture.allocator, forged);
    errdefer fixture.allocator.free(encoded);
    const location = try process.rootPath(fixture, root, path);
    defer fixture.allocator.free(location);
    try fixture.write(location, encoded, 0o600);
    return encoded;
}

/// A blocked recovery leaves the captured root, the bytes at `paths` and the
/// pending operation exactly as they were.
fn expectBlockedUnchanged(
    fixture: *foundation.Fixture,
    root: []const u8,
    name: []const u8,
    report: process.Report,
    before: []const u8,
    paths: []const []const u8,
    contents: []const []const u8,
) !void {
    if (!std.mem.eql(u8, report.outcome, "recovery_required") and !std.mem.eql(u8, report.outcome, "refused")) {
        std.debug.print("{s}: recovery was not blocked: {s}: {s}\n", .{ name, report.outcome, report.detail });
        return error.BlockedRecoveryAccepted;
    }
    const after = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.BlockedRecoveryMutatedRoot;
    for (paths, contents) |path, expected| {
        const observed = try process.rootBytes(fixture, root, path);
        defer fixture.allocator.free(observed);
        if (!std.mem.eql(u8, observed, expected)) return error.BlockedRecoveryMutatedRoot;
    }
    const pending = try process.rootBytes(fixture, root, operation_path);
    fixture.allocator.free(pending);
    try process.rootAbsent(fixture, root, completion_path);
}

fn runSignalCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, kind: SignalCase) !void {
    const name = switch (kind) {
        .preinst => "statoverride-signal-preinst",
        .postrm => "statoverride-signal-postrm",
        .postrm_forged => "statoverride-signal-postrm-forged",
    };
    const install = kind == .preinst;
    const operation = if (install) "install" else "upgrade";
    const package_workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(package_workspace);
    const first = try statoverride.signalEditArchive(fixture, arch, "1", package_workspace);
    defer fixture.allocator.free(first);
    const second = try statoverride.signalEditArchive(fixture, arch, "2", package_workspace);
    defer fixture.allocator.free(second);
    const archives = [_][]const u8{if (install) first else second};
    const selected = [_]foundation.PackageIdentity{.{ .name = statoverride.name, .architecture = arch }};

    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    try statoverride.seed(&case, "");
    try installDpkgStatoverride(&case, dpkg);
    // Records only, so no file metadata changes and only the signal decides.
    try statoverride.replace(&case, statoverride.edit_marker, if (install) "preinst:install\n" else "postrm:upgrade\n");
    try statoverride.both(&case, statoverride.signal_marker, if (install) "preinst:install TERM\n" else "postrm:upgrade KILL\n");
    if (!install) try case.seed(first);

    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = operation,
        .archives = &archives,
        .packages = &selected,
        .triggers = false,
    }, reference_log) != @intFromBool(install)) return error.UnexpectedReferenceOutcome;
    const reference_output = try support.path(fixture.allocator, reference_log, "reference.log");
    defer fixture.allocator.free(reference_output);
    const output = try support.read(fixture, reference_output, 1024 * 1024);
    defer fixture.allocator.free(output);
    try statoverride.expectReports(name, output, if (install)
        &.{statoverride.terminated_report}
    else
        &.{ statoverride.killed_report, statoverride.fallback_report });

    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = operation,
        .archives = &archives,
        .packages = &selected,
        .crash_at = if (install) "after_failure_outcome" else "after_upgrade_postrm_outcome",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) |value| {
        var invalid = value;
        invalid.deinit();
        return error.MissingCrash;
    }
    try statoverride.expectEditApplied(&case);
    try statoverride.expectSignalSent(&case);
    const outcome_path = try signaledOutcome(fixture, case.native_root, if (install) .preinst else .postrm, if (install) 15 else 9);
    defer fixture.allocator.free(outcome_path);
    for ([_][]const u8{ first, second }) |path| {
        try fixture.dir.deleteFile(fixture.io, path[fixture.path.len + 1 ..]);
        try support.absent(fixture, path[fixture.path.len + 1 ..]);
    }
    const forged = if (kind == .postrm_forged) try forgeExitedOutcome(fixture, case.native_root, outcome_path) else null;
    defer if (forged) |bytes| fixture.allocator.free(bytes);

    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const database_before = try process.rootBytes(fixture, case.native_root, "var/lib/dpkg/statoverride");
    defer fixture.allocator.free(database_before);
    const status_before = try process.rootBytes(fixture, case.native_root, "var/lib/dpkg/status");
    defer fixture.allocator.free(status_before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var report = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer report.deinit();

    if (forged) |forged_bytes| {
        const paths = [_][]const u8{ "var/lib/dpkg/statoverride", "var/lib/dpkg/status", outcome_path };
        const contents = [_][]const u8{ database_before, status_before, forged_bytes };
        try expectBlockedUnchanged(fixture, case.native_root, name, report.value, before, &paths, &contents);
        const repeat_log = try support.path(fixture.allocator, name, "recover-again");
        defer fixture.allocator.free(repeat_log);
        var repeated = (try process.invoke(fixture, driver, case.native_root, arch, repeat_log, .{
            .operation = "recover",
            .triggers = false,
            .caller_owned = true,
            .isolated_helper = true,
            .core_product = true,
        })) orelse return error.MissingRecoveryReport;
        defer repeated.deinit();
        try expectBlockedUnchanged(fixture, case.native_root, name, repeated.value, before, &paths, &contents);
        std.debug.print("statoverride signal postrm-forged: blocked as {s} ({s})\n", .{ report.value.outcome, report.value.detail });
        return;
    }

    try process.same(report.value.outcome, if (install) "script_failed" else "applied");
    const comparison = try support.path(fixture.allocator, name, "comparison");
    defer fixture.allocator.free(comparison);
    try fixture.directory(comparison);
    try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
    if (!install) {
        try statoverride.expectObserved(&case, statoverride.base ++ "/mode", statoverride.packaged_mode);
        try statoverride.expectObserved(&case, statoverride.conffile_path, statoverride.packaged_conffile);
    }
    try support.assertDatabaseBytes(&case, "statoverride");
    try support.assertDatabaseBytes(&case, "statoverride-old");
    try statoverride.expectNoUnpackStatOverrideInput(&case);
    const proof_path = try process.reportProvenancePath(report.value.provenance_path);
    var proof = try process.rootDocument(fixture, case.native_root, proof_path);
    defer proof.deinit();
    try process.same(try process.text(proof.value, "attempt_id"), report.value.attempt_id orelse return error.MissingRecoveryProof);
    var completion = try process.rootDocument(fixture, case.native_root, completion_path);
    defer completion.deinit();
    try process.same(try process.text(completion.value, "outcome"), if (install) "failed_after_mutation" else "succeeded");
    try process.same(try process.text(completion.value, "attempt_id"), try process.text(proof.value, "attempt_id"));
    try process.rootAbsent(fixture, case.native_root, operation_path);
    try process.rootAbsent(fixture, case.native_root, intent_path);
    const completion_before = try process.rootBytes(fixture, case.native_root, completion_path);
    defer fixture.allocator.free(completion_before);
    const settled = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(settled);
    const repeat_log = try support.path(fixture.allocator, name, "recover-again");
    defer fixture.allocator.free(repeat_log);
    var repeated = (try process.invoke(fixture, driver, case.native_root, arch, repeat_log, .{
        .operation = "recover",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer repeated.deinit();
    try process.same(repeated.value.outcome, "applied");
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, settled, after)) return error.RepeatedRecoveryMutatedRoot;
    const completion_after = try process.rootBytes(fixture, case.native_root, completion_path);
    defer fixture.allocator.free(completion_after);
    if (!std.mem.eql(u8, completion_before, completion_after)) return error.RepeatedRecoveryReplacedReceipt;
    std.debug.print("statoverride signal {s}: recovered as {s}\n", .{ @tagName(kind), report.value.outcome });
}

fn runChronyCase(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    changed: bool,
    drift: ?enum { mode, owner, bytes },
) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "statoverride-chrony-{s}-{s}", .{
        if (changed) "changed" else "created",
        if (drift) |value| @tagName(value) else "recover",
    });
    defer fixture.allocator.free(name);
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    try statoverride.seedChrony(&case, dpkg, changed);
    const workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(workspace);
    const archive = try statoverride.chronyArchive(fixture, arch, "1", workspace);
    defer fixture.allocator.free(archive);
    const selected = [_]foundation.PackageIdentity{.{ .name = statoverride.chrony_name, .architecture = arch }};
    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "install",
        .archives = &.{archive},
        .packages = &selected,
    }, reference_log) != 0) return error.UnexpectedReferenceOutcome;
    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = "install",
        .archives = &.{archive},
        .packages = &selected,
        .crash_at = "after_script_outcome",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) |value| {
        var invalid = value;
        invalid.deinit();
        return error.MissingCrash;
    }
    try expectChronyCheckpoint(fixture, case.native_root);
    try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
    for ([_][]const u8{ case.reference_root, case.native_root }) |root_path| {
        var dir = try foundation.guardedRoot(fixture.io, root_path);
        defer dir.close(fixture.io);
        try (root_fs.Root.init(fixture.io, dir)).applyMetadata(
            try root_fs.Path.init(statoverride.admin_target),
            .{ .mode = 0o600 },
        );
    }
    if (drift) |value| {
        var dir = try foundation.guardedRoot(fixture.io, case.native_root);
        defer dir.close(fixture.io);
        const root: root_fs.Root = .init(fixture.io, dir);
        switch (value) {
            .mode => try root.applyMetadata(try root_fs.Path.init("var/log/chrony"), .{ .mode = 0o700 }),
            .owner => try root.applyMetadata(try root_fs.Path.init("var/lib/chrony"), .{ .uid = 42422 }),
            .bytes => {
                const path = try process.rootPath(fixture, case.native_root, statoverride.chrony_targets[0]);
                defer fixture.allocator.free(path);
                try support.fixtureFile(fixture, path, "drifted key!\n", 0o640);
                try root.applyMetadata(try root_fs.Path.init(statoverride.chrony_targets[0]), .{ .gid = 42421 });
            },
        }
    }
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var report = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer report.deinit();
    if (drift != null) {
        if (!std.mem.eql(u8, report.value.outcome, "recovery_required") or
            std.mem.indexOf(u8, report.value.detail, "managed_state_changed") == null)
            return error.ChangedOverrideTargetDriftAccepted;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.BlockedRecoveryMutatedRoot;
    } else {
        try process.same(report.value.outcome, "applied");
        const comparison = try support.path(fixture.allocator, name, "comparison");
        defer fixture.allocator.free(comparison);
        try fixture.directory(comparison);
        try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
        try statoverride.expectChronyMetadata(&case);
        try support.assertDatabaseBytes(&case, "statoverride");
        try support.assertDatabaseBytes(&case, "statoverride-old");
        try statoverride.verifyChronyState(&case);
        var managed = try statoverride.settledChronyState(&case);
        defer managed.deinit();
        var dir = try foundation.guardedRoot(fixture.io, case.native_root);
        defer dir.close(fixture.io);
        const root: root_fs.Root = .init(fixture.io, dir);
        try root.applyMetadata(try root_fs.Path.init("var/log/chrony"), .{ .mode = 0o700 });
        try std.testing.expectError(error.LivePayloadChanged, debz.native_recovery.verifySettledManagedState(
            fixture.allocator,
            root,
            managed.document,
            .{ .paths = &.{"etc/debz-native.conf"}, .prefixes = &.{"var/lib/debz/"} },
        ));
    }
    std.debug.print("{s}: checkpoint/settled verification passed\n", .{name});
}

fn runFailedChronyCase(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, drift: bool) !void {
    const name = if (drift) "statoverride-chrony-failed-mode" else "statoverride-chrony-failed-recover";
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    try statoverride.seedChrony(&case, dpkg, false);
    try statoverride.both(&case, support.failure, statoverride.chrony_failure);
    const workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(workspace);
    const archive = try statoverride.chronyArchive(fixture, arch, "1", workspace);
    defer fixture.allocator.free(archive);
    const selected = [_]foundation.PackageIdentity{.{ .name = statoverride.chrony_name, .architecture = arch }};
    const reference_log = try support.path(fixture.allocator, name, "reference-execution");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "install",
        .archives = &.{archive},
        .packages = &selected,
    }, reference_log) != 1) return error.UnexpectedReferenceOutcome;
    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = "install",
        .archives = &.{archive},
        .packages = &selected,
        .crash_at = "after_failure_outcome",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) |value| {
        var invalid = value;
        invalid.deinit();
        return error.MissingCrash;
    }
    // The failed postinst added these overrides before exiting nonzero.
    try expectChronyCheckpoint(fixture, case.native_root);
    try fixture.dir.deleteFile(fixture.io, archive[fixture.path.len + 1 ..]);
    for ([_][]const u8{ case.reference_root, case.native_root }) |root_path| {
        var dir = try foundation.guardedRoot(fixture.io, root_path);
        defer dir.close(fixture.io);
        const root: root_fs.Root = .init(fixture.io, dir);
        try root.applyMetadata(try root_fs.Path.init(statoverride.admin_target), .{ .mode = 0o600 });
        if (drift and std.mem.eql(u8, root_path, case.native_root))
            try root.applyMetadata(try root_fs.Path.init("var/log/chrony"), .{ .mode = 0o700 });
    }
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var report = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer report.deinit();
    if (drift) {
        if (!std.mem.eql(u8, report.value.outcome, "recovery_required") or
            std.mem.indexOf(u8, report.value.detail, "managed_state_changed") == null)
            return error.FailedScriptOverrideDriftAccepted;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.BlockedRecoveryMutatedRoot;
    } else {
        try process.same(report.value.outcome, "script_failed");
        const comparison = try support.path(fixture.allocator, name, "comparison");
        defer fixture.allocator.free(comparison);
        try fixture.directory(comparison);
        try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
        try statoverride.expectChronyMetadata(&case);
        try support.assertDatabaseBytes(&case, "statoverride");
        try support.assertDatabaseBytes(&case, "statoverride-old");
        try statoverride.expectFailedChronyBinding(&case);
        var completion = try process.rootDocument(fixture, case.native_root, completion_path);
        defer completion.deinit();
        try process.same(try process.text(completion.value, "outcome"), "failed_after_mutation");
    }
    std.debug.print("{s}: failed-script checkpoint passed\n", .{name});
}

fn expectChronyCheckpoint(fixture: *foundation.Fixture, root_path: []const u8) !void {
    var dir = try foundation.guardedRoot(fixture.io, root_path);
    defer dir.close(fixture.io);
    var managed = try debz.native_recovery.readManagedState(fixture.allocator, .init(fixture.io, dir));
    defer managed.deinit();
    const stable = managed.document.stable orelse return error.MissingManagedState;
    for (statoverride.chrony_targets) |target| {
        var found = false;
        for (stable.entries) |entry| {
            if (std.mem.eql(u8, entry.path, statoverride.admin_target)) return error.AdministratorOverrideWasManaged;
            if (std.mem.eql(u8, entry.path, target)) {
                found = true;
                if (entry.kind == .absent) return error.AbsentChangedOverrideTarget;
            }
        }
        if (!found) return error.MissingChangedOverrideTarget;
    }
}

const UpgradeScriptDrift = enum { old_to_new, new_to_old, old_unrelated, new_unrelated };

fn runChangedChronyUpgrade(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    crash: []const u8,
    drift: ?UpgradeScriptDrift,
) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "statoverride-script-upgrade-{s}-{s}", .{
        crash, if (drift) |value| @tagName(value) else "recover",
    });
    defer fixture.allocator.free(name);
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer case.deinit();
    try statoverride.seedChrony(&case, dpkg, false);
    const workspace = try support.path(fixture.allocator, name, "packages");
    defer fixture.allocator.free(workspace);
    const first = try statoverride.chronyArchive(fixture, arch, "1", workspace);
    defer fixture.allocator.free(first);
    const second = try statoverride.changedChronyArchive(fixture, arch, "2", workspace);
    defer fixture.allocator.free(second);
    const selected = [_]foundation.PackageIdentity{.{ .name = statoverride.chrony_name, .architecture = arch }};
    try case.phase(.{ .operation = "install", .archives = &.{first}, .packages = &selected, .recovery = true }, false);
    const original = try process.rootBytes(fixture, case.native_root, "var/lib/dpkg/info/" ++ statoverride.chrony_name ++ ".postinst");
    defer fixture.allocator.free(original);
    const reference_log = try support.path(fixture.allocator, name, "reference-upgrade");
    defer fixture.allocator.free(reference_log);
    try fixture.directory(reference_log);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "upgrade",
        .archives = &.{second},
        .packages = &selected,
    }, reference_log) != 0) return error.UnexpectedReferenceOutcome;
    const crash_log = try support.path(fixture.allocator, name, "crash");
    defer fixture.allocator.free(crash_log);
    if (try process.invoke(fixture, driver, case.native_root, arch, crash_log, .{
        .operation = "upgrade",
        .archives = &.{second},
        .packages = &selected,
        .crash_at = crash,
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) |value| {
        var invalid = value;
        invalid.deinit();
        return error.MissingCrash;
    }
    const old_path = try std.fmt.allocPrint(fixture.allocator, "var/lib/debz-lifecycle-scripts/{s}:{s}.postinst", .{ statoverride.chrony_name, arch });
    defer fixture.allocator.free(old_path);
    const new_path = "var/lib/debz-lifecycle-scripts/" ++ statoverride.chrony_name ++ ".postinst";
    const old_script = try process.rootBytes(fixture, case.native_root, old_path);
    defer fixture.allocator.free(old_script);
    const new_script = try process.rootBytes(fixture, case.native_root, new_path);
    defer fixture.allocator.free(new_script);
    if (!std.mem.eql(u8, original, old_script)) return error.OriginalScriptAuthorityLost;
    if (std.mem.eql(u8, old_script, new_script)) return error.ChangedScriptFixtureWasByteStable;
    if (drift) |value| {
        const target = switch (value) {
            .old_to_new, .old_unrelated => old_path,
            .new_to_old, .new_unrelated => new_path,
        };
        const bytes = switch (value) {
            .old_to_new => new_script,
            .new_to_old => old_script,
            .old_unrelated, .new_unrelated => "#!/bin/sh\nprintf 'unauthorized\\n' > /unrelated-script-called\nexit 0\n",
        };
        const path = try process.rootPath(fixture, case.native_root, target);
        defer fixture.allocator.free(path);
        var dir = try foundation.guardedRoot(fixture.io, case.native_root);
        defer dir.close(fixture.io);
        const root: root_fs.Root = .init(fixture.io, dir);
        const entry = try root.entry(try root_fs.Path.init(target));
        try support.fixtureFile(fixture, path, bytes, entry.mode);
        try root.applyMetadata(try root_fs.Path.init(target), .{
            .uid = entry.uid,
            .gid = entry.gid,
            .modified_nanoseconds = entry.modified_nanoseconds,
        });
        const after = try root.entry(try root_fs.Path.init(target));
        if (entry.device != after.device or entry.inode != after.inode)
            return error.ScriptDriftChangedIdentity;
    }
    try fixture.dir.deleteFile(fixture.io, first[fixture.path.len + 1 ..]);
    try fixture.dir.deleteFile(fixture.io, second[fixture.path.len + 1 ..]);
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const recovery_log = try support.path(fixture.allocator, name, "recover");
    defer fixture.allocator.free(recovery_log);
    var report = (try process.invoke(fixture, driver, case.native_root, arch, recovery_log, .{
        .operation = "recover",
        .triggers = false,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = true,
    })) orelse return error.MissingRecoveryReport;
    defer report.deinit();
    try process.rootAbsent(fixture, case.native_root, "unrelated-script-called");
    if (drift != null) {
        if (!std.mem.eql(u8, report.value.outcome, "recovery_required") or
            std.mem.indexOf(u8, report.value.detail, "managed_state_changed") == null)
            return error.ChangedScriptAuthorityDriftAccepted;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.BlockedRecoveryMutatedRoot;
    } else {
        try process.same(report.value.outcome, "applied");
        const comparison = try support.path(fixture.allocator, name, "comparison");
        defer fixture.allocator.free(comparison);
        try fixture.directory(comparison);
        try support.compare(fixture, case.reference_root, case.native_root, comparison, true);
        try statoverride.expectChangedChronyMetadata(&case);
        try support.assertDatabaseBytes(&case, "statoverride");
        try support.assertDatabaseBytes(&case, "statoverride-old");
        try statoverride.verifyChangedChronyState(&case);
    }
    std.debug.print("{s}: old/new script authority passed\n", .{name});
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
    try runChangedChronyUpgrade(&fixture, driver, reference.executable, reference.architecture, "after_script_prepared", null);
    try runChangedChronyUpgrade(&fixture, driver, reference.executable, reference.architecture, "after_script_outcome", null);
    for (std.meta.tags(UpgradeScriptDrift)) |drift|
        try runChangedChronyUpgrade(&fixture, driver, reference.executable, reference.architecture, "after_script_outcome", drift);
    try runChronyCase(&fixture, driver, reference.executable, reference.architecture, false, null);
    try runChronyCase(&fixture, driver, reference.executable, reference.architecture, true, null);
    try runChronyCase(&fixture, driver, reference.executable, reference.architecture, false, .mode);
    try runChronyCase(&fixture, driver, reference.executable, reference.architecture, true, .owner);
    try runChronyCase(&fixture, driver, reference.executable, reference.architecture, false, .bytes);
    try runFailedChronyCase(&fixture, driver, reference.executable, reference.architecture, false);
    try runFailedChronyCase(&fixture, driver, reference.executable, reference.architecture, true);
    try runRefreshCase(&fixture, driver, reference.executable, reference.architecture, false);
    std.debug.print("statoverride refresh after_script_outcome: recovered\n", .{});
    try runRefreshCase(&fixture, driver, reference.executable, reference.architecture, true);
    std.debug.print("statoverride refresh after_script_outcome: tamper blocked\n", .{});
    for (std.meta.tags(InvocationCase)) |kind| {
        try runInvocationCase(&fixture, driver, reference.executable, reference.architecture, kind);
        std.debug.print("statoverride invocation {s}: recovered or blocked\n", .{@tagName(kind)});
    }
    for (std.meta.tags(SignalCase)) |kind|
        try runSignalCase(&fixture, driver, reference.executable, reference.architecture, kind);
    for (cases) |entry| {
        try runCase(&fixture, driver, reference.executable, reference.architecture, entry);
        std.debug.print("statoverride {s}/{s}: recovered or blocked\n", .{ entry.operation, entry.boundary });
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
