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
    try runRefreshCase(&fixture, driver, reference.executable, reference.architecture, false);
    std.debug.print("statoverride refresh after_script_outcome: recovered\n", .{});
    try runRefreshCase(&fixture, driver, reference.executable, reference.architecture, true);
    std.debug.print("statoverride refresh after_script_outcome: tamper blocked\n", .{});
    for (cases) |entry| {
        try runCase(&fixture, driver, reference.executable, reference.architecture, entry);
        std.debug.print("statoverride {s}/{s}: recovered or blocked\n", .{ entry.operation, entry.boundary });
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
