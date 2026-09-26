const std = @import("std");
const debz = @import("debz");
const foundation = @import("native_test_foundation.zig");
const lifecycle = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");
const root_fs = @import("debz").root_fs;

const package = "diversion-lifecycle";
const base = "usr/share/" ++ package;
const namespace = "var/lib/debz/";
const operation_path = namespace ++ "root-operation-v1.json";
const intent_path = namespace ++ "native-execution-intent-v1.json";
const completion_path = namespace ++ "root-operation-completion-v1.json";
const proof_path = namespace ++ "native-transaction-provenance-v1.json";
const diversion_cache = namespace ++ "native-diversion-cache-v1.json";

const Case = struct {
    number: u8,
    operation: []const u8,
    crash: []const u8,
    mutation: ?[]const u8 = null,
};

const cases = [_]Case{
    .{ .number = 1, .operation = "install", .crash = "after_execution_intent" },
    .{ .number = 2, .operation = "install", .crash = "during_filesystem_publication" },
    .{ .number = 3, .operation = "install", .crash = "after_script_outcome" },
    .{ .number = 4, .operation = "install", .crash = "after_failure_outcome" },
    .{ .number = 5, .operation = "upgrade", .crash = "during_database_publication" },
    .{ .number = 6, .operation = "upgrade", .crash = "after_script_outcome" },
    .{ .number = 7, .operation = "remove", .crash = "after_script_outcome" },
    .{ .number = 8, .operation = "purge", .crash = "after_script_prepared" },
    .{ .number = 9, .operation = "install", .crash = "after_script_outcome", .mutation = "preinst" },
    .{ .number = 10, .operation = "install", .crash = "after_script_outcome", .mutation = "created" },
    .{ .number = 11, .operation = "install", .crash = "after_script_outcome", .mutation = "helper" },
    .{ .number = 12, .operation = "install", .crash = "after_script_prepared", .mutation = "inplace" },
    .{ .number = 13, .operation = "install", .crash = "after_script_outcome", .mutation = "inplace" },
    .{ .number = 14, .operation = "install", .crash = "after_failure_outcome", .mutation = "inplace" },
    .{ .number = 15, .operation = "install", .crash = "after_script_return_before_outcome", .mutation = "inplace-unknown" },
    .{ .number = 16, .operation = "upgrade", .crash = "during_filesystem_publication", .mutation = "inplace" },
    .{ .number = 17, .operation = "remove", .crash = "after_script_outcome", .mutation = "inplace-prerm" },
    .{ .number = 18, .operation = "purge", .crash = "after_script_prepared", .mutation = "inplace-postrm" },
    .{ .number = 19, .operation = "install", .crash = "after_script_outcome", .mutation = "inplace-empty" },
    .{ .number = 20, .operation = "install", .crash = "after_trigger_outcome", .mutation = "atomic-then-inplace" },
    .{ .number = 21, .operation = "upgrade", .crash = "during_filesystem_publication", .mutation = "mid-unpack" },
    .{ .number = 22, .operation = "upgrade", .crash = "after_script_prepared", .mutation = "mid-unpack" },
    .{ .number = 23, .operation = "upgrade", .crash = "after_upgrade_postrm_route_publication", .mutation = "mid-unpack" },
    .{ .number = 24, .operation = "upgrade", .crash = "after_upgrade_postrm_outcome", .mutation = "mid-unpack" },
    .{ .number = 25, .operation = "upgrade", .crash = "during_filesystem_publication", .mutation = "mid-cached-route" },
    .{ .number = 26, .operation = "upgrade", .crash = "after_script_prepared", .mutation = "mid-cached-route" },
    .{ .number = 27, .operation = "upgrade", .crash = "after_upgrade_postrm_route_publication", .mutation = "mid-cached-route" },
    .{ .number = 28, .operation = "upgrade", .crash = "after_upgrade_postrm_outcome", .mutation = "mid-cached-route" },
    .{ .number = 29, .operation = "install", .crash = "after_trigger_outcome", .mutation = "postinst" },
    .{ .number = 30, .operation = "install", .crash = "after_execution_intent", .mutation = "database-drift" },
    .{ .number = 31, .operation = "install", .crash = "after_trigger_outcome", .mutation = "destination-drift" },
    .{ .number = 32, .operation = "purge", .crash = "after_script_prepared", .mutation = "conffile-drift" },
    .{ .number = 33, .operation = "install", .crash = "after_execution_intent", .mutation = "cache-file-drift" },
    .{ .number = 34, .operation = "install", .crash = "after_execution_intent", .mutation = "cache-mode-drift" },
    .{ .number = 35, .operation = "install", .crash = "after_execution_intent", .mutation = "cache-missing-drift" },
    .{ .number = 36, .operation = "install", .crash = "after_trigger_outcome", .mutation = "unpack-cache-file-drift" },
    .{ .number = 37, .operation = "install", .crash = "after_trigger_outcome", .mutation = "unpack-cache-mode-drift" },
    .{ .number = 38, .operation = "install", .crash = "after_trigger_outcome", .mutation = "unpack-cache-missing-drift" },
    .{ .number = 39, .operation = "install", .crash = "after_provenance", .mutation = "unpack-retained-file-drift" },
    .{ .number = 40, .operation = "install", .crash = "after_provenance", .mutation = "unpack-retained-missing-drift" },
    .{ .number = 41, .operation = "upgrade", .crash = "after_unpack_backups", .mutation = "backup-probe" },
    .{ .number = 42, .operation = "upgrade", .crash = "before_unpack_backup_cleanup", .mutation = "backup-probe" },
    .{ .number = 43, .operation = "upgrade", .crash = "after_unpack_backup_cleanup", .mutation = "backup-probe" },
    .{ .number = 44, .operation = "upgrade", .crash = "after_upgrade_postrm_return_before_outcome", .mutation = "backup-unknown" },
    .{ .number = 45, .operation = "upgrade", .crash = "after_unpack_backups", .mutation = "backup-file-drift" },
    .{ .number = 46, .operation = "upgrade", .crash = "after_unpack_backups", .mutation = "backup-mode-drift" },
    .{ .number = 47, .operation = "upgrade", .crash = "after_unpack_backups", .mutation = "backup-missing-drift" },
    .{ .number = 48, .operation = "upgrade", .crash = "after_unpack_backups", .mutation = "backup-source-drift" },
    .{ .number = 49, .operation = "upgrade", .crash = "before_unpack_backup_cleanup", .mutation = "backup-failure" },
    .{ .number = 50, .operation = "upgrade", .crash = "after_unpack_backup_cleanup", .mutation = "backup-failure" },
    .{ .number = 51, .operation = "upgrade", .crash = "before_failed_unpack_publication", .mutation = "backup-failure" },
    .{ .number = 52, .operation = "upgrade", .crash = "after_failed_unpack_publication", .mutation = "backup-failure" },
    .{ .number = 53, .operation = "upgrade", .crash = "during_unpack_backup_publication", .mutation = "backup-probe" },
    .{ .number = 54, .operation = "upgrade", .crash = "during_unpack_backup_cleanup", .mutation = "backup-probe" },
    .{ .number = 55, .operation = "upgrade", .crash = "during_failed_unpack_publication", .mutation = "backup-failure" },
    .{ .number = 56, .operation = "upgrade", .crash = "during_unpack_backup_cleanup", .mutation = "backup-failure" },
    .{ .number = 57, .operation = "upgrade", .crash = "after_failure_outcome", .mutation = "backup-failure" },
    .{ .number = 58, .operation = "upgrade", .crash = "after_upgrade_postrm_outcome", .mutation = "backup-probe" },
    .{ .number = 59, .operation = "upgrade", .crash = "after_upgrade_unwind_outcome", .mutation = "backup-unwind" },
    .{ .number = 60, .operation = "upgrade", .crash = "after_upgrade_unwind_outcome", .mutation = "backup-failure" },
    .{ .number = 61, .operation = "upgrade", .crash = "after_upgrade_pre_rollback_compensation_outcome", .mutation = "backup-failure" },
    .{ .number = 62, .operation = "upgrade", .crash = "after_upgrade_postrm_outcome", .mutation = "backup-probe-atomic" },
    .{ .number = 63, .operation = "upgrade", .crash = "after_failure_outcome", .mutation = "backup-failure-atomic" },
    .{ .number = 64, .operation = "upgrade", .crash = "after_failure_outcome", .mutation = "backup-failure-rollback-crash" },
    .{ .number = 65, .operation = "upgrade", .crash = "after_failure_outcome", .mutation = "backup-failure-rollback-finished" },
    .{ .number = 66, .operation = "upgrade", .crash = "after_upgrade_postrm_outcome", .mutation = "backup-postrm-payload-drift" },
    .{ .number = 67, .operation = "upgrade", .crash = "after_upgrade_postrm_outcome", .mutation = "backup-postrm-backup-drift" },
    .{ .number = 68, .operation = "upgrade", .crash = "after_upgrade_postrm_outcome", .mutation = "backup-postrm-cache-drift" },
    .{ .number = 69, .operation = "upgrade", .crash = "after_upgrade_postrm_outcome", .mutation = "backup-postrm-route-drift" },
    .{ .number = 70, .operation = "upgrade", .crash = "after_upgrade_postrm_outcome", .mutation = "backup-postrm-route-missing-drift" },
    .{ .number = 71, .operation = "upgrade", .crash = "after_upgrade_postrm_marker_cleared", .mutation = "backup-probe" },
    .{ .number = 72, .operation = "upgrade", .crash = "after_upgrade_postrm_marker_cleared", .mutation = "backup-failure" },
    .{ .number = 73, .operation = "upgrade", .crash = "after_upgrade_postrm_completed", .mutation = "backup-probe-atomic" },
    .{ .number = 74, .operation = "upgrade", .crash = "after_upgrade_postrm_completed", .mutation = "backup-failure" },
    .{ .number = 75, .operation = "upgrade", .crash = "after_upgrade_unwind_completed", .mutation = "backup-unwind" },
    .{ .number = 76, .operation = "upgrade", .crash = "after_upgrade_unwind_completed", .mutation = "backup-failure" },
    .{ .number = 77, .operation = "upgrade", .crash = "after_upgrade_pre_rollback_compensation_completed", .mutation = "backup-failure" },
    .{ .number = 78, .operation = "upgrade", .crash = "during_unpack_obsolete_removal", .mutation = "backup-probe" },
    .{ .number = 79, .operation = "upgrade", .crash = "during_unpack_obsolete_removal", .mutation = "backup-probe-atomic" },
    .{ .number = 80, .operation = "upgrade", .crash = "during_unpack_obsolete_removal", .mutation = "backup-unwind" },
    .{ .number = 81, .operation = "upgrade", .crash = "during_unpack_obsolete_removal", .mutation = "backup-probe-rollback-crash" },
    .{ .number = 82, .operation = "upgrade", .crash = "during_unpack_obsolete_removal", .mutation = "backup-probe-rollback-finished" },
    .{ .number = 83, .operation = "upgrade", .crash = "during_unpack_obsolete_removal", .mutation = "backup-postrm-directory-drift" },
    .{ .number = 84, .operation = "upgrade", .crash = "after_unpack_payload", .mutation = "backup-probe" },
    .{ .number = 85, .operation = "upgrade", .crash = "after_unpack_payload", .mutation = "backup-probe-atomic" },
    .{ .number = 86, .operation = "upgrade", .crash = "after_unpack_payload", .mutation = "backup-unwind" },
    .{ .number = 87, .operation = "upgrade", .crash = "after_unpack_payload_commit", .mutation = "backup-probe" },
    .{ .number = 88, .operation = "upgrade", .crash = "during_unpack_settlement", .mutation = "backup-probe" },
    .{ .number = 89, .operation = "upgrade", .crash = "during_unpack_settlement", .mutation = "backup-probe-atomic" },
    .{ .number = 90, .operation = "upgrade", .crash = "during_unpack_settlement", .mutation = "backup-unwind" },
    .{ .number = 91, .operation = "upgrade", .crash = "during_unpack_settlement", .mutation = "backup-probe-rollback-crash" },
    .{ .number = 92, .operation = "upgrade", .crash = "during_unpack_settlement", .mutation = "backup-probe-rollback-finished" },
    .{ .number = 93, .operation = "upgrade", .crash = "after_unpack_settlement", .mutation = "backup-probe" },
    .{ .number = 94, .operation = "upgrade", .crash = "after_unpack_settlement", .mutation = "backup-unwind" },
    .{ .number = 95, .operation = "upgrade", .crash = "after_unpack_settlement_commit", .mutation = "backup-probe" },
    .{ .number = 96, .operation = "upgrade", .crash = "after_unpack_settlement_rollback", .mutation = "backup-probe" },
    .{ .number = 97, .operation = "upgrade", .crash = "after_unpack_settlement_rollback", .mutation = "backup-unwind" },
    .{ .number = 98, .operation = "upgrade", .crash = "after_unpack_payload", .mutation = "backup-postrm-payload-drift" },
    .{ .number = 99, .operation = "upgrade", .crash = "after_unpack_payload", .mutation = "backup-settlement-input-drift" },
    .{ .number = 100, .operation = "upgrade", .crash = "during_unpack_settlement", .mutation = "backup-postrm-directory-drift" },
};

comptime {
    if (cases.len != 100) @compileError("diversion recovery must execute exactly 100 Python tuples");
    var previous: u8 = 0;
    for (cases) |c| {
        if (c.number <= previous or c.number > 100) @compileError("diversion recovery case numbers must be unique, ordered Python tuples");
        previous = c.number;
    }
}

const Report = struct {
    outcome: []const u8,
    detail: []const u8 = "",
    attempt_id: ?[]const u8 = null,
    program_sha256: ?[]const u8 = null,
    provenance_path: ?[]const u8 = null,
};

fn eq(left: []const u8, right: []const u8) bool {
    return std.mem.eql(u8, left, right);
}

fn same(actual: []const u8, expected: []const u8) !void {
    if (!eq(actual, expected)) {
        std.debug.print("expected {s}, got {s}\n", .{ expected, actual });
        return error.UnexpectedDiversionEvidence;
    }
}

fn relative(f: *foundation.Fixture, root: []const u8, name: []const u8) ![]u8 {
    if (!std.mem.startsWith(u8, root, f.path) or root.len <= f.path.len or root[f.path.len] != '/')
        return error.NotFixtureRoot;
    return lifecycle.path(f.allocator, root[f.path.len + 1 ..], name);
}

fn read(f: *foundation.Fixture, root: []const u8, name: []const u8, limit: usize) ![]u8 {
    const path = try relative(f, root, name);
    defer f.allocator.free(path);
    return lifecycle.read(f, path, limit);
}

fn rootEntry(f: *foundation.Fixture, root: []const u8, path: []const u8) !root_fs.Entry {
    var guarded = try foundation.guardedRoot(f.io, root);
    defer guarded.close(f.io);
    const state: root_fs.Root = .init(f.io, guarded);
    return state.entry(try root_fs.Path.init(path));
}

fn linkTime(f: *foundation.Fixture, root: []const u8) !i128 {
    const entry = try rootEntry(f, root, base ++ "/current");
    if (entry.kind != .sym_link) return error.RollbackChangedLinkKind;
    return entry.modified_nanoseconds;
}

const PayloadAnchor = struct {
    data: []u8,
    inode: u64,
    time: i128,
    staged: []u8,
    staged_time: i128,

    fn deinit(self: PayloadAnchor, allocator: std.mem.Allocator) void {
        allocator.free(self.data);
        allocator.free(self.staged);
    }
};

fn anchorPayload(f: *foundation.Fixture, root: []const u8) !PayloadAnchor {
    const data = try read(f, root, base ++ "/data", 1024 * 1024);
    errdefer f.allocator.free(data);
    const staged = try read(f, root, "etc/debz-native.conf.distrib.dpkg-new", 1024 * 1024);
    errdefer f.allocator.free(staged);
    const payload = try rootEntry(f, root, base ++ "/data");
    const conffile = try rootEntry(f, root, "etc/debz-native.conf.distrib.dpkg-new");
    if (payload.kind != .file or conffile.kind != .file) return error.NotPublishedPayload;
    return .{
        .data = data,
        .inode = payload.inode,
        .time = payload.modified_nanoseconds,
        .staged = staged,
        .staged_time = conffile.modified_nanoseconds,
    };
}

fn checkPayload(f: *foundation.Fixture, root: []const u8, anchor: PayloadAnchor) !void {
    const data = try read(f, root, base ++ "/data", 1024 * 1024);
    defer f.allocator.free(data);
    const installed = try read(f, root, "etc/debz-native.conf.distrib", 1024 * 1024);
    defer f.allocator.free(installed);
    const payload = try rootEntry(f, root, base ++ "/data");
    const conffile = try rootEntry(f, root, "etc/debz-native.conf.distrib");
    if (!eq(data, anchor.data) or payload.inode != anchor.inode or
        payload.modified_nanoseconds != anchor.time or !eq(installed, anchor.staged) or
        conffile.modified_nanoseconds != anchor.staged_time)
        return error.RecoveryRepublishedCommittedPayload;
}

fn document(f: *foundation.Fixture, root: []const u8, name: []const u8) !std.json.Parsed(std.json.Value) {
    const bytes = try read(f, root, name, 128 * 1024 * 1024);
    defer f.allocator.free(bytes);
    return std.json.parseFromSlice(std.json.Value, f.allocator, bytes, .{ .allocate = .alloc_always });
}

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidDiversionEvidence;
    return value.object.get(name) orelse error.MissingDiversionEvidence;
}

fn text(value: std.json.Value, name: []const u8) ![]const u8 {
    const item = try field(value, name);
    if (item != .string) return error.InvalidDiversionEvidence;
    return item.string;
}

fn evidenceFile(f: *foundation.Fixture, root: []const u8, prefix: []const u8) ![]u8 {
    const directory = try relative(f, root, namespace);
    defer f.allocator.free(directory);
    var dir = try f.dir.openDir(f.io, directory, .{ .iterate = true, .follow_symlinks = false });
    defer dir.close(f.io);
    var iterator = dir.iterate();
    var match: ?[]u8 = null;
    while (try iterator.next(f.io)) |entry| {
        if (std.mem.startsWith(u8, entry.name, prefix) and std.mem.endsWith(u8, entry.name, ".json")) {
            if (match != null or entry.kind != .file) return error.AmbiguousRecoveryEvidence;
            match = try lifecycle.path(f.allocator, namespace[0 .. namespace.len - 1], entry.name);
        }
    }
    return match orelse error.MissingRecoveryEvidence;
}

fn diversionRecords(f: *foundation.Fixture, suffix: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        f.allocator,
        "/{s}/mode\n/{s}/mode.{s}\n:\n" ++
            "/etc/diversion\\literal\n/etc/diversion\\literal.distrib\n:\n" ++
            "/etc/debz-native.conf\n/etc/debz-native.conf.distrib\n:\n",
        .{ base, base, suffix },
    );
}

fn seedRecord(f: *foundation.Fixture, root: []const u8, name: []const u8, bytes: []const u8) !void {
    const path = try relative(f, root, name);
    defer f.allocator.free(path);
    try lifecycle.fixtureFile(f, path, bytes, 0o644);
}

const mutation_script =
    \\replacement="/diversion-$DPKG_MAINTSCRIPT_NAME-replace"
    \\if [ -f "$replacement" ]; then
    \\    /diversion-mv "$replacement" /var/lib/dpkg/diversions || exit 26
    \\fi
    \\inplace="/diversion-$DPKG_MAINTSCRIPT_NAME-inplace"
    \\if [ -f "$inplace" ]; then
    \\    while IFS= read -r line; do
    \\        printf '%s\n' "$line"
    \\    done < "$inplace" > /var/lib/dpkg/diversions
    \\fi
    \\
;

const helper_script =
    \\if [ "$DPKG_MAINTSCRIPT_NAME" = preinst ] && [ -f /diversion-helper-record ]; then
    \\    { IFS= read -r source || exit 27; IFS= read -r destination || exit 27; } < /diversion-helper-record
    \\    /diversion-helper --local --no-rename --remove "$source" || exit 28
    \\    /diversion-helper --local --no-rename --divert "$destination" --add "$source" || exit 28
    \\fi
    \\
;

const backup_probe_script =
    \\if [ "$DPKG_MAINTSCRIPT_NAME" = preinst ] && [ "$1" = upgrade ]; then
    \\    /backup-probe-stat --printf='%d:%i\n' /usr/share/diversion-lifecycle/data /usr/share/diversion-lifecycle/current > /backup-before || exit 31
    \\fi
    \\if [ "$DPKG_MAINTSCRIPT_NAME" = postrm ] && [ "$1" = upgrade ]; then
    \\    { IFS= read -r original_data || exit 32; IFS= read -r original_symlink || exit 32; } < /backup-before
    \\    [ "$(/backup-probe-stat --printf='%d:%i' /usr/share/diversion-lifecycle/data.dpkg-tmp)" = "$original_data" ] || exit 33
    \\    [ "$(/backup-probe-stat --printf='%d:%i' /usr/share/diversion-lifecycle/data.link.dpkg-tmp)" = "$original_data" ] || exit 34
    \\    [ -L /usr/share/diversion-lifecycle/current.dpkg-tmp ] || exit 35
    \\    [ "$(/backup-probe-stat --printf='%d:%i' /usr/share/diversion-lifecycle/current.dpkg-tmp)" != "$original_symlink" ] || exit 36
    \\    [ "$(/backup-probe-stat --printf='%a:%u:%g:%Y' /usr/share/diversion-lifecycle/mode.distrib.dpkg-tmp)" = '600:0:0:1700000000' ] || exit 37
    \\    IFS= read -r previous < /usr/share/diversion-lifecycle/data.dpkg-tmp || exit 38
    \\    [ "$previous" = 'data version 1' ] || exit 39
    \\    [ ! -e /etc/debz-native.conf.dpkg-tmp ] || exit 40
    \\    [ -f /usr/share/diversion-lifecycle/obsolete ] || exit 42
    \\    IFS= read -r obsolete < /usr/share/diversion-lifecycle/obsolete || exit 43
    \\    [ "$obsolete" = 'only in 1' ] || exit 44
    \\    /backup-probe-rm -f /backup-before || exit 41
    \\fi
    \\
;

fn makePackage(f: *foundation.Fixture, arch: []const u8, workspace: []const u8, version: []const u8, backup: bool, directory: bool) ![]u8 {
    const extra = [_]foundation.Fixture.ExtraFile{
        .{ .path = "etc/diversion\\literal", .content = if (eq(version, "1")) "literal version 1\n" else "literal version 2\n" },
        .{ .path = base ++ "/tracked/child", .content = "tracked directory\n" },
    };
    const archive = try lifecycle.makePackage(f, arch, version, package, workspace, .{
        .conffile_content = if (eq(version, "1")) "configuration 1\n" else "configuration 2\n",
        .extra_files = if (directory and eq(version, "2")) &extra else extra[0..1],
        .full_payload = true,
    });
    const source = try std.fmt.allocPrint(f.allocator, "{s}/{s}_{s}_data.source", .{ workspace, package, version });
    defer f.allocator.free(source);
    const insertion = if (backup) mutation_script ++ helper_script ++ backup_probe_script else mutation_script ++ helper_script;
    try lifecycle.scriptsWith(f, source, package, version, .{ .before_failure = insertion });
    const output = try std.fmt.allocPrint(f.allocator, "{s}/{s}_{s}_data.deb", .{ workspace, package, version });
    defer f.allocator.free(output);
    const rebuilt = try f.buildPackage(source, output, .{});
    f.allocator.free(rebuilt);
    return archive;
}

fn makeHelperPackage(f: *foundation.Fixture, arch: []const u8, workspace: []const u8, root: []const u8) ![]u8 {
    const helper = try read(f, root, "usr/bin/dpkg-trigger", 8 * 1024 * 1024);
    defer f.allocator.free(helper);
    const extra = [_]foundation.Fixture.ExtraFile{.{ .path = "usr/bin/dpkg-trigger", .content = helper, .mode = 0o755 }};
    return lifecycle.makePackage(f, arch, "1", "diversion-helper-target", workspace, .{
        .extra_files = &extra,
        .no_scripts = true,
    });
}

fn invoke(f: *foundation.Fixture, driver: []const u8, root: []const u8, arch: []const u8, destination: []const u8, operation: []const u8, archive: ?[]const u8, crash: ?[]const u8) !?std.json.Parsed(Report) {
    return invokeWithMode(f, driver, root, arch, destination, operation, archive, crash, false);
}

fn invokeWithMode(f: *foundation.Fixture, driver: []const u8, root: []const u8, arch: []const u8, destination: []const u8, operation: []const u8, archive: ?[]const u8, crash: ?[]const u8, recovery_fault: bool) !?std.json.Parsed(Report) {
    var guarded = try foundation.guardedRoot(f.io, root);
    guarded.close(f.io);
    if (eq(operation, "recover") and (archive != null or (crash != null and !recovery_fault)))
        return error.RecoveryMustBePersistedOnly;
    if (recovery_fault and (!eq(operation, "recover") or crash == null or
        (!eq(crash.?, "during_known_unpack_rollback") and !eq(crash.?, "after_known_unpack_rollback"))))
        return error.InvalidRollbackCrashTransport;
    try f.directory(destination);
    const request_file = try lifecycle.path(f.allocator, destination, "request.json");
    defer f.allocator.free(request_file);
    const report_file = try lifecycle.path(f.allocator, destination, "report.json");
    defer f.allocator.free(report_file);
    try lifecycle.absent(f, report_file);
    const request_path = try f.absolute(request_file);
    defer f.allocator.free(request_path);
    const report_path = try f.absolute(report_file);
    defer f.allocator.free(report_path);
    const archives: []const []const u8 = if (archive) |path| &.{path} else &.{};
    const packages: []const foundation.PackageIdentity = if (eq(operation, "recover")) &.{} else &.{.{ .name = package, .architecture = arch }};
    const payload = try std.json.Stringify.valueAlloc(f.allocator, .{
        .root = root,
        .architecture = arch,
        .operation = operation,
        .archives = archives,
        .packages = packages,
        .report = report_path,
        .policy = "keep_existing",
        .triggers = true,
        .recovery = true,
        .caller_owned = true,
        .isolated_helper = true,
        .core_product = !recovery_fault,
        .crash_at = crash,
    }, .{});
    defer f.allocator.free(payload);
    try f.write(request_file, payload, 0o644);
    try f.environment.put("DEBZ_NATIVE_LIFECYCLE_REQUEST", request_path);
    const result = try std.process.run(f.allocator, f.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", driver },
        .environ_map = &f.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    });
    defer f.allocator.free(result.stdout);
    defer f.allocator.free(result.stderr);
    const log = try std.mem.concat(f.allocator, u8, &.{ result.stdout, result.stderr });
    defer f.allocator.free(log);
    const log_file = try lifecycle.path(f.allocator, destination, "native.log");
    defer f.allocator.free(log_file);
    try f.write(log_file, log, 0o644);
    if (result.term != .exited or result.term.exited != (if (crash != null) @as(u8, 86) else @as(u8, 0))) {
        std.debug.print("case {s}: native exit {any}; {s}/{s}\n{s}\n", .{ destination, result.term, f.path, log_file, log[log.len - @min(log.len, 12_000) ..] });
        return error.UnexpectedNativeProcessExit;
    }
    if (crash != null) {
        try lifecycle.absent(f, report_file);
        return null;
    }
    const bytes = try lifecycle.read(f, report_file, 64 * 1024);
    defer f.allocator.free(bytes);
    return try std.json.parseFromSlice(Report, f.allocator, bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = true });
}

fn reportExpected(maybe: ?std.json.Parsed(Report), outcome: []const u8) !std.json.Parsed(Report) {
    const report = maybe orelse return error.MissingRecoveryReport;
    errdefer {
        var invalid = report;
        invalid.deinit();
    }
    try same(report.value.outcome, outcome);
    return report;
}

fn mutate(f: *foundation.Fixture, root: []const u8, mutation: []const u8) !void {
    if (eq(mutation, "database-drift")) {
        const changed = try diversionRecords(f, "changed");
        defer f.allocator.free(changed);
        return seedRecord(f, root, "var/lib/dpkg/diversions", changed);
    }
    if (eq(mutation, "destination-drift"))
        return seedRecord(f, root, base ++ "/mode.distrib", "external destination drift\n");
    if (eq(mutation, "conffile-drift"))
        return seedRecord(f, root, "etc/debz-native.conf.distrib", "external conffile drift\n");
    const name: []const u8 = if (std.mem.startsWith(u8, mutation, "cache-") or eq(mutation, "backup-postrm-cache-drift"))
        diversion_cache
    else if (std.mem.startsWith(u8, mutation, "unpack-retained-")) blk: {
        var proof = try document(f, root, proof_path);
        defer proof.deinit();
        const evidence = try field(proof.value, "evidence_files");
        if (evidence != .array) return error.InvalidDiversionEvidence;
        for (evidence.array.items) |entry| {
            if (eq(try text(entry, "kind"), "unpack_diversion_cache"))
                break :blk try f.allocator.dupe(u8, try text(entry, "path"));
        }
        return error.MissingRetainedUnpackCache;
    } else if (std.mem.startsWith(u8, mutation, "unpack-cache-") or eq(mutation, "backup-settlement-input-drift"))
        try evidenceFile(f, root, "native-unpack-diversion-v1-")
    else if (std.mem.startsWith(u8, mutation, "backup-postrm-route-"))
        try evidenceFile(f, root, "native-unpack-route-settlement-v1-")
    else if (eq(mutation, "backup-postrm-directory-drift"))
        base ++ "/tracked/unrecorded"
    else if (eq(mutation, "backup-source-drift") or eq(mutation, "backup-postrm-payload-drift"))
        base ++ "/data"
    else
        base ++ "/data.dpkg-tmp";
    defer if (std.mem.startsWith(u8, mutation, "unpack-") or eq(mutation, "backup-settlement-input-drift") or std.mem.startsWith(u8, mutation, "backup-postrm-route-")) f.allocator.free(name);
    const path = try relative(f, root, name);
    defer f.allocator.free(path);
    if (!eq(mutation, "backup-postrm-directory-drift")) {
        const stat = try f.dir.statFile(f.io, path, .{ .follow_symlinks = false });
        if (stat.kind != .file) return error.NotRegularRecoveryEvidence;
    }
    if (std.mem.endsWith(u8, mutation, "-drift") and
        !std.mem.endsWith(u8, mutation, "-mode-drift") and
        !std.mem.endsWith(u8, mutation, "-missing-drift"))
    {
        try f.write(path, "external diversion recovery drift\n", 0o644);
    } else if (std.mem.endsWith(u8, mutation, "-mode-drift")) {
        try f.dir.setFilePermissions(f.io, path, .fromMode(if (std.mem.startsWith(u8, mutation, "backup-")) 0o600 else 0o644), .{});
    } else if (std.mem.endsWith(u8, mutation, "-missing-drift")) {
        try f.dir.deleteFile(f.io, path);
    } else return error.InvalidDiversionMutation;
}

fn checkBinding(f: *foundation.Fixture, root: []const u8, original: std.json.Value, intent: std.json.Value, report: Report, failed: bool) !void {
    var proof = try document(f, root, proof_path);
    defer proof.deinit();
    const attempt = try text(original, "attempt_id");
    try same(try text(intent, "attempt_id"), attempt);
    try same(report.attempt_id orelse return error.MissingReportBinding, attempt);
    try same(report.program_sha256 orelse return error.MissingReportBinding, try text(intent, "program_sha256"));
    try same(report.provenance_path orelse return error.MissingReportBinding, proof_path);
    try same(try text(proof.value, "outcome"), if (failed) "failed" else "succeeded");
    try same(try text(proof.value, "install_root"), root);
    try same(try text(proof.value, "attempt_id"), attempt);
    try same(try text(proof.value, "execution_intent_sha256"), try text(intent, "digest_sha256"));
    for ([_][]const u8{ "program_sha256", "root_identity_sha256", "authorization_sha256", "artifact_evidence_sha256" }) |key|
        try same(try text(proof.value, key), try text(intent, key));
    var completion = try document(f, root, completion_path);
    defer completion.deinit();
    try same(try text(completion.value, "outcome"), if (failed) "failed_after_mutation" else "succeeded");
    try same(try text(completion.value, "attempt_id"), attempt);
    const evidence = try field(proof.value, "evidence_files");
    if (evidence != .array) return error.MissingDiversionEvidence;
    var found = false;
    for (evidence.array.items) |entry| {
        if (eq(try text(entry, "kind"), "diversion_cache")) found = true;
    }
    if (!found) return error.MissingDiversionCacheBinding;
    var guard = try foundation.guardedRoot(f.io, root);
    defer guard.close(f.io);
    const raw = try read(f, root, proof_path, 16 * 1024 * 1024);
    defer f.allocator.free(raw);
    var decoded = try debz.native_provenance.decode(f.allocator, raw);
    defer decoded.deinit();
    try debz.native_provenance.verifyEvidence(f.allocator, .init(f.io, guard), decoded.document);
}

fn verifyRestoredBackupLink(f: *foundation.Fixture, root: []const u8) !void {
    var proof = try document(f, root, proof_path);
    defer proof.deinit();
    const evidence = try field(proof.value, "evidence_files");
    if (evidence != .array) return error.InvalidDiversionEvidence;
    for (evidence.array.items) |row| {
        if (!eq(try text(row, "kind"), "unpack_diversion_cache")) continue;
        var unpack = try document(f, root, try text(row, "path"));
        defer unpack.deinit();
        const backups = try field(unpack.value, "backups");
        if (backups != .array) return error.MissingActualUnpackBackups;
        for (backups.array.items) |backup| {
            if (!eq(try text(backup, "path"), base ++ "/current")) continue;
            const time = try field(backup, "backup_modified_nanoseconds");
            if (time != .integer or time.integer != try linkTime(f, root))
                return error.RolledBackLinkDoesNotMatchRetainedBackup;
            return;
        }
        return error.MissingRetainedBackupSymlink;
    }
    return error.MissingRetainedUnpackCache;
}

fn runCase(f: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, c: Case) !void {
    const name = try std.fmt.allocPrint(f.allocator, "diversion-{d:0>3}-{s}-{s}{s}{s}", .{
        c.number, c.operation, c.crash, if (c.mutation != null) "-" else "", c.mutation orelse "",
    });
    defer f.allocator.free(name);
    var scenario = try lifecycle.Scenario.init(f, name, driver, dpkg, arch, true);
    defer scenario.deinit();
    const backup = c.mutation != null and std.mem.startsWith(u8, c.mutation.?, "backup-");
    const directory = c.mutation != null and eq(c.mutation.?, "backup-postrm-directory-drift");
    const records = try diversionRecords(f, "distrib");
    defer f.allocator.free(records);
    for ([_][]const u8{ scenario.reference_root, scenario.native_root }) |root| {
        if (c.mutation == null or !eq(c.mutation.?, "created"))
            try seedRecord(f, root, "var/lib/dpkg/diversions", records);
        if (backup) {
            try lifecycle.copyProgram(f, root[f.path.len + 1 ..], "/usr/bin/stat", "/backup-probe-stat");
            try lifecycle.copyProgram(f, root[f.path.len + 1 ..], "/usr/bin/rm", "/backup-probe-rm");
        }
    }
    const receiver = try lifecycle.makePackage(f, arch, "1", "diversion-receiver", name, .{
        .declarations = if (c.mutation != null and (eq(c.mutation.?, "postinst") or eq(c.mutation.?, "atomic-then-inplace")))
            "interest-noawait /usr/share/diversion-lifecycle/mode.distrib\n" ++
                "interest-noawait /usr/share/diversion-lifecycle/mode.changed\n" ++
                "interest-noawait /usr/share/diversion-lifecycle/mode.atomic\n"
        else
            "interest-noawait /usr/share/diversion-lifecycle\n",
    });
    try scenario.seed(receiver);
    const target = try makeHelperPackage(f, arch, name, scenario.reference_root);
    try scenario.seed(target);
    const first = try makePackage(f, arch, name, "1", backup, directory);
    if (!eq(c.operation, "install")) try scenario.seed(first);
    if (eq(c.operation, "purge")) try scenario.phase(.{
        .operation = "remove",
        .packages = &.{.{ .name = package, .architecture = arch }},
        .triggers = true,
    }, false);
    const second = if (eq(c.operation, "upgrade")) try makePackage(f, arch, name, "2", backup, directory) else first;
    if (c.mutation) |mutation| for ([_][]const u8{ scenario.reference_root, scenario.native_root }) |root| {
        if (eq(mutation, "inplace") or eq(mutation, "inplace-unknown") or eq(mutation, "inplace-empty") or eq(mutation, "mid-cached-route") or
            eq(mutation, "inplace-prerm") or eq(mutation, "inplace-postrm") or eq(mutation, "atomic-then-inplace"))
        {
            const changed = try diversionRecords(f, "changed");
            defer f.allocator.free(changed);
            try seedRecord(f, root, if (eq(mutation, "inplace-prerm")) "diversion-prerm-inplace" else if (eq(mutation, "inplace-postrm")) "diversion-postrm-inplace" else if (eq(mutation, "atomic-then-inplace")) "diversion-postinst-inplace" else "diversion-preinst-inplace", if (eq(mutation, "inplace-empty")) "" else changed);
        }
        const kind: ?[]const u8 = if (eq(mutation, "preinst") or eq(mutation, "created") or eq(mutation, "atomic-then-inplace"))
            "preinst"
        else if (eq(mutation, "postinst"))
            "postinst"
        else if (eq(mutation, "mid-unpack") or eq(mutation, "mid-cached-route") or
            eq(mutation, "backup-probe-atomic") or eq(mutation, "backup-failure-atomic"))
            "postrm"
        else
            null;
        if (kind) |script| {
            try lifecycle.copyProgram(f, root[f.path.len + 1 ..], "/bin/mv", "/diversion-mv");
            const changed = try diversionRecords(f, if (eq(mutation, "atomic-then-inplace")) "atomic" else if (eq(mutation, "backup-probe-atomic") or eq(mutation, "backup-failure-atomic")) "distrib" else "changed");
            defer f.allocator.free(changed);
            const marker = try std.fmt.allocPrint(f.allocator, "diversion-{s}-replace", .{script});
            defer f.allocator.free(marker);
            try seedRecord(f, root, marker, changed);
        }
        if (eq(mutation, "helper")) {
            try lifecycle.copyProgram(f, root[f.path.len + 1 ..], "/usr/bin/dpkg-divert", "/diversion-helper");
            try seedRecord(f, root, "diversion-helper-record", "/" ++ base ++ "/mode\n/" ++ base ++ "/mode.changed\n");
        }
    };
    const backup_failure = c.mutation != null and std.mem.startsWith(u8, c.mutation.?, "backup-failure");
    const backup_unwind = c.mutation != null and eq(c.mutation.?, "backup-unwind");
    const failed = eq(c.crash, "after_failure_outcome") or backup_failure;
    if (failed) for ([_][]const u8{ scenario.reference_root, scenario.native_root }) |root|
        try seedRecord(f, root, lifecycle.failure, if (backup_failure)
            package ++ "@1:postrm:upgrade\n" ++ package ++ "@2:postrm:failed-upgrade\n"
        else
            package ++ "@1:postinst:configure\n");
    if (backup_unwind) for ([_][]const u8{ scenario.reference_root, scenario.native_root }) |root|
        try seedRecord(f, root, lifecycle.failure, package ++ "@1:postrm:upgrade\n");
    const original_time = if (backup_failure) try linkTime(f, scenario.reference_root) else @as(i128, 0);
    const helper = try read(f, scenario.native_root, "usr/bin/dpkg-trigger", 8 * 1024 * 1024);
    defer f.allocator.free(helper);
    const helper_file = try relative(f, scenario.native_root, "usr/bin/dpkg-trigger");
    defer f.allocator.free(helper_file);
    const helper_inode = (try f.dir.statFile(f.io, helper_file, .{ .follow_symlinks = false })).inode;
    const destination = try lifecycle.path(f.allocator, name, "operation");
    defer f.allocator.free(destination);
    try f.directory(destination);
    const phase: lifecycle.Phase = .{
        .operation = c.operation,
        .archives = if (eq(c.operation, "install") or eq(c.operation, "upgrade")) &.{second} else &.{},
        .packages = &.{.{ .name = package, .architecture = arch }},
        .triggers = true,
    };
    const inspect_unpack = backup and (eq(c.crash, "after_unpack_backups") or eq(c.crash, "after_unpack_payload") or
        eq(c.crash, "after_unpack_payload_commit") or eq(c.crash, "after_unpack_settlement_rollback"));
    const old_control = if (inspect_unpack) try read(f, scenario.native_root, "var/lib/dpkg/info/" ++ package ++ ".postrm", 64 * 1024) else null;
    defer if (old_control) |bytes| f.allocator.free(bytes);
    const started = std.Io.Clock.real.now(f.io).nanoseconds;
    const reference_status = try lifecycle.reference(f, dpkg, scenario.reference_root, phase, destination);
    if (reference_status != @as(u8, if (failed) 1 else 0)) return error.UnexpectedReferenceOutcome;
    const crash_dir = try lifecycle.path(f.allocator, name, "crash");
    defer f.allocator.free(crash_dir);
    _ = try invoke(f, driver, scenario.native_root, arch, crash_dir, c.operation, if (phase.archives.len == 1) second else null, c.crash);
    var original = try document(f, scenario.native_root, operation_path);
    defer original.deinit();
    var intent = try document(f, scenario.native_root, intent_path);
    defer intent.deinit();
    try same(try text(original.value, "backend"), "native");
    const committed_payload = if (backup and (eq(c.crash, "after_unpack_payload") or
        eq(c.crash, "during_unpack_settlement") or eq(c.crash, "after_unpack_settlement") or
        eq(c.crash, "after_unpack_payload_commit") or eq(c.crash, "after_unpack_settlement_commit") or
        eq(c.crash, "after_unpack_settlement_rollback")))
        try anchorPayload(f, scenario.native_root)
    else
        null;
    defer if (committed_payload) |anchor| anchor.deinit(f.allocator);
    if (inspect_unpack) {
        const unpack = try evidenceFile(f, scenario.native_root, "native-unpack-diversion-v1-");
        defer f.allocator.free(unpack);
        var envelope = try document(f, scenario.native_root, unpack);
        defer envelope.deinit();
        const backups = try field(envelope.value, "backups");
        if (backups != .array or backups.array.items.len == 0) return error.MissingActualUnpackBackups;
        const settlement = try field(envelope.value, "settlement");
        if (eq(c.crash, "after_unpack_backups")) {
            const backup_bytes = try read(f, scenario.native_root, base ++ "/data.dpkg-tmp", 128);
            defer f.allocator.free(backup_bytes);
            try same(backup_bytes, "data version 1\n");
        } else {
            const control = try read(f, scenario.native_root, "var/lib/dpkg/info/" ++ package ++ ".postrm", 64 * 1024);
            defer f.allocator.free(control);
            try same(control, old_control.?);
            const status = try read(f, scenario.native_root, "var/lib/dpkg/status", 16 * 1024 * 1024);
            defer f.allocator.free(status);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(status, &digest, .{});
            try same(&std.fmt.bytesToHex(digest, .lower), try text(settlement, "base_status_sha256"));
            const obsolete = try read(f, scenario.native_root, base ++ "/obsolete", 128);
            defer f.allocator.free(obsolete);
            try same(obsolete, "only in 1\n");
        }
    }
    if (backup and eq(c.crash, "after_upgrade_postrm_outcome")) {
        const route_path = try evidenceFile(f, scenario.native_root, "native-unpack-route-settlement-v1-");
        defer f.allocator.free(route_path);
        var route = try document(f, scenario.native_root, route_path);
        defer route.deinit();
        const unpack_path = try evidenceFile(f, scenario.native_root, "native-unpack-diversion-v1-");
        defer f.allocator.free(unpack_path);
        var unpack = try document(f, scenario.native_root, unpack_path);
        defer unpack.deinit();
        try same(try text(route.value, "intent_sha256"), try text(intent.value, "digest_sha256"));
        try same(try text(route.value, "unpack_input_sha256"), try text(unpack.value, "digest_sha256"));
        const routes = try field(route.value, "routes");
        if (routes != .array or routes.array.items.len == 0) return error.MissingActualRouteSettlement;
    }
    try f.dir.deleteFile(f.io, second[f.path.len + 1 ..]);
    if (eq(c.operation, "upgrade")) try f.dir.deleteFile(f.io, first[f.path.len + 1 ..]);
    try lifecycle.absent(f, second[f.path.len + 1 ..]);
    const interrupted_rollback = c.mutation != null and (std.mem.endsWith(u8, c.mutation.?, "-rollback-crash") or
        std.mem.endsWith(u8, c.mutation.?, "-rollback-finished"));
    if (interrupted_rollback) {
        const interrupted = try lifecycle.path(f.allocator, name, "interrupted-recovery");
        defer f.allocator.free(interrupted);
        const fault = if (std.mem.endsWith(u8, c.mutation.?, "-crash"))
            "during_known_unpack_rollback"
        else
            "after_known_unpack_rollback";
        _ = try invokeWithMode(f, driver, scenario.native_root, arch, interrupted, "recover", null, fault, true);
        var pending = try document(f, scenario.native_root, operation_path);
        defer pending.deinit();
        try same(try text(pending.value, "attempt_id"), try text(original.value, "attempt_id"));
    }
    if (c.mutation) |mutation| {
        if (std.mem.endsWith(u8, mutation, "-drift")) try mutate(f, scenario.native_root, mutation);
    }
    const before = try foundation.capture(f.allocator, f.io, scenario.native_root);
    defer f.allocator.free(before);
    const finish = try lifecycle.path(f.allocator, name, "fresh-recovery");
    defer f.allocator.free(finish);
    const recovered = try invoke(f, driver, scenario.native_root, arch, finish, "recover", null, null);
    const helper_after = try read(f, scenario.native_root, "usr/bin/dpkg-trigger", 8 * 1024 * 1024);
    defer f.allocator.free(helper_after);
    if (!eq(helper, helper_after) or helper_inode != (try f.dir.statFile(f.io, helper_file, .{ .follow_symlinks = false })).inode)
        return error.PackageOwnedHelperChanged;
    const unknown = c.mutation != null and (eq(c.mutation.?, "inplace-unknown") or eq(c.mutation.?, "backup-unknown"));
    if (unknown or (c.mutation != null and std.mem.endsWith(u8, c.mutation.?, "-drift"))) {
        var refused = recovered orelse return error.MissingRefusal;
        defer refused.deinit();
        if ((unknown and !eq(refused.value.outcome, "recovery_required")) or
            (!unknown and !eq(refused.value.outcome, "recovery_required") and !eq(refused.value.outcome, "refused")))
            return error.DriftAccepted;
        const after = try foundation.capture(f.allocator, f.io, scenario.native_root);
        defer f.allocator.free(after);
        if (!eq(before, after)) return error.RefusalMutatedPackageState;
        var still_active = try document(f, scenario.native_root, operation_path);
        defer still_active.deinit();
        try same(try text(still_active.value, "attempt_id"), try text(original.value, "attempt_id"));
        const repeat_dir = try lifecycle.path(f.allocator, name, "blocked-repeat");
        defer f.allocator.free(repeat_dir);
        const repeat = (try invoke(f, driver, scenario.native_root, arch, repeat_dir, "recover", null, null)) orelse return error.MissingRepeatedRefusal;
        var repeated = repeat;
        defer repeated.deinit();
        if (!eq(repeated.value.outcome, "recovery_required") and !eq(repeated.value.outcome, "refused"))
            return error.RepeatedRefusalAcceptedMutation;
        const replay = try foundation.capture(f.allocator, f.io, scenario.native_root);
        defer f.allocator.free(replay);
        if (!eq(before, replay)) return error.RepeatedRefusalMutatedPackageState;
        std.debug.print("{s}: exit-86, evicted archive, fresh and repeated refusal, unchanged package state\n", .{name});
        return;
    }
    var result = try reportExpected(recovered, if (failed) "script_failed" else "applied");
    defer result.deinit();
    if (committed_payload) |anchor| try checkPayload(f, scenario.native_root, anchor);
    const comparison = try lifecycle.path(f.allocator, name, "comparison");
    defer f.allocator.free(comparison);
    try f.directory(comparison);
    if (backup_failure) {
        const ended = std.Io.Clock.real.now(f.io).nanoseconds;
        try lifecycle.compareRollback(f, scenario.reference_root, scenario.native_root, comparison, &.{.{
            .path = base ++ "/current",
            .original = @intCast(original_time),
        }}, @intCast(started), @intCast(ended));
        for ([_][]const u8{ scenario.reference_root, scenario.native_root }) |root| {
            const time = try linkTime(f, root);
            if (time < started or time > ended) return error.RollbackSymlinkWasNotRecreated;
        }
    } else try lifecycle.compare(f, scenario.reference_root, scenario.native_root, comparison, true);
    try checkBinding(f, scenario.native_root, original.value, intent.value, result.value, failed);
    if (backup_failure) try verifyRestoredBackupLink(f, scenario.native_root);
    for ([_][]const u8{ operation_path, intent_path }) |active| {
        const path = try relative(f, scenario.native_root, active);
        defer f.allocator.free(path);
        try lifecycle.absent(f, path);
    }
    const proof_before = try read(f, scenario.native_root, proof_path, 16 * 1024 * 1024);
    defer f.allocator.free(proof_before);
    const completion_before = try read(f, scenario.native_root, completion_path, 16 * 1024 * 1024);
    defer f.allocator.free(completion_before);
    const settled = try foundation.capture(f.allocator, f.io, scenario.native_root);
    defer f.allocator.free(settled);
    const repeat_dir = try lifecycle.path(f.allocator, name, "repeat");
    defer f.allocator.free(repeat_dir);
    var repeated = try reportExpected(try invoke(f, driver, scenario.native_root, arch, repeat_dir, "recover", null, null), "applied");
    defer repeated.deinit();
    const repeat = try foundation.capture(f.allocator, f.io, scenario.native_root);
    defer f.allocator.free(repeat);
    if (!eq(settled, repeat)) return error.RepeatedRecoveryChangedRoot;
    const proof_after = try read(f, scenario.native_root, proof_path, 16 * 1024 * 1024);
    defer f.allocator.free(proof_after);
    const completion_after = try read(f, scenario.native_root, completion_path, 16 * 1024 * 1024);
    defer f.allocator.free(completion_after);
    if (!eq(proof_before, proof_after) or !eq(completion_before, completion_after))
        return error.RepeatedRecoveryChangedReceipt;
    std.debug.print("{s}: exit-86, evicted archive, {s} recovery, pinned-dpkg parity and immutable replay\n", .{ name, result.value.outcome });
}

pub fn main(init: std.process.Init) !void {
    const a = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    var pinned: ?[]const u8 = null;
    var selected: ?u8 = null;
    while (args.next()) |option| {
        if (eq(option, "--case")) {
            if (selected != null) return error.DuplicateCase;
            selected = try std.fmt.parseInt(u8, args.next() orelse return error.MissingCase, 10);
        } else if (eq(option, "--reference-dpkg")) {
            if (pinned != null) return error.DuplicateReference;
            pinned = args.next() orelse return error.MissingPinnedDpkg;
        } else return error.InvalidArguments;
    }
    const reference = try lifecycle.prerequisites(init, a, pinned orelse return error.PinnedDpkgRequired);
    var fixture = try foundation.Fixture.init(a, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer lifecycle.assertHostUnchanged(a, init.io, reference.before) catch |err|
        std.debug.print("host dpkg status changed: {s}\n", .{@errorName(err)});
    var executed: usize = 0;
    for (cases) |c| {
        if (selected != null and selected.? != c.number) continue;
        runCase(&fixture, driver, reference.executable, reference.architecture, c) catch |err| {
            std.debug.print("Python diversion recovery case {d} failed: {s}\n", .{ c.number, @errorName(err) });
            return err;
        };
        executed += 1;
    }
    if (executed != (if (selected != null) @as(usize, 1) else cases.len)) return error.DiversionCaseAccountingMismatch;
    try lifecycle.assertHostUnchanged(a, init.io, reference.before);
    std.debug.print("diversion recovery: {d}/{d} declared real crash cases executed against pinned dpkg\n", .{ executed, if (selected != null) @as(usize, 1) else cases.len });
}
