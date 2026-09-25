const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

fn value(fixture: *foundation.Fixture, relative: []const u8) !std.json.Parsed(std.json.Value) {
    const content = try support.read(fixture, relative, 64 * 1024);
    defer fixture.allocator.free(content);
    return std.json.parseFromSlice(std.json.Value, fixture.allocator, content, .{ .allocate = .alloc_always });
}

fn field(document: std.json.Value, name: []const u8) ![]const u8 {
    const found = document.object.get(name) orelse return error.MissingRecoveryField;
    if (found != .string) return error.WrongRecoveryField;
    return found.string;
}

fn status(fixture: *foundation.Fixture, root: []const u8) ![]u8 {
    const path = try support.path(fixture.allocator, root, "var/lib/dpkg/status");
    defer fixture.allocator.free(path);
    return support.read(fixture, path, 64 * 1024 * 1024);
}

fn trace(fixture: *foundation.Fixture, root: []const u8) ![]u8 {
    const path = try support.path(fixture.allocator, root, support.trace);
    defer fixture.allocator.free(path);
    return support.read(fixture, path, 16 * 1024 * 1024);
}

fn stagingRefusals(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const source = "packages/staging-negative/retained-metadata_1_data.source";
    const initial = try support.makePackage(fixture, arch, "1", "retained-metadata", "packages/staging-negative", .{});
    defer fixture.allocator.free(initial);
    try fixture.write(source ++ "/DEBIAN/config", "#!/bin/sh\nexit 97\n", 0o755);
    const metadata_archive = try fixture.buildPackage(source, "packages/staging-negative/retained-metadata_1_data.deb", .{});
    defer fixture.allocator.free(metadata_archive);
    const chosen = [_]foundation.PackageIdentity{.{ .name = "retained-metadata", .architecture = arch }};
    for ([_][]const u8{ "empty-directory", "occupied-directory", "file", "symlink" }) |collision| {
        const label = try std.fmt.allocPrint(fixture.allocator, "config-staging-collision-{s}", .{collision});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/native/var/lib/dpkg/tmp.ci", .{label});
        defer fixture.allocator.free(relative);
        if (std.mem.endsWith(u8, collision, "directory")) {
            try fixture.directory(relative);
            if (std.mem.eql(u8, collision, "occupied-directory"))
                try support.fixtureFile(fixture, try support.path(fixture.allocator, relative, "other"), "ambient control state\n", 0o644);
        } else if (std.mem.eql(u8, collision, "file")) {
            try support.fixtureFile(fixture, relative, "not a directory\n", 0o644);
        } else try fixture.dir.symLink(fixture.io, "info", relative, .{});
        const before = try fixture.dir.statFile(fixture.io, relative, .{ .follow_symlinks = false });
        const before_status = try status(fixture, try support.path(fixture.allocator, label, "native"));
        defer fixture.allocator.free(before_status);
        const before_trace = try trace(fixture, try support.path(fixture.allocator, label, "native"));
        defer fixture.allocator.free(before_trace);
        const destination = try support.path(fixture.allocator, label, "refusal");
        defer fixture.allocator.free(destination);
        try fixture.directory(destination);
        var result = try support.native(fixture, driver, case.native_root, arch, .{
            .operation = "install",
            .archives = &.{metadata_archive},
            .packages = &chosen,
        }, destination);
        defer result.deinit();
        if (!std.mem.eql(u8, result.value.outcome, "refused") or
            !std.mem.eql(u8, result.value.detail, "config_staging_collision"))
            return error.UnexpectedStagingRefusal;
        const after = try fixture.dir.statFile(fixture.io, relative, .{ .follow_symlinks = false });
        if (!std.meta.eql(before, after)) return error.StagingCollisionChanged;
        const after_status = try status(fixture, try support.path(fixture.allocator, label, "native"));
        defer fixture.allocator.free(after_status);
        const after_trace = try trace(fixture, try support.path(fixture.allocator, label, "native"));
        defer fixture.allocator.free(after_trace);
        if (!std.mem.eql(u8, before_status, after_status) or !std.mem.eql(u8, before_trace, after_trace))
            return error.RefusalChangedRoot;
        try support.assertNoActiveEvidence(fixture, case.native_root);
    }
}

fn scriptFaults(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first = try support.makePackage(fixture, arch, "1", foundation.package, "packages/fault", .{});
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, arch, "2", foundation.package, "packages/fault", .{});
    defer fixture.allocator.free(second);
    const chosen = [_]foundation.PackageIdentity{.{ .name = foundation.package, .architecture = arch }};
    for ([_]struct {
        label: []const u8,
        operation: []const u8,
        version: []const u8,
        fault: []const u8,
        kind: []const u8,
        source: []const u8,
        expected_argument: []const u8,
        trace_count: usize,
    }{
        .{ .label = "script-outcome-unknown", .operation = "install", .version = "1", .fault = "after_script_before_record", .kind = "preinst", .source = "new_package", .expected_argument = "install", .trace_count = 1 },
        .{ .label = "upgrade-postrm-outcome-unknown", .operation = "upgrade", .version = "2", .fault = "after_upgrade_postrm_before_record", .kind = "postrm", .source = "installed_package", .expected_argument = "upgrade", .trace_count = 3 },
    }) |entry| {
        var case = try support.Scenario.init(fixture, entry.label, driver, dpkg, arch, false);
        defer case.deinit();
        if (std.mem.eql(u8, entry.operation, "upgrade")) try case.seed(first);
        const destination = try support.path(fixture.allocator, entry.label, "interrupted");
        defer fixture.allocator.free(destination);
        try fixture.directory(destination);
        var report = try support.native(fixture, driver, case.native_root, arch, .{
            .operation = entry.operation,
            .archives = &.{if (std.mem.eql(u8, entry.version, "1")) first else second},
            .packages = &chosen,
            .fault = entry.fault,
        }, destination);
        defer report.deinit();
        if (!std.mem.eql(u8, report.value.outcome, "recovery_required")) return error.FaultDidNotRequireRecovery;
        const root_relative = try support.path(fixture.allocator, entry.label, "native");
        defer fixture.allocator.free(root_relative);
        const operation_path = try support.path(fixture.allocator, root_relative, "var/lib/debz/root-operation-v1.json");
        defer fixture.allocator.free(operation_path);
        const script_path = try support.path(fixture.allocator, root_relative, "var/lib/debz/native-lifecycle-script-v1.json");
        defer fixture.allocator.free(script_path);
        const record_bytes = try support.read(fixture, operation_path, 64 * 1024);
        defer fixture.allocator.free(record_bytes);
        const script_bytes = try support.read(fixture, script_path, 64 * 1024);
        defer fixture.allocator.free(script_bytes);
        var operation_record = try value(fixture, operation_path);
        defer operation_record.deinit();
        var script_record = try value(fixture, script_path);
        defer script_record.deinit();
        if (!std.mem.eql(u8, try field(operation_record.value, "state"), "recovery_required") or
            !std.mem.eql(u8, try field(operation_record.value, "phase"), "script") or
            !std.mem.eql(u8, try field(operation_record.value, "backend"), "native") or
            !std.mem.eql(u8, try field(operation_record.value, "install_root"), case.native_root) or
            operation_record.value.object.get("mutation_started").? != .bool or
            !operation_record.value.object.get("mutation_started").?.bool)
            return error.InvalidRecoveryBinding;
        const digest = try field(operation_record.value, "program_sha256");
        if (digest.len != 64 or std.mem.allEqual(u8, digest, '0')) return error.InvalidRecoveryBinding;
        for (digest) |digit| if (!std.ascii.isDigit(digit) and (digit < 'a' or digit > 'f')) return error.InvalidRecoveryBinding;
        if (!std.mem.eql(u8, try field(script_record.value, "program_sha256"), digest) or
            !std.mem.eql(u8, try field(script_record.value, "package"), foundation.package) or
            !std.mem.eql(u8, try field(script_record.value, "version"), "1") or
            !std.mem.eql(u8, try field(script_record.value, "architecture"), arch) or
            !std.mem.eql(u8, try field(script_record.value, "kind"), entry.kind) or
            !std.mem.eql(u8, try field(script_record.value, "source"), entry.source) or
            !std.mem.eql(u8, try field(script_record.value, "outcome"), "in_flight") or
            script_record.value.object.get("exit_code").? != .null)
            return error.InvalidScriptBinding;
        const arguments = script_record.value.object.get("arguments") orelse return error.InvalidScriptBinding;
        if (arguments != .array or arguments.array.items.len != (if (std.mem.eql(u8, entry.operation, "install")) @as(usize, 1) else 2) or
            !std.mem.eql(u8, arguments.array.items[0].string, entry.expected_argument) or
            (arguments.array.items.len == 2 and !std.mem.eql(u8, arguments.array.items[1].string, "2")))
            return error.InvalidScriptBinding;
        const script_source = try std.fmt.allocPrint(fixture.allocator, "packages/fault/{s}_1_data.source/DEBIAN/{s}", .{ foundation.package, entry.kind });
        defer fixture.allocator.free(script_source);
        const script_body = try support.read(fixture, script_source, 64 * 1024);
        defer fixture.allocator.free(script_body);
        var hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(script_body, &hash, .{});
        if (!std.mem.eql(u8, try field(script_record.value, "script_sha256"), &std.fmt.bytesToHex(hash, .lower)))
            return error.InvalidScriptBinding;
        const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(before);
        const observed = try trace(fixture, root_relative);
        defer fixture.allocator.free(observed);
        if (std.mem.count(u8, observed, "\n") != entry.trace_count) return error.FaultDidNotReachScript;
        for ([_][]const u8{ "same-operation", "absent-purge" }) |retry| {
            const next = try support.path(fixture.allocator, entry.label, retry);
            defer fixture.allocator.free(next);
            try fixture.directory(next);
            const absent = [_]foundation.PackageIdentity{.{ .name = "debz-lifecycle-absent", .architecture = arch }};
            var blocked = try support.native(fixture, driver, case.native_root, arch, .{
                .operation = if (std.mem.eql(u8, retry, "same-operation")) entry.operation else "purge",
                .archives = if (std.mem.eql(u8, retry, "same-operation")) &.{if (std.mem.eql(u8, entry.version, "1")) first else second} else &.{},
                .packages = if (std.mem.eql(u8, retry, "same-operation")) &chosen else &absent,
            }, next);
            defer blocked.deinit();
            if (!std.mem.eql(u8, blocked.value.outcome, "recovery_required")) return error.ReentryWasNotBlocked;
            const next_record = try support.read(fixture, operation_path, 64 * 1024);
            defer fixture.allocator.free(next_record);
            const next_script = try support.read(fixture, script_path, 64 * 1024);
            defer fixture.allocator.free(next_script);
            const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
            defer fixture.allocator.free(after);
            if (!std.mem.eql(u8, record_bytes, next_record) or !std.mem.eql(u8, script_bytes, next_script) or
                !std.mem.eql(u8, before, after)) return error.ReentryChangedRoot;
        }
    }
}

fn unexpectedClosure(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const unrelated = "debz-lifecycle-unrelated";
    const seed_archive = try support.makePackage(fixture, arch, "1", unrelated, "packages/unrelated", .{ .no_scripts = true });
    defer fixture.allocator.free(seed_archive);
    const initial = try support.makePackage(fixture, arch, "1", foundation.package, "packages/changed-database", .{});
    defer fixture.allocator.free(initial);
    const source = "packages/changed-database/" ++ foundation.package ++ "_1_data.source";
    const postinst = source ++ "/DEBIAN/postinst";
    const original = try support.read(fixture, postinst, 64 * 1024);
    defer fixture.allocator.free(original);
    if (!std.mem.endsWith(u8, original, "exit 0\n")) return error.InvalidFixtureScript;
    const mutation =
        \\status=''
        \\selected=no
        \\while IFS= read -r line; do
        \\    case "$line" in
        \\        'Package: debz-lifecycle-unrelated') selected=yes ;;
        \\        'Package: '*) selected=no ;;
        \\    esac
        \\    if [ "$selected" = yes ] && [ "$line" = 'Version: 1' ]; then
        \\        line='Version: 9'
        \\    fi
        \\    status="$status$line
        \\"
        \\done < /var/lib/dpkg/status
        \\printf '%s' "$status" > /var/lib/dpkg/status
        \\exit 0
        \\
    ;
    const body = try std.mem.concat(fixture.allocator, u8, &.{ original[0 .. original.len - "exit 0\n".len], mutation });
    defer fixture.allocator.free(body);
    try fixture.write(postinst, body, 0o755);
    const modified = try fixture.buildPackage(source, "packages/changed-database/" ++ foundation.package ++ "_1_data.deb", .{});
    defer fixture.allocator.free(modified);
    var case = try support.Scenario.init(fixture, "unexpected-final-package-version", driver, dpkg, arch, false);
    defer case.deinit();
    try case.seed(seed_archive);
    const output = "unexpected-final-package-version/install";
    try fixture.directory(output);
    const chosen = [_]foundation.PackageIdentity{.{ .name = foundation.package, .architecture = arch }};
    var report = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "install",
        .archives = &.{modified},
        .packages = &chosen,
    }, output);
    defer report.deinit();
    if (!std.mem.eql(u8, report.value.outcome, "recovery_required")) return error.ClosureWasAccepted;
    const record_path = "unexpected-final-package-version/native/var/lib/debz/root-operation-v1.json";
    var record = try value(fixture, record_path);
    defer record.deinit();
    if (!std.mem.eql(u8, try field(record.value, "state"), "recovery_required") or
        !std.mem.eql(u8, try field(record.value, "phase"), "verification"))
        return error.InvalidClosureEvidence;
    const status_text = try status(fixture, "unexpected-final-package-version/native");
    defer fixture.allocator.free(status_text);
    if (std.mem.indexOf(u8, status_text, "Version: 9\n") == null) return error.ScriptDidNotChangeStatus;
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    try stagingRefusals(fixture, driver, dpkg, arch);
    try scriptFaults(fixture, driver, dpkg, arch);
    try unexpectedClosure(fixture, driver, dpkg, arch);
}
