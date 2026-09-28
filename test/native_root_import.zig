const std = @import("std");
const native_alternatives = @import("debz").native_alternatives;
const native_provenance = @import("debz").native_provenance;
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");

const keeper = "import-keeper";
const incoming = "import-incoming";
const admin = "var/lib/dpkg/";

fn rootFile(fixture: *foundation.Fixture, root: []const u8, path: []const u8) ![]u8 {
    const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}", .{
        root[fixture.path.len + 1 ..], path,
    });
    defer fixture.allocator.free(relative);
    return support.read(fixture, relative, 64 * 1024 * 1024);
}

fn assertFile(fixture: *foundation.Fixture, root: []const u8, path: []const u8, expected: []const u8) !void {
    const bytes = try rootFile(fixture, root, path);
    defer fixture.allocator.free(bytes);
    if (!std.mem.eql(u8, expected, bytes)) return error.ImportChangedPreexistingFile;
}

fn cloneRoot(fixture: *foundation.Fixture, source: []const u8, name: []const u8, architecture: []const u8) ![]u8 {
    const target = try fixture.makeRoot(name, architecture);
    errdefer fixture.allocator.free(target);
    const contents = try std.fmt.allocPrint(fixture.allocator, "{s}/.", .{source});
    defer fixture.allocator.free(contents);
    const log = try std.fmt.allocPrint(fixture.allocator, "{s}-copy.log", .{name});
    defer fixture.allocator.free(log);
    try fixture.run(&.{ "/bin/cp", "-a", "--", contents, target }, log, 30);
    var guard = try foundation.guardedRoot(fixture.io, target);
    guard.close(fixture.io);
    return target;
}

fn checkProvenance(fixture: *foundation.Fixture, root: []const u8) !void {
    var directory = try foundation.guardedRoot(fixture.io, root);
    defer directory.close(fixture.io);
    const selected: root_fs.Root = .init(fixture.io, directory);
    var receipt = try native_provenance.read(fixture.allocator, selected) orelse
        return error.ImportProvenanceMissing;
    defer receipt.deinit();
    const document = receipt.document;
    if (document.outcome != .succeeded or document.evidence_files.len == 0 or
        std.mem.allEqual(u8, &document.initial_database_generation_sha256, '0') or
        std.mem.eql(u8, &document.initial_database_generation_sha256, &document.final_database_generation_sha256))
        return error.ImportProvenanceMissing;
    try native_provenance.verifyEvidence(fixture.allocator, selected, document);
}

fn refusal(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    architecture: []const u8,
    archive: []const u8,
    label: []const u8,
    detail: []const u8,
) !void {
    const before = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(before);
    const destination = try std.fmt.allocPrint(fixture.allocator, "{s}-result", .{label});
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    const selected = [_]foundation.PackageIdentity{.{ .name = incoming, .architecture = architecture }};
    for (0..2) |retry| {
        const output = try std.fmt.allocPrint(fixture.allocator, "{s}/{d}", .{ destination, retry });
        defer fixture.allocator.free(output);
        try fixture.directory(output);
        var report = try support.native(fixture, driver, root, architecture, .{
            .operation = "install",
            .archives = &.{archive},
            .packages = &selected,
            .triggers = true,
        }, output);
        defer report.deinit();
        if (!std.mem.eql(u8, report.value.outcome, "refused") or
            !std.mem.eql(u8, report.value.detail, detail))
        {
            std.debug.print("{s}: expected refusal {s}, got {s}: {s}\n", .{
                label, detail, report.value.outcome, report.value.detail,
            });
            return error.ImportRefusalMismatch;
        }
        const after = try foundation.capture(fixture.allocator, fixture.io, root);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.ImportRefusalChangedRoot;
        try support.assertNoActiveEvidence(fixture, root);
    }
}

fn externalDrift(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    architecture: []const u8,
    archive: []const u8,
    label: []const u8,
    drift: support.ImportDrift,
) !void {
    const path = if (drift == .status_mode)
        admin ++ "status"
    else
        admin ++ "info/" ++ keeper ++ ".postinst";
    const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}", .{
        label, path,
    });
    defer fixture.allocator.free(relative);
    const original_mode: u32 = if (drift == .status_mode) 0o644 else 0o755;
    const changed_mode: u32 = if (drift == .status_mode) 0o600 else 0o700;
    try fixture.dir.setFilePermissions(fixture.io, relative, .fromMode(changed_mode), .{});
    const externally_changed = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(externally_changed);
    try fixture.dir.setFilePermissions(fixture.io, relative, .fromMode(original_mode), .{});

    const destination = try std.fmt.allocPrint(fixture.allocator, "{s}-result", .{label});
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    const selected = [_]foundation.PackageIdentity{.{ .name = incoming, .architecture = architecture }};
    var report = try support.native(fixture, driver, root, architecture, .{
        .operation = "install",
        .archives = &.{archive},
        .packages = &selected,
        .triggers = true,
        .fixture_import_drift = drift,
    }, destination);
    defer report.deinit();
    if (!std.mem.eql(u8, report.value.outcome, "refused") or
        !std.mem.eql(u8, report.value.detail, "database_generation_drift"))
    {
        std.debug.print("{s}: expected generation refusal, got {s}: {s}\n", .{
            label, report.value.outcome, report.value.detail,
        });
        return error.ImportDriftWasAccepted;
    }
    const after = try foundation.capture(fixture.allocator, fixture.io, root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, externally_changed, after))
        return error.ImportDriftChangedRoot;
    try support.assertNoActiveEvidence(fixture, root);
}

fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, architecture: []const u8) !void {
    const original = try support.makePackage(fixture, architecture, "1", keeper, "packages/root-import", .{
        .conffile_content = "keeper configuration\n",
        .declarations = "interest-noawait /usr/share/import-incoming\n",
    });
    defer fixture.allocator.free(original);
    const archive = try support.makePackage(fixture, architecture, "1", incoming, "packages/root-import", .{});
    defer fixture.allocator.free(archive);
    var scenario = try support.Scenario.init(fixture, "healthy-import", driver, dpkg, architecture, true);
    defer scenario.deinit();
    try scenario.seed(original);
    const alternative_record = try native_alternatives.canonicalBytes(fixture.allocator, .{
        .name = "import-tool",
        .mode = .auto,
        .master_link = "/usr/bin/import-tool",
        .slaves = &.{},
        .candidates = &.{.{
            .path = "/usr/share/import-keeper/data",
            .priority = 10,
            .targets = &.{},
        }},
    });
    defer fixture.allocator.free(alternative_record);
    for ([_][]const u8{ "reference", "native" }) |side| {
        const prefix = try support.path(fixture.allocator, scenario.name, side);
        defer fixture.allocator.free(prefix);
        const alternatives = try support.path(fixture.allocator, prefix, admin ++ "alternatives");
        defer fixture.allocator.free(alternatives);
        try fixture.directory(alternatives);
        const selector_dir = try support.path(fixture.allocator, prefix, "etc/alternatives");
        defer fixture.allocator.free(selector_dir);
        try fixture.directory(selector_dir);
        for ([_]struct { path: []const u8, bytes: []const u8 }{
            .{ .path = admin ++ "available", .bytes = "" },
            .{ .path = admin ++ "diversions", .bytes = "/opt/import-unused\n/opt/import-unused.distrib\n:\n" },
            .{ .path = admin ++ "statoverride", .bytes = "#0 #0 0644 /usr/share/import-keeper/data\n" },
            .{ .path = admin ++ "alternatives/import-tool", .bytes = alternative_record },
        }) |entry| {
            const path = try support.path(fixture.allocator, prefix, entry.path);
            defer fixture.allocator.free(path);
            try support.fixtureFile(fixture, path, entry.bytes, 0o644);
        }
        var guarded = try foundation.guardedRoot(fixture.io, if (std.mem.eql(u8, side, "reference"))
            scenario.reference_root
        else
            scenario.native_root);
        defer guarded.close(fixture.io);
        const root: root_fs.Root = .init(fixture.io, guarded);
        for ([_]struct { path: []const u8, target: []const u8 }{
            .{ .path = "etc/alternatives/import-tool", .target = "/usr/share/import-keeper/data" },
            .{ .path = "usr/bin/import-tool", .target = "/etc/alternatives/import-tool" },
        }) |link| {
            const path = try root_fs.Path.init(link.path);
            try root.createSymbolicLink(path, link.target);
            try root.applyMetadata(path, .{ .modified_nanoseconds = foundation.epoch * std.time.ns_per_s });
        }
    }
    try fixture.directory("healthy-import/baseline");
    try support.compare(fixture, scenario.reference_root, scenario.native_root, "healthy-import/baseline", true);
    const status_before = try rootFile(fixture, scenario.native_root, admin ++ "status");
    defer fixture.allocator.free(status_before);
    if (std.mem.indexOf(u8, status_before, "Package: " ++ keeper ++ "\n") == null)
        return error.ImportPrestateMissing;
    const preserved = [_][]const u8{
        admin ++ "info/" ++ keeper ++ ".list",
        admin ++ "info/" ++ keeper ++ ".md5sums",
        admin ++ "info/" ++ keeper ++ ".conffiles",
        admin ++ "info/" ++ keeper ++ ".triggers",
        admin ++ "info/" ++ keeper ++ ".postinst",
        admin ++ "available",
        admin ++ "diversions",
        admin ++ "statoverride",
        admin ++ "alternatives/import-tool",
        "etc/debz-native.conf",
    };
    var originals: [preserved.len][]u8 = undefined;
    for (preserved, 0..) |path, index| {
        originals[index] = try rootFile(fixture, scenario.native_root, path);
    }
    defer for (originals) |bytes| fixture.allocator.free(bytes);

    const corrupt = try cloneRoot(fixture, scenario.native_root, "corrupt-import", architecture);
    defer fixture.allocator.free(corrupt);
    const ambiguous = try cloneRoot(fixture, scenario.native_root, "ambiguous-import", architecture);
    defer fixture.allocator.free(ambiguous);
    const unsupported = try cloneRoot(fixture, scenario.native_root, "unsupported-import", architecture);
    defer fixture.allocator.free(unsupported);
    const unsafe = try cloneRoot(fixture, scenario.native_root, "unsafe-import", architecture);
    defer fixture.allocator.free(unsafe);
    const updates = try cloneRoot(fixture, scenario.native_root, "updates-import", architecture);
    defer fixture.allocator.free(updates);
    const staging = try cloneRoot(fixture, scenario.native_root, "staging-import", architecture);
    defer fixture.allocator.free(staging);
    const status_drift = try cloneRoot(fixture, scenario.native_root, "status-drift-import", architecture);
    defer fixture.allocator.free(status_drift);
    const script_drift = try cloneRoot(fixture, scenario.native_root, "script-drift-import", architecture);
    defer fixture.allocator.free(script_drift);

    const chosen = [_]foundation.PackageIdentity{.{ .name = incoming, .architecture = architecture }};
    try scenario.phase(.{
        .operation = "install",
        .archives = &.{archive},
        .packages = &chosen,
        .triggers = true,
        .recovery = true,
    }, false);
    const status_after = try rootFile(fixture, scenario.native_root, admin ++ "status");
    defer fixture.allocator.free(status_after);
    if (std.mem.indexOf(u8, status_after, "Package: " ++ keeper ++ "\n") == null or
        std.mem.indexOf(u8, status_after, "Package: " ++ incoming ++ "\n") == null)
        return error.ImportLostPackage;
    for (preserved, originals) |path, bytes|
        try assertFile(fixture, scenario.native_root, path, bytes);
    const trace = try rootFile(fixture, scenario.native_root, support.trace);
    defer fixture.allocator.free(trace);
    if (std.mem.indexOf(u8, trace, keeper ++ "@1:postinst\t") == null or
        std.mem.indexOf(u8, trace, "\t9:triggered\t") == null or
        std.mem.indexOf(u8, trace, incoming ++ "@1:postinst\t") == null or
        std.mem.indexOf(u8, trace, "\t9:configure\t") == null)
        return error.ImportTriggerOrScriptMissing;
    try checkProvenance(fixture, scenario.native_root);

    const invalid_status = try std.mem.replaceOwned(u8, fixture.allocator, status_before, "Status: install ok installed", "Status: install ok mystery");
    defer fixture.allocator.free(invalid_status);
    try fixture.write("corrupt-import/" ++ admin ++ "status", invalid_status, 0o644);
    try refusal(fixture, driver, corrupt, architecture, archive, "corrupt-import", "invalid_state");

    const repeated = try std.mem.concat(fixture.allocator, u8, &.{ status_before, status_before });
    defer fixture.allocator.free(repeated);
    try fixture.write("ambiguous-import/" ++ admin ++ "status", repeated, 0o644);
    try refusal(fixture, driver, ambiguous, architecture, archive, "ambiguous-import", "repeated_identity");

    try fixture.write("unsupported-import/" ++ admin ++ "future-feature", "unknown metadata\n", 0o644);
    try refusal(fixture, driver, unsupported, architecture, archive, "unsupported-import", "UnsupportedDatabaseEntry");

    try fixture.write("unsafe-import/" ++ admin ++ "status", status_before, 0o666);
    try refusal(fixture, driver, unsafe, architecture, archive, "unsafe-import", "UnsafeDatabaseEntry");

    try fixture.write("updates-import/" ++ admin ++ "updates/0000", status_before, 0o644);
    try refusal(fixture, driver, updates, architecture, archive, "updates-import", "update_fragments_present");
    try fixture.write("staging-import/" ++ admin ++ "tmp.ci/ambient", "incomplete staging\n", 0o644);
    try refusal(fixture, driver, staging, architecture, archive, "staging-import", "config_staging_collision");
    try externalDrift(fixture, driver, status_drift, architecture, archive, "status-drift-import", .status_mode);
    try externalDrift(fixture, driver, script_drift, architecture, archive, "script-drift-import", .installed_script_mode);
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const driver = args.next() orelse return error.MissingNativeDriver;
    if (!std.mem.eql(u8, args.next() orelse return error.PinnedReferenceRequired, "--reference-dpkg"))
        return error.PinnedReferenceRequired;
    const pinned = args.next() orelse return error.PinnedReferenceRequired;
    if (args.next() != null) return error.InvalidArguments;
    const prerequisite = try support.prerequisites(init, allocator, pinned);
    defer allocator.free(prerequisite.architecture);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    try run(&fixture, driver, prerequisite.executable, prerequisite.architecture);
    try support.assertHostUnchanged(allocator, init.io, prerequisite.before);
}
