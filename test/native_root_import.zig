const std = @import("std");
const native_alternatives = @import("debz").native_alternatives;
const native_provenance = @import("debz").native_provenance;
const root_fs = @import("debz").root_fs;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const dpkg_query = @import("native_dpkg_query.zig");
const options = @import("native_test_options");

const keeper = "import-keeper";
const incoming = "import-incoming";
const admin = "var/lib/dpkg/";
const arch_native_writer = "import-arch-native";
const arch_native = admin ++ "arch-native";

/// dpkg 1.23.7 `debian/dpkg.postinst` writes the admin directory's native
/// architecture from configure with exactly this function.
const dpkg_create_db_native_arch =
    \\create_db_native_arch()
    \\{
    \\  local admindir="${DPKG_ADMINDIR:-/var/lib/dpkg}"
    \\
    \\  echo "$DPKG_MAINTSCRIPT_ARCH" >"$admindir/arch-native"
    \\}
    \\if [ "$1" = configure ]; then
    \\  create_db_native_arch
    \\fi
    \\
;

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
    try dpkg_query.observeRefusedImport(fixture, dpkg, architecture, corrupt, "corrupt-import", null);
    try refusal(fixture, driver, corrupt, architecture, archive, "corrupt-import", "invalid_state");

    const repeated = try std.mem.concat(fixture.allocator, u8, &.{ status_before, status_before });
    defer fixture.allocator.free(repeated);
    try fixture.write("ambiguous-import/" ++ admin ++ "status", repeated, 0o644);
    try dpkg_query.observeRefusedImport(fixture, dpkg, architecture, ambiguous, "ambiguous-import", null);
    try refusal(fixture, driver, ambiguous, architecture, archive, "ambiguous-import", "repeated_identity");

    try fixture.write("unsupported-import/" ++ admin ++ "future-feature", "unknown metadata\n", 0o644);
    const imported_show = try std.fmt.allocPrint(fixture.allocator, keeper ++ " 1 {s} install ok installed\n", .{architecture});
    defer fixture.allocator.free(imported_show);
    try dpkg_query.observeRefusedImport(fixture, dpkg, architecture, unsupported, "unsupported-import", imported_show);
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

const UnchangedReport = struct {
    outcome: []const u8,
    changed: bool,
    detail: []const u8,
};

/// Runs the driver's zero-action `upgrade-all`: production's `Runtime.prepare`
/// classification, then `Runtime.verifyUnchanged`. It never executes.
fn unchangedUpgradeAll(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    architecture: []const u8,
    destination: []const u8,
) !std.json.Parsed(UnchangedReport) {
    try fixture.directory(destination);
    const request_relative = try support.path(fixture.allocator, destination, "unchanged.request.json");
    defer fixture.allocator.free(request_relative);
    const report_relative = try support.path(fixture.allocator, destination, "unchanged.report.json");
    defer fixture.allocator.free(report_relative);
    const log = try support.path(fixture.allocator, destination, "unchanged.log");
    defer fixture.allocator.free(log);
    const request = try fixture.absolute(request_relative);
    defer fixture.allocator.free(request);
    const report = try fixture.absolute(report_relative);
    defer fixture.allocator.free(report);
    const document = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = root,
        .architecture = architecture,
        .report = report,
    }, .{});
    defer fixture.allocator.free(document);
    try fixture.write(request_relative, document, 0o644);
    // The lifecycle test in the same driver would otherwise replay its last request.
    _ = fixture.environment.swapRemove("DEBZ_NATIVE_LIFECYCLE_REQUEST");
    try fixture.environment.put("DEBZ_NATIVE_UNCHANGED_REQUEST", request);
    defer _ = fixture.environment.swapRemove("DEBZ_NATIVE_UNCHANGED_REQUEST");
    try fixture.run(&.{driver}, log, 120);
    const bytes = try support.read(fixture, report_relative, 64 * 1024);
    defer fixture.allocator.free(bytes);
    return std.json.parseFromSlice(UnchangedReport, fixture.allocator, bytes, .{
        .allocate = .alloc_always,
    });
}

/// `foundation.capture` refuses a linked database entry, so such a root is
/// compared by a raw listing that records the link, modes, owners, and bytes.
fn rootState(fixture: *foundation.Fixture, root: []const u8, label: []const u8) ![]u8 {
    return foundation.capture(fixture.allocator, fixture.io, root) catch |err| switch (err) {
        error.UnsafeDatabaseEntry => {
            const log = try std.fmt.allocPrint(fixture.allocator, "{s}.state", .{label});
            defer fixture.allocator.free(log);
            const listing =
                \\cd "$1" && LC_ALL=C && export LC_ALL &&
                \\find . -path ./var/lib/debz -prune -o -printf '%p %y %m %U:%G %s %T@ %l\n' | sort &&
                \\find . -path ./var/lib/debz -prune -o -type f -print0 | sort -z | xargs -0r sha256sum
            ;
            try fixture.run(&.{ "/bin/sh", "-c", listing, "sh", root }, log, 60);
            return support.read(fixture, log, 64 * 1024 * 1024);
        },
        else => err,
    };
}

/// Byte-level listing of `var/lib/dpkg` and `var/lib/debz` (where provenance
/// lives), which `foundation.capture` compares only semantically or not at all.
/// `times` adds mtimes, proving that nothing was rewritten with equal bytes.
/// Acquiring the root operation creates and removes its transient record in
/// `var/lib/debz`, so only that directory's own mtime is never listed.
fn databaseState(fixture: *foundation.Fixture, root: []const u8, label: []const u8, times: bool) ![]u8 {
    const log = try std.fmt.allocPrint(fixture.allocator, "{s}.database", .{label});
    defer fixture.allocator.free(log);
    const listing =
        \\format=$2 && cd "$1" && LC_ALL=C && export LC_ALL &&
        \\set -- var/lib/dpkg $(test ! -d var/lib/debz || echo var/lib/debz) &&
        \\find "$@" \( -path var/lib/debz -printf "%p %y %m %U:%G %s\n" \) -o -printf "%p %y %m %U:%G %s %l$format\n" | sort &&
        \\find "$@" -type f -print0 | sort -z | xargs -0r sha256sum
    ;
    try fixture.run(&.{ "/bin/sh", "-c", listing, "sh", root, if (times) " %T@" else "" }, log, 60);
    return support.read(fixture, log, 64 * 1024 * 1024);
}

/// The path of a `databaseState` line: first field of a listing line, or the
/// name after `sha256sum`'s two-space separator.
fn listedPath(line: []const u8) []const u8 {
    if (std.mem.indexOf(u8, line, "  ")) |at| if (at == 64) return line[at + 2 ..];
    return line[0 .. std.mem.indexOfScalar(u8, line, ' ') orelse line.len];
}

/// Paths whose listing lines differ between two `databaseState` captures.
fn changedPaths(allocator: std.mem.Allocator, before: []const u8, after: []const u8) ![]const []const u8 {
    var changed: std.ArrayList([]const u8) = .empty;
    for ([_][2][]const u8{ .{ before, after }, .{ after, before } }) |sides| {
        var lines = std.mem.splitScalar(u8, sides[0], '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            var other = std.mem.splitScalar(u8, sides[1], '\n');
            const present = while (other.next()) |candidate| {
                if (std.mem.eql(u8, candidate, line)) break true;
            } else false;
            if (present) continue;
            const name = listedPath(line);
            for (changed.items) |seen| {
                if (std.mem.eql(u8, seen, name)) break;
            } else try changed.append(allocator, name);
        }
    }
    return changed.toOwnedSlice(allocator);
}

const ZeroAction = enum { unchanged, execution_required, refused };

/// Runs one zero-action `upgrade-all` and requires the expected production
/// classification. The driver never executes, so the whole root, the dpkg
/// database, and `var/lib/debz` (including provenance) must stay identical
/// down to mtimes for every outcome.
fn expectZeroAction(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    architecture: []const u8,
    destination: []const u8,
    expected: ZeroAction,
    detail: []const u8,
) !void {
    const before_label = try std.fmt.allocPrint(fixture.allocator, "{s}-before", .{destination});
    defer fixture.allocator.free(before_label);
    const before = try rootState(fixture, root, before_label);
    defer fixture.allocator.free(before);
    const before_database = try databaseState(fixture, root, before_label, true);
    defer fixture.allocator.free(before_database);
    var report = try unchangedUpgradeAll(fixture, driver, root, architecture, destination);
    defer report.deinit();
    if (!std.mem.eql(u8, report.value.outcome, @tagName(expected)) or
        report.value.changed != (expected == .execution_required) or
        !std.mem.eql(u8, report.value.detail, detail))
    {
        std.debug.print("{s}: expected zero-action {t} {s}, got {s} changed={} {s}\n", .{
            destination, expected, detail, report.value.outcome, report.value.changed, report.value.detail,
        });
        return error.ZeroActionUpgradeMismatch;
    }
    const after_label = try std.fmt.allocPrint(fixture.allocator, "{s}-after", .{destination});
    defer fixture.allocator.free(after_label);
    const after = try rootState(fixture, root, after_label);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.ZeroActionUpgradeChangedRoot;
    const after_database = try databaseState(fixture, root, after_label, true);
    defer fixture.allocator.free(after_database);
    if (!std.mem.eql(u8, before_database, after_database)) {
        const changed = try changedPaths(fixture.allocator, before_database, after_database);
        defer fixture.allocator.free(changed);
        // The first debz operation on a dpkg-only root creates its empty
        // persistent root-operation lock, as dpkg leaves its own lock files.
        const first_operation = std.mem.indexOf(u8, before_database, "var/lib/debz ") == null;
        const created = [_][]const u8{ "var/lib/debz", "var/lib/debz/root-operation.lock" };
        var unexpected = false;
        for (changed) |name| {
            std.debug.print("{s}: zero-action changed {s}\n", .{ destination, name });
            for (created) |allowed| {
                if (first_operation and std.mem.eql(u8, name, allowed)) break;
            } else unexpected = true;
        }
        if (unexpected or (first_operation and
            std.mem.indexOf(u8, after_database, "\nvar/lib/debz/root-operation.lock f 600 0:0 0 ") == null))
            return error.ZeroActionUpgradeChangedDatabase;
    }
    try support.assertNoActiveEvidence(fixture, root);
}

fn expectUnchanged(
    fixture: *foundation.Fixture,
    driver: []const u8,
    root: []const u8,
    architecture: []const u8,
    destination: []const u8,
    detail: []const u8,
) !void {
    const expected: ZeroAction = if (std.mem.eql(u8, detail, "unchanged")) .unchanged else .refused;
    return expectZeroAction(fixture, driver, root, architecture, destination, expected, detail);
}

/// A postinst that writes `arch-native` exactly like dpkg's own must leave a
/// root that a zero-action `upgrade-all` proves unchanged (changed=false),
/// while foreign, malformed, linked, or writable entries stay typed refusals.
fn archNative(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, architecture: []const u8) !void {
    const archive = try support.makePackage(fixture, architecture, "1", arch_native_writer, "packages/root-import-arch-native", .{
        .postinst_append = dpkg_create_db_native_arch,
    });
    defer fixture.allocator.free(archive);
    var scenario = try support.Scenario.init(fixture, "arch-native-import", driver, dpkg, architecture, false);
    defer scenario.deinit();
    const chosen = [_]foundation.PackageIdentity{.{ .name = arch_native_writer, .architecture = architecture }};
    try scenario.phase(.{ .operation = "install", .archives = &.{archive}, .packages = &chosen }, false);
    const expected = try std.fmt.allocPrint(fixture.allocator, "{s}\n", .{architecture});
    defer fixture.allocator.free(expected);
    for ([_][]const u8{ scenario.reference_root, scenario.native_root }) |root| {
        try assertFile(fixture, root, arch_native, expected);
        var guarded = try foundation.guardedRoot(fixture.io, root);
        defer guarded.close(fixture.io);
        const entry = try (root_fs.Root.init(fixture.io, guarded)).entry(try root_fs.Path.init(arch_native));
        if (!entry.isRegularFile() or entry.mode & 0o7777 != 0o644) return error.ArchNativeModeMismatch;
    }

    const foreign = try cloneRoot(fixture, scenario.native_root, "arch-native-foreign", architecture);
    defer fixture.allocator.free(foreign);
    const trailing = try cloneRoot(fixture, scenario.native_root, "arch-native-trailing", architecture);
    defer fixture.allocator.free(trailing);
    const linked = try cloneRoot(fixture, scenario.native_root, "arch-native-linked", architecture);
    defer fixture.allocator.free(linked);
    const writable = try cloneRoot(fixture, scenario.native_root, "arch-native-writable", architecture);
    defer fixture.allocator.free(writable);

    try expectUnchanged(fixture, driver, scenario.native_root, architecture, "arch-native-import/unchanged-upgrade-all", "unchanged");
    try expectUnchanged(fixture, driver, scenario.native_root, architecture, "arch-native-import/unchanged-upgrade-all-again", "unchanged");

    const other = if (std.mem.eql(u8, architecture, "amd64")) "arm64\n" else "amd64\n";
    try fixture.write("arch-native-foreign/" ++ arch_native, other, 0o644);
    const doubled = try std.fmt.allocPrint(fixture.allocator, "{s}\n\n", .{architecture});
    defer fixture.allocator.free(doubled);
    try fixture.write("arch-native-trailing/" ++ arch_native, doubled, 0o644);
    try fixture.dir.deleteFile(fixture.io, "arch-native-linked/" ++ arch_native);
    try fixture.dir.symLink(fixture.io, "status", "arch-native-linked/" ++ arch_native, .{});
    try fixture.write("arch-native-writable/" ++ arch_native, expected, 0o666);
    for ([_]struct { root: []const u8, label: []const u8, detail: []const u8 }{
        .{ .root = foreign, .label = "arch-native-foreign", .detail = "DatabaseNativeArchitectureMismatch" },
        .{ .root = trailing, .label = "arch-native-trailing", .detail = "DatabaseNativeArchitectureMismatch" },
        .{ .root = linked, .label = "arch-native-linked", .detail = "UnsafeDatabaseEntry" },
        .{ .root = writable, .label = "arch-native-writable", .detail = "UnsafeDatabaseEntry" },
    }) |case| {
        const zero = try std.fmt.allocPrint(fixture.allocator, "{s}-unchanged", .{case.label});
        defer fixture.allocator.free(zero);
        try expectUnchanged(fixture, driver, case.root, architecture, zero, case.detail);
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}-reinstall", .{case.label});
        defer fixture.allocator.free(destination);
        const before_label = try std.fmt.allocPrint(fixture.allocator, "{s}-before", .{destination});
        defer fixture.allocator.free(before_label);
        const before = try rootState(fixture, case.root, before_label);
        defer fixture.allocator.free(before);
        try fixture.directory(destination);
        var report = try support.native(fixture, driver, case.root, architecture, .{
            .operation = "reinstall",
            .archives = &.{archive},
            .packages = &chosen,
        }, destination);
        defer report.deinit();
        if (!std.mem.eql(u8, report.value.outcome, "refused") or
            !std.mem.eql(u8, report.value.detail, case.detail))
        {
            std.debug.print("{s}: expected refusal {s}, got {s}: {s}\n", .{
                case.label, case.detail, report.value.outcome, report.value.detail,
            });
            return error.ArchNativeRefusalMismatch;
        }
        const after_label = try std.fmt.allocPrint(fixture.allocator, "{s}-after", .{destination});
        defer fixture.allocator.free(after_label);
        const after = try rootState(fixture, case.root, after_label);
        defer fixture.allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.ArchNativeRefusalChangedRoot;
        try support.assertNoActiveEvidence(fixture, case.root);
    }
}

const zero_handler = "zero-trigger-handler";
const zero_file_handler = "zero-file-handler";
const zero_source = "zero-trigger-source";
const zero_activator = "zero-trigger-activator";
const zero_trigger = "debz-zero-trigger";
const zero_files = "usr/share/debz-zero-files";

/// A configured root has no trigger work: no package awaits or has pending
/// triggers, and `triggers/Unincorp` is absent or empty.
fn assertNoPendingTriggers(fixture: *foundation.Fixture, root: []const u8) !void {
    const status = try rootFile(fixture, root, admin ++ "status");
    defer fixture.allocator.free(status);
    for ([_][]const u8{ "Triggers-Pending:", "Triggers-Awaited:", " triggers-pending\n", " triggers-awaited\n" }) |marker|
        if (std.mem.indexOf(u8, status, marker) != null) return error.ZeroActionFixtureHasPendingTriggers;
    const unincorp = rootFile(fixture, root, admin ++ "triggers/Unincorp") catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer fixture.allocator.free(unincorp);
    if (unincorp.len != 0) return error.ZeroActionFixtureHasPendingTriggers;
}

/// Status paragraphs as a sorted multiset, so record order is ignored.
fn sameParagraphs(allocator: std.mem.Allocator, left: []const u8, right: []const u8) !bool {
    var sides: [2]std.ArrayList([]const u8) = .{ .empty, .empty };
    defer for (&sides) |*side| side.deinit(allocator);
    for ([_][]const u8{ left, right }, &sides) |text, *side| {
        var paragraphs = std.mem.splitSequence(u8, text, "\n\n");
        while (paragraphs.next()) |paragraph| {
            const trimmed = std.mem.trim(u8, paragraph, "\n");
            if (trimmed.len != 0) try side.append(allocator, trimmed);
        }
        std.mem.sort([]const u8, side.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);
    }
    if (sides[0].items.len != sides[1].items.len) return false;
    for (sides[0].items, sides[1].items) |a, b| if (!std.mem.eql(u8, a, b)) return false;
    return true;
}

/// Which database rewrites pinned dpkg may make while proving it has no
/// pending work. On its own reference root nothing but `status-old` may
/// change. On a native root dpkg additionally creates its persistent lock
/// files and rewrites `status` in its own record order (dpkg sorts records by
/// name and architecture; native keeps install order), which is allowed only
/// when the paragraph set is identical.
const PendingNoop = enum { reference, native };

/// Pinned dpkg's own pending-work commands on a copy of `source`. With nothing
/// pending, neither may run a script or change `triggers/` state, and `status`
/// may change only as `PendingNoop` allows. Every rewrite is logged.
fn dpkgPendingNoop(
    fixture: *foundation.Fixture,
    dpkg: []const u8,
    source: []const u8,
    label: []const u8,
    architecture: []const u8,
    kind: PendingNoop,
) !void {
    const copy = try cloneRoot(fixture, source, label, architecture);
    defer fixture.allocator.free(copy);
    const root_arg = try std.fmt.allocPrint(fixture.allocator, "--root={s}", .{copy});
    defer fixture.allocator.free(root_arg);
    const lock_files = [_][]const u8{ admin ++ "lock", admin ++ "lock-frontend", admin ++ "triggers/Lock" };
    for ([_][2][]const u8{ .{ "--configure", "--pending" }, .{ "--triggers-only", "-a" } }, [_][]const u8{ "configure-pending", "triggers-only" }) |command, name| {
        const step = try std.fmt.allocPrint(fixture.allocator, "{s}-{s}", .{ label, name });
        defer fixture.allocator.free(step);
        const before_label = try std.fmt.allocPrint(fixture.allocator, "{s}-before", .{step});
        defer fixture.allocator.free(before_label);
        const before = try databaseState(fixture, copy, before_label, false);
        defer fixture.allocator.free(before);
        const status_before = try rootFile(fixture, copy, admin ++ "status");
        defer fixture.allocator.free(status_before);
        const trace_before = try rootFile(fixture, copy, support.trace);
        defer fixture.allocator.free(trace_before);
        const log = try std.fmt.allocPrint(fixture.allocator, "{s}.log", .{step});
        defer fixture.allocator.free(log);
        if (try support.runExit(fixture, &.{ dpkg, "--force-not-root", "--force-bad-path", root_arg, command[0], command[1] }, log) != 0)
            return error.ReferencePendingFailed;
        const after_label = try std.fmt.allocPrint(fixture.allocator, "{s}-after", .{step});
        defer fixture.allocator.free(after_label);
        const after = try databaseState(fixture, copy, after_label, false);
        defer fixture.allocator.free(after);
        const status_after = try rootFile(fixture, copy, admin ++ "status");
        defer fixture.allocator.free(status_after);
        const changed = try changedPaths(fixture.allocator, before, after);
        defer fixture.allocator.free(changed);
        for (changed) |path_name| {
            std.debug.print("{s}: dpkg {s} {s} rewrote {s}\n", .{ label, command[0], command[1], path_name });
            if (std.mem.eql(u8, path_name, admin ++ "status-old")) continue;
            if (kind == .native) {
                for (lock_files) |lock| {
                    if (std.mem.eql(u8, path_name, lock)) break;
                } else if (std.mem.eql(u8, path_name, admin[0 .. admin.len - 1]) or
                    std.mem.eql(u8, path_name, admin ++ "triggers"))
                {
                    // Directory entries change only with the created lock files.
                } else if (std.mem.eql(u8, path_name, admin ++ "status")) {
                    if (!try sameParagraphs(fixture.allocator, status_before, status_after))
                        return error.ReferencePendingChangedDatabase;
                } else return error.ReferencePendingChangedDatabase;
                continue;
            }
            return error.ReferencePendingChangedDatabase;
        }
        const trace_after = try rootFile(fixture, copy, support.trace);
        defer fixture.allocator.free(trace_after);
        if (!std.mem.eql(u8, trace_before, trace_after)) return error.ReferencePendingRanScript;
    }
}

/// A fully configured root whose packages declare trigger interest and
/// activation, with nothing pending, is unchanged by a zero-action
/// `upgrade-all`: no program, changed=false, and identical status, `triggers/`,
/// and provenance, as pinned dpkg's `--configure --pending` and
/// `--triggers-only -a` are no-ops on the same root. Pending work, whether
/// package states or unincorporated activations, still requires the
/// `process_triggers` program.
fn zeroActionTriggers(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, architecture: []const u8) !void {
    const workspace = "packages/zero-action-triggers";
    const handler = try support.makePackage(fixture, architecture, "1", zero_handler, workspace, .{
        .declarations = "interest-noawait " ++ zero_trigger ++ "\n",
    });
    defer fixture.allocator.free(handler);
    const file_handler = try support.makePackage(fixture, architecture, "1", zero_file_handler, workspace, .{
        .declarations = "interest /" ++ zero_files ++ "\n",
    });
    defer fixture.allocator.free(file_handler);
    const source = try support.makePackage(fixture, architecture, "1", zero_source, workspace, .{
        .declarations = "activate-noawait " ++ zero_trigger ++ "\n",
        .extra_files = &.{.{ .path = zero_files ++ "/" ++ zero_source, .content = "file trigger payload\n" }},
    });
    defer fixture.allocator.free(source);
    const activator = try support.makePackage(fixture, architecture, "1", zero_activator, workspace, .{
        .declarations = "activate-noawait debz-zero-unhandled\n",
    });
    defer fixture.allocator.free(activator);

    var scenario = try support.Scenario.init(fixture, "zero-action-triggers", driver, dpkg, architecture, false);
    defer scenario.deinit();
    try scenario.phase(.{ .operation = "install", .archives = &.{ handler, file_handler }, .triggers = true, .recovery = true }, false);
    try scenario.phase(.{ .operation = "install", .archives = &.{source}, .triggers = true, .recovery = true }, false);
    const trace = try rootFile(fixture, scenario.native_root, support.trace);
    defer fixture.allocator.free(trace);
    for ([_][]const u8{ zero_handler, zero_file_handler }) |name| {
        const triggered = try std.fmt.allocPrint(fixture.allocator, "{s}@1:postinst\t{s}\tpostinst\t{s}\t2\t9:triggered\t", .{ name, name, architecture });
        defer fixture.allocator.free(triggered);
        if (std.mem.indexOf(u8, trace, triggered) == null) return error.ZeroActionFixtureTriggerNotProcessed;
    }
    for ([_][]const u8{ scenario.reference_root, scenario.native_root }) |root|
        try assertNoPendingTriggers(fixture, root);
    try checkProvenance(fixture, scenario.native_root);
    const unincorporated = try cloneRoot(fixture, scenario.native_root, "zero-action-triggers-unincorp", architecture);
    defer fixture.allocator.free(unincorporated);

    try expectZeroAction(fixture, driver, scenario.native_root, architecture, "zero-action-triggers/upgrade-all", .unchanged, "unchanged");
    try expectZeroAction(fixture, driver, scenario.native_root, architecture, "zero-action-triggers/upgrade-all-again", .unchanged, "unchanged");
    try dpkgPendingNoop(fixture, dpkg, scenario.reference_root, "zero-action-triggers-dpkg", architecture, .reference);
    try dpkgPendingNoop(fixture, dpkg, scenario.native_root, "zero-action-triggers-dpkg-native", architecture, .native);

    // dpkg incorporates and processes a recorded activation on its next run.
    try fixture.write("zero-action-triggers-unincorp/" ++ admin ++ "triggers/Unincorp", zero_trigger ++ " -\n", 0o644);
    try expectZeroAction(fixture, driver, unincorporated, architecture, "zero-action-triggers-unincorp-upgrade-all", .execution_required, "process_triggers");

    var pending = try support.Scenario.init(fixture, "zero-action-pending-triggers", driver, dpkg, architecture, false);
    defer pending.deinit();
    try pending.phase(.{ .operation = "install", .archives = &.{handler}, .triggers = true, .recovery = true }, false);
    try pending.phase(.{ .operation = "install", .archives = &.{source}, .triggers = true, .defer_triggers = true }, false);
    const deferred = try rootFile(fixture, pending.native_root, admin ++ "status");
    defer fixture.allocator.free(deferred);
    if (std.mem.indexOf(u8, deferred, "Triggers-Pending:") == null) return error.ZeroActionFixtureMissingPendingTriggers;
    try expectZeroAction(fixture, driver, pending.native_root, architecture, "zero-action-pending-triggers/upgrade-all", .execution_required, "process_triggers");
    try pending.phase(.{ .operation = "process_triggers", .triggers = true }, false);
    for ([_][]const u8{ pending.reference_root, pending.native_root }) |root|
        try assertNoPendingTriggers(fixture, root);
    try expectZeroAction(fixture, driver, pending.native_root, architecture, "zero-action-pending-triggers/processed-upgrade-all", .unchanged, "unchanged");

    // Activations with no interested package anywhere leave nothing to
    // process. Native installs refuse such a root's trigger authority as empty,
    // so dpkg installs it on both sides.
    var activate_only = try support.Scenario.init(fixture, "zero-action-activate-only", driver, dpkg, architecture, false);
    defer activate_only.deinit();
    try activate_only.seed(activator);
    for ([_][]const u8{ activate_only.reference_root, activate_only.native_root }) |root|
        try assertNoPendingTriggers(fixture, root);
    try expectZeroAction(fixture, driver, activate_only.native_root, architecture, "zero-action-activate-only/upgrade-all", .unchanged, "unchanged");
    try expectZeroAction(fixture, driver, activate_only.native_root, architecture, "zero-action-activate-only/upgrade-all-again", .unchanged, "unchanged");
    try dpkgPendingNoop(fixture, dpkg, activate_only.reference_root, "zero-action-activate-only-dpkg", architecture, .reference);
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
    try dpkg_query.runImported(&fixture, driver, prerequisite.executable, prerequisite.architecture);
    try run(&fixture, driver, prerequisite.executable, prerequisite.architecture);
    try archNative(&fixture, driver, prerequisite.executable, prerequisite.architecture);
    try zeroActionTriggers(&fixture, driver, prerequisite.executable, prerequisite.architecture);
    try support.assertHostUnchanged(allocator, init.io, prerequisite.before);
}
