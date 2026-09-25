const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const root_fs = @import("debz").root_fs;

pub const trace = "var/log/debz-native-differential.trace";
pub const failure = "lifecycle-fail";
pub const kinds = [_][]const u8{ "preinst", "postinst", "prerm", "postrm" };

pub fn path(allocator: std.mem.Allocator, first: []const u8, second: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ first, second });
}

pub fn read(fixture: *foundation.Fixture, relative: []const u8, limit: usize) ![]u8 {
    var file = try fixture.dir.openFile(fixture.io, relative, .{
        .follow_symlinks = false,
        .allow_directory = false,
    });
    defer file.close(fixture.io);
    var reader = file.reader(fixture.io, &.{});
    return reader.interface.allocRemaining(fixture.allocator, .limited(limit));
}

pub fn absent(fixture: *foundation.Fixture, relative: []const u8) !void {
    if (fixture.dir.statFile(fixture.io, relative, .{ .follow_symlinks = false })) |_|
        return error.UnexpectedArtifact
    else |err| if (err != error.FileNotFound) return err;
}

pub fn fixtureFile(fixture: *foundation.Fixture, relative: []const u8, content: []const u8, mode: u32) !void {
    try fixture.write(relative, content, mode);
    try fixture.dir.setTimestamps(fixture.io, relative, .{
        .modify_timestamp = .{ .new = .{ .nanoseconds = foundation.epoch * std.time.ns_per_s } },
    });
}

pub fn copyProgram(fixture: *foundation.Fixture, root: []const u8, source: []const u8, destination: []const u8) !void {
    if (!std.fs.path.isAbsolute(source) or !std.fs.path.isAbsolute(destination)) return error.InvalidProgramPath;
    const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}", .{ root, destination[1..] });
    defer fixture.allocator.free(relative);
    if (fixture.dir.statFile(fixture.io, relative, .{ .follow_symlinks = false })) |_| return else |err| if (err != error.FileNotFound) return err;
    var input = try std.Io.Dir.openFileAbsolute(fixture.io, source, .{});
    defer input.close(fixture.io);
    var reader = input.reader(fixture.io, &.{});
    const bytes = try reader.interface.allocRemaining(fixture.allocator, .limited(32 * 1024 * 1024));
    defer fixture.allocator.free(bytes);
    try fixtureFile(fixture, relative, bytes, 0o755);
    if (std.mem.startsWith(u8, bytes, "#!")) {
        const end = std.mem.indexOfScalar(u8, bytes, '\n') orelse return error.InvalidInterpreter;
        const interpreter = std.mem.trim(u8, bytes[2..end], " \t");
        if (!std.fs.path.isAbsolute(interpreter)) return error.InvalidInterpreter;
        try copyProgram(fixture, root, interpreter, interpreter);
        return;
    }
    const result = try std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "ldd", source },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const static = std.mem.indexOf(u8, result.stdout, "statically linked") != null or
        std.mem.indexOf(u8, result.stderr, "not a dynamic executable") != null;
    if (!static and (result.term != .exited or result.term.exited != 0 or
        std.mem.indexOf(u8, result.stdout, "=> not found") != null))
        return error.MissingFixtureLibrary;
    var words = std.mem.tokenizeAny(u8, result.stdout, " \r\n\t()");
    while (words.next()) |word| {
        if (word.len < 2 or word[0] != '/') continue;
        const library = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}", .{ root, word[1..] });
        defer fixture.allocator.free(library);
        if (fixture.dir.statFile(fixture.io, library, .{ .follow_symlinks = false })) |_| continue else |err| if (err != error.FileNotFound) return err;
        var lib = try std.Io.Dir.openFileAbsolute(fixture.io, word, .{});
        defer lib.close(fixture.io);
        var lib_reader = lib.reader(fixture.io, &.{});
        const content = try lib_reader.interface.allocRemaining(fixture.allocator, .limited(32 * 1024 * 1024));
        defer fixture.allocator.free(content);
        try fixtureFile(fixture, library, content, 0o755);
    }
}

pub const ScriptOptions = struct {
    before_failure: []const u8 = "",
    after_failure: []const u8 = "",
    omit_postrm: bool = false,
};

pub fn scripts(fixture: *foundation.Fixture, source: []const u8, package: []const u8, version: []const u8) !void {
    return scriptsWith(fixture, source, package, version, .{});
}

pub fn scriptsWith(fixture: *foundation.Fixture, source: []const u8, package: []const u8, version: []const u8, options: ScriptOptions) !void {
    for (kinds) |kind| {
        if (options.omit_postrm and std.mem.eql(u8, kind, "postrm")) continue;
        const body = try std.fmt.allocPrint(fixture.allocator,
            \\#!/bin/sh
            \\printf '%s\t%s\t%s\t%s\t%d' '{s}@{s}:{s}' "$DPKG_MAINTSCRIPT_PACKAGE" "$DPKG_MAINTSCRIPT_NAME" "$DPKG_MAINTSCRIPT_ARCH" "$#" >> /{s}
            \\for argument do
            \\    printf '\t%d:%s' "${{#argument}}" "$argument" >> /{s}
            \\done
            \\payload='<absent>'
            \\if [ -f /usr/share/{s}/data ]; then
            \\    IFS= read -r payload < /usr/share/{s}/data
            \\fi
            \\printf '\tpayload=%s' "$payload" >> /{s}
            \\printf '\n' >> /{s}
            \\{s}
            \\if [ -f /{s} ]; then
            \\    while IFS= read -r failure; do
            \\        if [ "$failure" = "{s}@{s}:{s}:$1" ]; then
            \\            exit 23
            \\        fi
            \\    done < /{s}
            \\fi
            \\{s}
            \\exit 0
            \\
        , .{ package, version, kind, trace, trace, package, package, trace, trace, options.before_failure, failure, package, version, kind, failure, options.after_failure });
        defer fixture.allocator.free(body);
        const relative = try std.fmt.allocPrint(fixture.allocator, "{s}/DEBIAN/{s}", .{ source, kind });
        defer fixture.allocator.free(relative);
        try fixture.write(relative, body, 0o755);
    }
}

pub const PackageSpec = struct {
    declarations: ?[]const u8 = null,
    activation: ?[]const u8 = null,
    conffile_content: ?[]const u8 = null,
    conffile_path: []const u8 = "etc/debz-native.conf",
    extra_conffile: ?foundation.Fixture.ExtraFile = null,
    extra_files: []const foundation.Fixture.ExtraFile = &.{},
    control_fields: []const u8 = "",
    full_payload: bool = false,
    bootstrap_shell: bool = false,
    no_scripts: bool = false,
    scripts: ScriptOptions = .{},
};

pub fn makePackage(fixture: *foundation.Fixture, architecture: []const u8, version: []const u8, name: []const u8, workspace: []const u8, spec: PackageSpec) ![]u8 {
    const stem = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}_{s}_data", .{ workspace, name, version });
    defer fixture.allocator.free(stem);
    const source = try std.fmt.allocPrint(fixture.allocator, "{s}.source", .{stem});
    defer fixture.allocator.free(source);
    const destination = try std.fmt.allocPrint(fixture.allocator, "{s}.deb", .{stem});
    defer fixture.allocator.free(destination);
    const control = try std.fmt.allocPrint(fixture.allocator, "Package: {s}\nVersion: {s}\nArchitecture: {s}\nMaintainer: debz fixture <fixture@example.invalid>\n{s}Description: native lifecycle fixture\n", .{ name, version, architecture, spec.control_fields });
    defer fixture.allocator.free(control);
    const control_path = try path(fixture.allocator, source, "DEBIAN/control");
    defer fixture.allocator.free(control_path);
    try fixture.write(control_path, control, 0o644);
    const data_path = try std.fmt.allocPrint(fixture.allocator, "{s}/usr/share/{s}/data", .{ source, name });
    defer fixture.allocator.free(data_path);
    const content = try std.fmt.allocPrint(fixture.allocator, "data version {s}\n", .{version});
    defer fixture.allocator.free(content);
    try fixture.write(data_path, content, 0o644);
    const hardlink = try std.fmt.allocPrint(fixture.allocator, "{s}/usr/share/{s}/data.link", .{ source, name });
    defer fixture.allocator.free(hardlink);
    try std.Io.Dir.hardLink(fixture.dir, data_path, fixture.dir, hardlink, fixture.io, .{});
    const symbolic = try std.fmt.allocPrint(fixture.allocator, "{s}/usr/share/{s}/current", .{ source, name });
    defer fixture.allocator.free(symbolic);
    try fixture.dir.symLink(fixture.io, "data", symbolic, .{});
    if (spec.full_payload) {
        const base = try std.fmt.allocPrint(fixture.allocator, "{s}/usr/share/{s}", .{ source, name });
        defer fixture.allocator.free(base);
        const mode = try path(fixture.allocator, base, "mode");
        defer fixture.allocator.free(mode);
        try fixture.write(mode, "permission-sensitive payload\n", if (std.mem.eql(u8, version, "1")) 0o600 else 0o640);
        const changed = try path(fixture.allocator, base, if (std.mem.eql(u8, version, "1")) "obsolete" else "introduced");
        defer fixture.allocator.free(changed);
        const changed_content = try std.fmt.allocPrint(fixture.allocator, "only in {s}\n", .{version});
        defer fixture.allocator.free(changed_content);
        try fixture.write(changed, changed_content, 0o644);
        const empty = try path(fixture.allocator, base, "empty");
        defer fixture.allocator.free(empty);
        try fixture.directory(empty);
        try fixture.dir.setFilePermissions(fixture.io, empty, .fromMode(0o750), .{});
    }
    if (spec.conffile_content) |configuration| {
        const conffile = try path(fixture.allocator, source, spec.conffile_path);
        defer fixture.allocator.free(conffile);
        try fixture.write(conffile, configuration, 0o644);
        const declaration = try path(fixture.allocator, source, "DEBIAN/conffiles");
        defer fixture.allocator.free(declaration);
        const declarations = if (spec.extra_conffile) |extra|
            try std.fmt.allocPrint(fixture.allocator, "/{s}\n/{s}\n", .{ spec.conffile_path, extra.path })
        else
            try std.fmt.allocPrint(fixture.allocator, "/{s}\n", .{spec.conffile_path});
        defer fixture.allocator.free(declarations);
        try fixture.write(declaration, declarations, 0o644);
    }
    if (spec.extra_conffile) |extra| {
        if (spec.conffile_content == null) return error.ExtraConffileWithoutPrimary;
        const relative = try path(fixture.allocator, source, extra.path);
        defer fixture.allocator.free(relative);
        try fixture.write(relative, extra.content, extra.mode);
    }
    for (spec.extra_files) |extra| {
        const relative = try path(fixture.allocator, source, extra.path);
        defer fixture.allocator.free(relative);
        try fixture.write(relative, extra.content, extra.mode);
    }
    if (spec.bootstrap_shell) try copyProgram(fixture, source, "/bin/sh", "/bin/sh");
    if (!spec.no_scripts) try scriptsWith(fixture, source, name, version, spec.scripts);
    if (spec.activation) |trigger| {
        const postinst = try path(fixture.allocator, source, "DEBIAN/postinst");
        defer fixture.allocator.free(postinst);
        const original = try read(fixture, postinst, 64 * 1024);
        defer fixture.allocator.free(original);
        if (!std.mem.endsWith(u8, original, "exit 0\n")) return error.InvalidFixtureScript;
        const activation = try std.fmt.allocPrint(fixture.allocator, "if [ \"$1\" = configure ]; then\n    /usr/bin/dpkg-trigger --no-await {s} || exit $?\nfi\nexit 0\n", .{trigger});
        defer fixture.allocator.free(activation);
        const body = try std.mem.concat(fixture.allocator, u8, &.{ original[0 .. original.len - "exit 0\n".len], activation });
        defer fixture.allocator.free(body);
        try fixture.write(postinst, body, 0o755);
    }
    if (spec.declarations) |text| {
        const member = try path(fixture.allocator, source, "DEBIAN/triggers");
        defer fixture.allocator.free(member);
        try fixture.write(member, text, 0o644);
    }
    return fixture.buildPackage(source, destination, .{
        .compression = if (spec.bootstrap_shell) .none else .gzip,
    });
}

pub const Action = struct {
    sequence: usize,
    kind: []const u8,
    package: []const u8,
    version: []const u8 = "1",
    architecture: []const u8,
};

pub const Phase = struct {
    operation: []const u8,
    archives: []const []const u8 = &.{},
    reference_groups: ?[]const []const []const u8 = null,
    packages: []const foundation.PackageIdentity = &.{},
    policy: []const u8 = "keep_existing",
    defer_triggers: bool = false,
    triggers: bool = false,
    fault: ?[]const u8 = null,
    recovery: bool = false,
    ordered_actions: ?[]const Action = null,
    rollback_links: []const []const u8 = &.{},
    created_rollback_links: []const []const u8 = &.{},
};

pub fn runExit(fixture: *foundation.Fixture, argv: []const []const u8, log: []const u8) !u8 {
    var bounded: std.ArrayList([]const u8) = .empty;
    defer bounded.deinit(fixture.allocator);
    try bounded.appendSlice(fixture.allocator, &.{ "/usr/bin/timeout", "--kill-after=2s", "120s" });
    try bounded.appendSlice(fixture.allocator, argv);
    const result = try std.process.run(fixture.allocator, fixture.io, .{
        .argv = bounded.items,
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    });
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const combined = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    defer fixture.allocator.free(combined);
    try fixture.write(log, combined, 0o644);
    if (result.term != .exited or result.term.exited > 1) {
        std.debug.print("{s}: unexpected exit {any}; log {s}/{s}:\n{s}\n", .{ argv[0], result.term, fixture.path, log, combined[0..@min(combined.len, 12_000)] });
        return error.UnexpectedProcessExit;
    }
    return result.term.exited;
}

pub fn reference(fixture: *foundation.Fixture, executable: []const u8, root: []const u8, phase: Phase, destination: []const u8) !u8 {
    var guarded = try foundation.guardedRoot(fixture.io, root);
    guarded.close(fixture.io);
    const root_arg = try std.fmt.allocPrint(fixture.allocator, "--root={s}", .{root});
    defer fixture.allocator.free(root_arg);
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(fixture.allocator);
    try argv.appendSlice(fixture.allocator, &.{
        executable, "--force-not-root", "--force-bad-path", root_arg,
    });
    if (!phase.triggers or phase.defer_triggers) try argv.append(fixture.allocator, "--no-triggers");
    try argv.append(fixture.allocator, if (std.mem.eql(u8, phase.policy, "keep_existing")) "--force-confold" else if (std.mem.eql(u8, phase.policy, "use_package_version")) "--force-confnew" else return error.InvalidConffilePolicy);
    const operation = phase.operation;
    if (std.mem.eql(u8, operation, "install") or std.mem.eql(u8, operation, "upgrade") or
        std.mem.eql(u8, operation, "downgrade") or std.mem.eql(u8, operation, "reinstall") or
        std.mem.eql(u8, operation, "unpack"))
    {
        if (phase.archives.len == 0) return error.MissingArchive;
        try argv.append(fixture.allocator, if (std.mem.eql(u8, operation, "unpack")) "--unpack" else "--install");
        try argv.appendSlice(fixture.allocator, phase.archives);
    } else if (std.mem.eql(u8, operation, "process_triggers")) {
        if (!phase.triggers) return error.InvalidReferenceOperation;
        try argv.append(fixture.allocator, "--triggers-only");
        if (phase.packages.len == 0) try argv.append(fixture.allocator, "--pending") else for (phase.packages) |item| try argv.append(fixture.allocator, item.name);
    } else if (std.mem.eql(u8, operation, "configure") or std.mem.eql(u8, operation, "remove") or std.mem.eql(u8, operation, "purge")) {
        if (phase.packages.len == 0) return error.MissingPackage;
        const flag = try std.fmt.allocPrint(fixture.allocator, "--{s}", .{operation});
        defer fixture.allocator.free(flag);
        try argv.append(fixture.allocator, flag);
        var owned: std.ArrayList([]const u8) = .empty;
        defer {
            for (owned.items) |item| fixture.allocator.free(item);
            owned.deinit(fixture.allocator);
        }
        for (phase.packages) |item| {
            const identity = try std.fmt.allocPrint(fixture.allocator, "{s}:{s}", .{ item.name, item.architecture });
            try owned.append(fixture.allocator, identity);
            try argv.append(fixture.allocator, identity);
        }
        const log = try path(fixture.allocator, destination, "reference.log");
        defer fixture.allocator.free(log);
        return runExit(fixture, argv.items, log);
    } else return error.InvalidReferenceOperation;
    const log = try path(fixture.allocator, destination, "reference.log");
    defer fixture.allocator.free(log);
    return runExit(fixture, argv.items, log);
}

pub const Report = struct { outcome: []const u8, detail: []const u8 = "" };

pub fn native(fixture: *foundation.Fixture, executable: []const u8, root: []const u8, architecture: []const u8, phase: Phase, destination: []const u8) !std.json.Parsed(Report) {
    var guarded = try foundation.guardedRoot(fixture.io, root);
    guarded.close(fixture.io);
    const request_relative = try path(fixture.allocator, destination, "native.request.json");
    defer fixture.allocator.free(request_relative);
    const report_relative = try path(fixture.allocator, destination, "native.report.json");
    defer fixture.allocator.free(report_relative);
    try absent(fixture, report_relative);
    const request = try fixture.absolute(request_relative);
    defer fixture.allocator.free(request);
    const report = try fixture.absolute(report_relative);
    defer fixture.allocator.free(report);
    const document = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .root = root,
        .architecture = architecture,
        .operation = phase.operation,
        .archives = phase.archives,
        .packages = phase.packages,
        .policy = phase.policy,
        .report = report,
        .triggers = phase.triggers,
        .defer_triggers = phase.defer_triggers,
        .fault = phase.fault,
        .recovery = phase.recovery,
        .ordered_actions = phase.ordered_actions,
    }, .{});
    defer fixture.allocator.free(document);
    try fixture.write(request_relative, document, 0o644);
    try fixture.environment.put("DEBZ_NATIVE_LIFECYCLE_REQUEST", request);
    const log = try path(fixture.allocator, destination, "native.log");
    defer fixture.allocator.free(log);
    try fixture.run(&.{executable}, log, 120);
    const bytes = try read(fixture, report_relative, 64 * 1024);
    defer fixture.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(Report, fixture.allocator, bytes, .{
        .allocate = .alloc_always,
        .ignore_unknown_fields = true,
    });
    for ([_][]const u8{ "applied", "script_failed", "trigger_failed", "recovery_required", "handoff", "refused" }) |outcome|
        if (std.mem.eql(u8, parsed.value.outcome, outcome)) return parsed;
    var bad = parsed;
    bad.deinit();
    return error.InvalidNativeReport;
}

pub fn assertNoActiveEvidence(fixture: *foundation.Fixture, root: []const u8) !void {
    if (root.len <= fixture.path.len or !std.mem.startsWith(u8, root, fixture.path) or
        root[fixture.path.len] != '/') return error.InvalidFixtureRoot;
    const relative = root[fixture.path.len + 1 ..];
    for ([_][]const u8{
        "root-operation-v1.json",          "root-mutation-v1.json",
        "native-lifecycle-script-v1.json", "native-trigger-authority-v1.json",
    }) |name| {
        const evidence = try std.fmt.allocPrint(fixture.allocator, "{s}/var/lib/debz/{s}", .{ relative, name });
        defer fixture.allocator.free(evidence);
        try absent(fixture, evidence);
    }
}

pub fn compare(fixture: *foundation.Fixture, reference_root: []const u8, candidate: []const u8, destination: []const u8, trigger_helper: bool) !void {
    if (!trigger_helper) return foundation.compare(fixture.*, reference_root, candidate, destination);
    const exclusions: []const []const u8 = &.{ foundation.guard, "usr/bin/dpkg-trigger" };
    const expected = try foundation.captureRealRoot(fixture.allocator, fixture.io, reference_root, .{}, exclusions);
    defer fixture.allocator.free(expected);
    const actual = try foundation.captureRealRoot(fixture.allocator, fixture.io, candidate, .{}, exclusions);
    defer fixture.allocator.free(actual);
    const left = try path(fixture.allocator, destination, "reference.snapshot.json");
    defer fixture.allocator.free(left);
    const right = try path(fixture.allocator, destination, "native.snapshot.json");
    defer fixture.allocator.free(right);
    try fixture.write(left, expected, 0o644);
    try fixture.write(right, actual, 0o644);
    if (!std.mem.eql(u8, expected, actual)) {
        var at: usize = 0;
        while (at < @min(expected.len, actual.len) and expected[at] == actual[at]) : (at += 1) {}
        if (fixture.diagnostics) std.debug.print("native/dpkg trigger mismatch in {s} at byte {d}:\nexpected: {s}\nactual: {s}\n", .{
            destination, at, expected[at..@min(expected.len, at + 200)], actual[at..@min(actual.len, at + 200)],
        });
        return error.NativeDpkgTriggerMismatch;
    }
}

const RollbackLink = struct { path: []const u8, original: ?i64 };

fn normalizeRollback(value: *std.json.Value, links: []const RollbackLink, start: i64, end: i64) !void {
    const entries = value.object.getPtr("filesystem") orelse return error.InvalidSnapshot;
    for (links) |link| {
        var found = false;
        for (entries.array.items) |*entry| {
            const path_value = entry.object.get("path") orelse return error.InvalidSnapshot;
            if (!std.mem.eql(u8, path_value.string, link.path)) continue;
            found = true;
            const kind = entry.object.get("kind") orelse return error.InvalidSnapshot;
            if (!std.mem.eql(u8, kind.string, "symlink")) return error.RollbackLinkTypeChanged;
            const time = entry.object.getPtr("mtime_ns") orelse return error.InvalidSnapshot;
            if (time.* != .integer) return error.InvalidSnapshot;
            if (time.integer != (link.original orelse 0) and (time.integer < start or time.integer > end))
                return error.RollbackLinkTimeOutsideOperation;
            time.* = .{ .integer = link.original orelse 0 };
            break;
        }
        if (!found) return error.RollbackLinkMissing;
    }
}

pub fn compareRollback(fixture: *foundation.Fixture, reference_root: []const u8, candidate: []const u8, destination: []const u8, links: []const RollbackLink, start: i64, end: i64) !void {
    const raw_left = try foundation.capture(fixture.allocator, fixture.io, reference_root);
    defer fixture.allocator.free(raw_left);
    const raw_right = try foundation.capture(fixture.allocator, fixture.io, candidate);
    defer fixture.allocator.free(raw_right);
    for ([_][]const u8{ raw_left, raw_right }, [_][]const u8{ "reference", "native" }) |raw, side| {
        const path_name = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}.snapshot.json", .{ destination, side });
        defer fixture.allocator.free(path_name);
        try fixture.write(path_name, raw, 0o644);
    }
    var left = try std.json.parseFromSlice(std.json.Value, fixture.allocator, raw_left, .{ .allocate = .alloc_always });
    defer left.deinit();
    var right = try std.json.parseFromSlice(std.json.Value, fixture.allocator, raw_right, .{ .allocate = .alloc_always });
    defer right.deinit();
    try normalizeRollback(&left.value, links, start, end);
    try normalizeRollback(&right.value, links, start, end);
    const normalized_left = try std.json.Stringify.valueAlloc(fixture.allocator, left.value, .{});
    defer fixture.allocator.free(normalized_left);
    const normalized_right = try std.json.Stringify.valueAlloc(fixture.allocator, right.value, .{});
    defer fixture.allocator.free(normalized_right);
    if (!std.mem.eql(u8, normalized_left, normalized_right)) {
        if (fixture.diagnostics) std.debug.print("native/dpkg rollback mismatch in {s}\n", .{destination});
        return error.NativeDpkgMismatch;
    }
}

fn normalizeAlternativeLog(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    var start: usize = 0;
    while (start < bytes.len) {
        const end = std.mem.indexOfScalarPos(u8, bytes, start, '\n') orelse bytes.len;
        const line = bytes[start..end];
        const prefix = "update-alternatives ";
        const timestamp = if (std.mem.startsWith(u8, line, prefix) and line.len >= prefix.len + 20)
            line[prefix.len .. prefix.len + 20]
        else
            "";
        const pattern = "0000-00-00 00:00:00:";
        var valid = timestamp.len == pattern.len;
        if (valid) for (pattern, timestamp) |expected, actual| {
            if ((expected == '0' and !std.ascii.isDigit(actual)) or (expected != '0' and expected != actual)) {
                valid = false;
                break;
            }
        };
        if (valid) {
            try result.appendSlice(allocator, "update-alternatives <clock>:");
            try result.appendSlice(allocator, line[prefix.len + 20 ..]);
        } else try result.appendSlice(allocator, line);
        if (end != bytes.len) try result.append(allocator, '\n');
        start = end + 1;
    }
    return result.toOwnedSlice(allocator);
}

fn normalizeAlternatives(allocator: std.mem.Allocator, value: *std.json.Value, root: []const u8, fixture: *foundation.Fixture, started: i64, ended: i64) !void {
    const entries = value.object.getPtr("filesystem") orelse return error.InvalidSnapshot;
    for (entries.array.items) |*entry| {
        const path_value = entry.object.get("path") orelse return error.InvalidSnapshot;
        const relative = path_value.string;
        const alternative = std.mem.eql(u8, relative, "usr/bin/debz-native-alternatives") or
            std.mem.eql(u8, relative, "usr/share/man/man1/debz-native-alternatives.1") or
            std.mem.eql(u8, relative, "var/log/alternatives.log") or
            std.mem.startsWith(u8, relative, "etc/alternatives/") or
            std.mem.startsWith(u8, relative, "var/lib/dpkg/alternatives/");
        if (!alternative) continue;
        const modified = entry.object.getPtr("mtime_ns") orelse return error.InvalidSnapshot;
        if (modified.* != .integer) return error.InvalidSnapshot;
        if (modified.integer != foundation.epoch * std.time.ns_per_s and
            (modified.integer < started or modified.integer > ended)) return error.AlternativeTimeOutsideOperation;
        modified.* = .{ .integer = 0 };
        if (std.mem.eql(u8, relative, "var/log/alternatives.log")) {
            const file_name = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, relative });
            const log_file = try std.Io.Dir.openFileAbsolute(fixture.io, file_name, .{ .follow_symlinks = false });
            defer log_file.close(fixture.io);
            var reader = log_file.reader(fixture.io, &.{});
            const raw = try reader.interface.allocRemaining(allocator, .limited(16 * 1024 * 1024));
            const normalized = try normalizeAlternativeLog(allocator, raw);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(normalized, &digest, .{});
            const hex = try allocator.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
            entry.object.getPtr("sha256").?.* = .{ .string = hex };
            entry.object.getPtr("size").?.* = .{ .integer = @intCast(normalized.len) };
        }
    }
}

pub fn compareAlternatives(fixture: *foundation.Fixture, reference_root: []const u8, candidate: []const u8, destination: []const u8, started: i64, ended: i64) !void {
    const expected = try foundation.capture(fixture.allocator, fixture.io, reference_root);
    defer fixture.allocator.free(expected);
    const actual = try foundation.capture(fixture.allocator, fixture.io, candidate);
    defer fixture.allocator.free(actual);
    for ([_][]const u8{ expected, actual }, [_][]const u8{ "reference", "native" }) |raw, side| {
        const path_name = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}.snapshot.json", .{ destination, side });
        defer fixture.allocator.free(path_name);
        try fixture.write(path_name, raw, 0o644);
    }
    var arena: std.heap.ArenaAllocator = .init(fixture.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var left = try std.json.parseFromSlice(std.json.Value, a, expected, .{});
    var right = try std.json.parseFromSlice(std.json.Value, a, actual, .{});
    try normalizeAlternatives(a, &left.value, reference_root, fixture, started, ended);
    try normalizeAlternatives(a, &right.value, candidate, fixture, started, ended);
    const normalized_left = try std.json.Stringify.valueAlloc(a, left.value, .{});
    const normalized_right = try std.json.Stringify.valueAlloc(a, right.value, .{});
    if (!std.mem.eql(u8, normalized_left, normalized_right)) {
        if (fixture.diagnostics) std.debug.print("native/dpkg alternatives mismatch in {s}\n", .{destination});
        return error.NativeDpkgMismatch;
    }
}

pub const Scenario = struct {
    fixture: *foundation.Fixture,
    name: []const u8,
    executable: []const u8,
    dpkg: []const u8,
    architecture: []const u8,
    helper: bool = false,
    alternatives: bool = false,
    alternatives_started: ?i64 = null,
    reference_root: []u8,
    native_root: []u8,
    index: usize = 0,

    pub fn init(fixture: *foundation.Fixture, name: []const u8, executable: []const u8, dpkg: []const u8, architecture: []const u8, helper: bool) !Scenario {
        return initWith(fixture, name, executable, dpkg, architecture, helper, false);
    }

    pub fn initWith(fixture: *foundation.Fixture, name: []const u8, executable: []const u8, dpkg: []const u8, architecture: []const u8, helper: bool, bootstrap: bool) !Scenario {
        const left = try path(fixture.allocator, name, "reference");
        defer fixture.allocator.free(left);
        const right = try path(fixture.allocator, name, "native");
        defer fixture.allocator.free(right);
        const reference_root = try fixture.makeRoot(left, architecture);
        errdefer fixture.allocator.free(reference_root);
        const native_root = try fixture.makeRoot(right, architecture);
        errdefer fixture.allocator.free(native_root);
        for ([_][]const u8{ left, right }) |relative| {
            const record = try path(fixture.allocator, relative, trace);
            defer fixture.allocator.free(record);
            try fixtureFile(fixture, record, "", 0o644);
            if (!bootstrap) try copyProgram(fixture, relative, "/bin/sh", "/bin/sh");
            if (helper) try copyProgram(fixture, relative, "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
        }
        return .{
            .fixture = fixture,
            .name = name,
            .executable = executable,
            .dpkg = dpkg,
            .architecture = architecture,
            .helper = helper,
            .reference_root = reference_root,
            .native_root = native_root,
        };
    }

    pub fn deinit(self: *Scenario) void {
        self.fixture.allocator.free(self.reference_root);
        self.fixture.allocator.free(self.native_root);
    }

    pub fn seed(self: *Scenario, archive: []const u8) !void {
        return self.seedWith(archive, true);
    }

    pub fn seedWith(self: *Scenario, archive: []const u8, configure: bool) !void {
        const install_phase: Phase = .{ .operation = if (configure) "install" else "unpack", .archives = &.{archive}, .triggers = self.helper };
        for ([_][]const u8{ self.reference_root, self.native_root }, [_][]const u8{ "reference", "native" }) |root, label| {
            const destination = try std.fmt.allocPrint(self.fixture.allocator, "{s}/seed-{d}-{s}", .{ self.name, self.index, label });
            defer self.fixture.allocator.free(destination);
            try self.fixture.directory(destination);
            if (try reference(self.fixture, self.dpkg, root, install_phase, destination) != 0) return error.SeedFailed;
            const record = try std.fmt.allocPrint(self.fixture.allocator, "{s}/{s}", .{ root[self.fixture.path.len + 1 ..], trace });
            defer self.fixture.allocator.free(record);
            try fixtureFile(self.fixture, record, "", 0o644);
        }
        self.index += 1;
    }

    pub fn phase(self: *Scenario, input: Phase, expected_failure: bool) !void {
        const destination = try std.fmt.allocPrint(self.fixture.allocator, "{s}/{d}-{s}", .{ self.name, self.index, input.operation });
        defer self.fixture.allocator.free(destination);
        try self.fixture.directory(destination);
        self.index += 1;
        var links: std.ArrayList(RollbackLink) = .empty;
        defer links.deinit(self.fixture.allocator);
        for (input.rollback_links) |relative| {
            var directory = try foundation.guardedRoot(self.fixture.io, self.reference_root);
            defer directory.close(self.fixture.io);
            const entry = try (root_fs.Root.init(self.fixture.io, directory)).entry(try root_fs.Path.init(relative));
            if (entry.kind != .sym_link) return error.RollbackLinkTypeChanged;
            try links.append(self.fixture.allocator, .{ .path = relative, .original = @intCast(entry.modified_nanoseconds) });
        }
        for (input.created_rollback_links) |relative| {
            const absolute = try std.fmt.allocPrint(self.fixture.allocator, "{s}/{s}", .{ self.reference_root, relative });
            defer self.fixture.allocator.free(absolute);
            if (std.Io.Dir.cwd().statFile(self.fixture.io, absolute, .{ .follow_symlinks = false })) |_|
                return error.RollbackLinkAlreadyExists
            else |err| if (err != error.FileNotFound) return err;
            try links.append(self.fixture.allocator, .{ .path = relative, .original = null });
        }
        const started: i64 = @intCast(std.Io.Clock.real.now(self.fixture.io).nanoseconds);
        if (self.alternatives and self.alternatives_started == null) self.alternatives_started = started;
        var status: u8 = 0;
        if (input.reference_groups) |groups| {
            for (groups, 0..) |archives, index| {
                const group_destination = try std.fmt.allocPrint(self.fixture.allocator, "{s}/group-{d}", .{ destination, index });
                defer self.fixture.allocator.free(group_destination);
                try self.fixture.directory(group_destination);
                var group = input;
                group.archives = archives;
                group.reference_groups = null;
                status = try reference(self.fixture, self.dpkg, self.reference_root, group, group_destination);
                if (status != 0) break;
            }
        } else status = try reference(self.fixture, self.dpkg, self.reference_root, input, destination);
        if ((status != 0) != expected_failure) return error.UnexpectedReferenceOutcome;
        var outcome = try native(self.fixture, self.executable, self.native_root, self.architecture, input, destination);
        defer outcome.deinit();
        if (expected_failure) {
            if (!std.mem.eql(u8, outcome.value.outcome, "script_failed") and
                (!self.helper or !std.mem.eql(u8, outcome.value.outcome, "trigger_failed")))
                return error.UnexpectedNativeOutcome;
        } else if (!std.mem.eql(u8, outcome.value.outcome, "applied")) {
            std.debug.print("{s}/{s}: {s}: {s}\n", .{ self.name, input.operation, outcome.value.outcome, outcome.value.detail });
            return error.UnexpectedNativeOutcome;
        }
        try assertNoActiveEvidence(self.fixture, self.native_root);
        const ended: i64 = @intCast(std.Io.Clock.real.now(self.fixture.io).nanoseconds);
        const result = if (self.alternatives)
            compareAlternatives(self.fixture, self.reference_root, self.native_root, destination, self.alternatives_started.?, ended)
        else if (links.items.len == 0)
            compare(self.fixture, self.reference_root, self.native_root, destination, self.helper)
        else
            compareRollback(self.fixture, self.reference_root, self.native_root, destination, links.items, started, ended);
        result catch |err| {
            self.fixture.retain = true;
            return err;
        };
        std.debug.print("{s}/{s}: native/dpkg parity passed\n", .{ self.name, input.operation });
    }
};

pub fn prerequisites(init: std.process.Init, allocator: std.mem.Allocator, pinned: ?[]const u8) !struct { architecture: []u8, executable: []const u8, before: [32]u8 } {
    if (std.os.linux.geteuid() != 0) return error.RequiresRootForChroot;
    const host = try foundation.hostDpkg(allocator, init.io, init.environ_map.get("PATH") orelse "/usr/bin:/bin");
    defer allocator.free(host);
    const arch = try foundation.hostArchitecture(allocator, init.io, host);
    const executable = try foundation.selectReference(allocator, init.io, pinned, arch, host);
    return .{
        .architecture = arch,
        .executable = try allocator.dupe(u8, executable),
        .before = try foundation.hostStatusDigest(allocator, init.io),
    };
}

pub fn assertHostUnchanged(allocator: std.mem.Allocator, io: std.Io, before: [32]u8) !void {
    const after = try foundation.hostStatusDigest(allocator, io);
    if (!std.mem.eql(u8, &before, &after)) return error.HostDpkgStatusChanged;
}

test "root guard refuses the host and unguarded roots before spawning reference" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, @import("native_test_options").repository);
    defer fixture.deinit();
    try std.testing.expectError(error.NotDisposableRoot, reference(&fixture, "/usr/bin/dpkg", "/", .{ .operation = "purge" }, "unused"));
}

test "trace and package database mismatches cannot be hidden by a success report" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, @import("native_test_options").repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("native", "amd64");
    defer std.testing.allocator.free(right);
    try fixture.write("reference/" ++ trace, "postinst\t2\t9:configure\t0:\tpayload=v1\n", 0o644);
    try fixture.write("native/" ++ trace, "postinst\t1\t9:configure\tpayload=v1\n", 0o644);
    try fixture.directory("observation");
    try std.testing.expectError(error.NativeDpkgMismatch, compare(&fixture, left, right, "observation", false));
    try fixture.write("native/" ++ trace, "postinst\t2\t9:configure\t0:\tpayload=v1\n", 0o644);
    try fixture.write("native/var/lib/dpkg/triggers/Unincorp", "malformed\x00queue -\n", 0o644);
    try std.testing.expectError(error.NativeDpkgMismatch, compare(&fixture, left, right, "observation", false));
}

test "empty retained package lists are observable rather than panicking" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, @import("native_test_options").repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("native", "amd64");
    defer std.testing.allocator.free(right);
    for ([_][]const u8{ "reference", "native" }) |label| {
        const filename = try std.fmt.allocPrint(std.testing.allocator, "{s}/var/lib/dpkg/info/demo.list", .{label});
        defer std.testing.allocator.free(filename);
        try fixture.write(filename, "", 0o644);
    }
    try fixture.directory("observation");
    try compare(&fixture, left, right, "observation", false);
    try fixture.write("native/var/lib/dpkg/info/demo.list", "/usr\n", 0o644);
    try std.testing.expectError(error.NativeDpkgMismatch, compare(&fixture, left, right, "observation", false));
}

test "rollback link timestamp exceptions are bounded to named symlinks and operation clock" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, @import("native_test_options").repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("native", "amd64");
    defer std.testing.allocator.free(right);
    try fixture.dir.symLink(fixture.io, "target", "reference/link", .{});
    try fixture.dir.symLink(fixture.io, "target", "native/link", .{});
    for ([_][]const u8{ left, right }, [_]i128{ 110, 120 }) |path_name, time| {
        var dir = try foundation.guardedRoot(fixture.io, path_name);
        defer dir.close(fixture.io);
        try (root_fs.Root.init(fixture.io, dir)).applyMetadata(try root_fs.Path.init("link"), .{ .modified_nanoseconds = time });
    }
    try fixture.directory("observation");
    try compareRollback(&fixture, left, right, "observation", &.{.{ .path = "link", .original = 100 }}, 105, 125);
    {
        var dir = try foundation.guardedRoot(fixture.io, right);
        defer dir.close(fixture.io);
        try (root_fs.Root.init(fixture.io, dir)).applyMetadata(try root_fs.Path.init("link"), .{ .modified_nanoseconds = 999 });
    }
    try std.testing.expectError(error.RollbackLinkTimeOutsideOperation, compareRollback(
        &fixture,
        left,
        right,
        "observation",
        &.{.{ .path = "link", .original = 100 }},
        105,
        125,
    ));
    try fixture.dir.deleteFile(fixture.io, "native/link");
    try fixture.write("native/link", "not a symlink", 0o644);
    try std.testing.expectError(error.RollbackLinkTypeChanged, compareRollback(
        &fixture,
        left,
        right,
        "observation",
        &.{.{ .path = "link", .original = 100 }},
        105,
        125,
    ));
}

test "non-rollback metadata, hardlinks, symlinks and script payload remain exact" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, @import("native_test_options").repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("native", "amd64");
    defer std.testing.allocator.free(right);
    try fixture.directory("observation");
    try fixtureFile(&fixture, "reference/file", "same bytes\n", 0o644);
    try fixtureFile(&fixture, "native/file", "same bytes\n", 0o644);
    try fixture.dir.setTimestamps(fixture.io, "native/file", .{
        .modify_timestamp = .{ .new = .{ .nanoseconds = (foundation.epoch + 1) * std.time.ns_per_s } },
    });
    try std.testing.expectError(error.NativeDpkgMismatch, compare(&fixture, left, right, "observation", false));
    try fixtureFile(&fixture, "native/file", "same bytes\n", 0o644);
    try std.Io.Dir.hardLink(fixture.dir, "reference/file", fixture.dir, "reference/hard", fixture.io, .{});
    try fixtureFile(&fixture, "native/hard", "same bytes\n", 0o644);
    try std.testing.expectError(error.NativeDpkgMismatch, compare(&fixture, left, right, "observation", false));
    try fixture.dir.deleteFile(fixture.io, "native/hard");
    try std.Io.Dir.hardLink(fixture.dir, "native/file", fixture.dir, "native/hard", fixture.io, .{});
    try fixture.dir.symLink(fixture.io, "file", "reference/symlink", .{});
    try fixture.dir.symLink(fixture.io, "hard", "native/symlink", .{});
    for ([_][]const u8{ left, right }) |path_name| {
        var dir = try foundation.guardedRoot(fixture.io, path_name);
        defer dir.close(fixture.io);
        try (root_fs.Root.init(fixture.io, dir)).applyMetadata(try root_fs.Path.init("symlink"), .{
            .modified_nanoseconds = foundation.epoch * std.time.ns_per_s,
        });
    }
    try std.testing.expectError(error.NativeDpkgMismatch, compare(&fixture, left, right, "observation", false));
    try fixture.dir.deleteFile(fixture.io, "native/symlink");
    try fixture.dir.symLink(fixture.io, "file", "native/symlink", .{});
    {
        var dir = try foundation.guardedRoot(fixture.io, right);
        defer dir.close(fixture.io);
        try (root_fs.Root.init(fixture.io, dir)).applyMetadata(try root_fs.Path.init("symlink"), .{
            .modified_nanoseconds = foundation.epoch * std.time.ns_per_s,
        });
    }
    try fixtureFile(&fixture, "reference/" ++ trace, "postinst\t2\t9:configure\t0:\tpayload=v1\n", 0o644);
    try fixtureFile(&fixture, "native/" ++ trace, "postinst\t2\t9:configure\t0:\tpayload=v2\n", 0o644);
    try std.testing.expectError(error.NativeDpkgMismatch, compare(&fixture, left, right, "observation", false));
}

test "malformed diversion, override, package list, checksum and status cannot be normalized away" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, @import("native_test_options").repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("native", "amd64");
    defer std.testing.allocator.free(right);
    try fixture.directory("observation");
    for ([_]struct { path: []const u8, bytes: []const u8, expected: anyerror }{
        .{ .path = "var/lib/dpkg/diversions", .bytes = "/source\n/destination\n", .expected = error.InvalidDiversions },
        .{ .path = "var/lib/dpkg/statoverride", .bytes = "#1 #2 0640 /file\n#3 #4 0600 /file\n", .expected = error.InvalidStatoverride },
        .{ .path = "var/lib/dpkg/info/demo.list", .bytes = "relative\n", .expected = error.UnsafePackagePath },
        .{ .path = "var/lib/dpkg/info/demo.md5sums", .bytes = "broken checksum\n", .expected = error.InvalidMd5sums },
        .{ .path = "var/lib/dpkg/status", .bytes = "Version: 1\nVersion: 2\n", .expected = error.InvalidDeb822 },
    }) |entry| {
        const right_path = try path(std.testing.allocator, "native", entry.path);
        defer std.testing.allocator.free(right_path);
        try fixture.write(right_path, entry.bytes, 0o644);
        try std.testing.expectError(entry.expected, compare(&fixture, left, right, "observation", false));
        try fixture.dir.deleteFile(fixture.io, right_path);
    }
}

test "native request preserves ordered actions and fault boundary under root guard" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, @import("native_test_options").repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(root);
    try fixture.directory("output");
    try fixture.write("fake-driver", "#!/bin/sh\nreport=$(sed -n 's/.*\"report\":\"\\([^\"]*\\)\".*/\\1/p' \"$DEBZ_NATIVE_LIFECYCLE_REQUEST\")\n" ++
        "[ -n \"$report\" ] || exit 1\nprintf '{\"outcome\":\"applied\"}' > \"$report\"\n", 0o755);
    const driver = try fixture.absolute("fake-driver");
    defer std.testing.allocator.free(driver);
    const actions = [_]Action{
        .{ .sequence = 0, .kind = "unpack", .package = "provider", .architecture = "amd64" },
        .{ .sequence = 1, .kind = "configure_pending", .package = "consumer", .architecture = "amd64" },
    };
    var report = try native(&fixture, driver, root, "amd64", .{
        .operation = "install",
        .archives = &.{"package.deb"},
        .ordered_actions = &actions,
        .fault = "after_script_before_record",
    }, "output");
    defer report.deinit();
    try std.testing.expectEqualStrings("applied", report.value.outcome);
    const request = try read(&fixture, "output/native.request.json", 64 * 1024);
    defer std.testing.allocator.free(request);
    var parsed = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, request, .{});
    defer parsed.deinit();
    try std.testing.expectEqualStrings("after_script_before_record", parsed.value.object.get("fault").?.string);
    const ordered_actions = parsed.value.object.get("ordered_actions").?.array.items;
    try std.testing.expectEqual(@as(usize, 2), ordered_actions.len);
    try std.testing.expectEqualStrings("configure_pending", ordered_actions[1].object.get("kind").?.string);
}

test "published script compensation schema retains bounded invocations and hash identities" {
    const io = std.testing.io;
    var file = try std.Io.Dir.cwd().openFile(io, "schema/native-transaction-program-v1.json", .{ .follow_symlinks = false });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    const bytes = try reader.interface.allocRemaining(std.testing.allocator, .limited(1024 * 1024));
    defer std.testing.allocator.free(bytes);
    var document = try std.json.parseFromSlice(std.json.Value, std.testing.allocator, bytes, .{});
    defer document.deinit();
    const definitions = document.value.object.get("$defs").?.object;
    const script_failure = definitions.get("scriptFailure").?.object.get("properties").?.object;
    const compensations = script_failure.get("compensations").?.object;
    try std.testing.expectEqual(@as(i64, 8), compensations.get("maxItems").?.integer);
    try std.testing.expectEqualStrings("#/$defs/unwind", compensations.get("items").?.object.get("$ref").?.string);
    const rollback = script_failure.get("rollback_after_compensations").?.object.get("oneOf").?.array.items;
    try std.testing.expectEqual(@as(i64, 0), rollback[1].object.get("minimum").?.integer);
    try std.testing.expectEqual(@as(i64, 8), rollback[1].object.get("maximum").?.integer);
    const unwind = definitions.get("unwind").?.object.get("properties").?.object;
    try std.testing.expectEqualStrings("#/$defs/sha256", unwind.get("script_sha256").?.object.get("$ref").?.string);
    try std.testing.expectEqual(@as(i64, 8), unwind.get("arguments").?.object.get("maxItems").?.integer);
    try std.testing.expectEqual(@as(i64, 512), unwind.get("arguments").?.object.get("items").?.object.get("maxLength").?.integer);
    try std.testing.expectEqualStrings("^[0-9a-f]{64}$", definitions.get("sha256").?.object.get("pattern").?.string);
}
