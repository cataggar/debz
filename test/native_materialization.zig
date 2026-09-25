const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const root_fs = @import("debz").root_fs;
const options = @import("native_test_options");

fn bytes(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    var file = try std.Io.Dir.openFileAbsolute(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    var reader = file.reader(io, &.{});
    return reader.interface.allocRemaining(allocator, .limited(64 * 1024 * 1024));
}

fn name(allocator: std.mem.Allocator, prefix: []const u8, suffix: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/{s}", .{ prefix, suffix });
}

fn assertApplied(report: foundation.Outcome, operation: []const u8) !void {
    if (!std.mem.eql(u8, report.outcome, "applied")) {
        std.debug.print("{s}: native did not apply: {s} ({s})\n", .{
            operation, report.outcome, report.detail,
        });
        return error.NativeNotApplied;
    }
}

fn referencePreparation(allocator: std.mem.Allocator) ![]u8 {
    return std.fs.path.join(allocator, &.{ options.repository, "tools/prepare-native-dpkg.py" });
}

fn expectCliFailure(fixture: *foundation.Fixture, argv: []const []const u8, log: []const u8, diagnostic: []const u8) !void {
    fixture.diagnostics = false;
    try std.testing.expectError(error.ChildFailed, fixture.run(argv, log, 10));
    const path = try fixture.absolute(log);
    defer fixture.allocator.free(path);
    const output = try bytes(fixture.allocator, fixture.io, path);
    defer fixture.allocator.free(output);
    if (std.mem.indexOf(u8, output, diagnostic) == null) {
        std.debug.print("expected diagnostic {s}, found {s}\n", .{ diagnostic, output[0..@min(output.len, 1024)] });
        return error.MissingReferenceDiagnostic;
    }
}

fn assertAbsent(fixture: foundation.Fixture, path: []const u8) !void {
    if (fixture.dir.statFile(fixture.io, path, .{ .follow_symlinks = false })) |_| {
        return error.UnexpectedFixtureArtifact;
    } else |err| if (err != error.FileNotFound) return err;
}

fn execute(
    fixture: *foundation.Fixture,
    executable: []const u8,
    reference_dpkg: []const u8,
    arch: []const u8,
) !void {
    const allocator = fixture.allocator;
    const archive1 = try fixture.makePackage(arch, "1", .data);
    defer allocator.free(archive1);
    const archive2 = try fixture.makePackage(arch, "2", .data);
    defer allocator.free(archive2);
    const cases = [_]struct {
        operation: []const u8,
        initial: ?[]const u8,
        final: []const u8,
    }{
        .{ .operation = "install", .initial = null, .final = archive1 },
        .{ .operation = "upgrade", .initial = archive1, .final = archive2 },
        .{ .operation = "downgrade", .initial = archive2, .final = archive1 },
        .{ .operation = "reinstall", .initial = archive1, .final = archive1 },
    };
    for (cases) |scenario| {
        const root_name = try name(allocator, scenario.operation, "reference");
        defer allocator.free(root_name);
        const candidate_name = try name(allocator, scenario.operation, "native");
        defer allocator.free(candidate_name);
        const reference_root = try fixture.makeRoot(root_name, arch);
        defer allocator.free(reference_root);
        const candidate_root = try fixture.makeRoot(candidate_name, arch);
        defer allocator.free(candidate_root);
        if (scenario.initial) |seed| {
            const seed_reference_log = try name(allocator, scenario.operation, "reference.seed.log");
            defer allocator.free(seed_reference_log);
            const seed_native_log = try name(allocator, scenario.operation, "native.seed.log");
            defer allocator.free(seed_native_log);
            try foundation.reference(fixture.*, reference_dpkg, reference_root, seed, seed_reference_log, true);
            try foundation.reference(fixture.*, reference_dpkg, candidate_root, seed, seed_native_log, true);
            if (std.mem.eql(u8, scenario.operation, "reinstall")) {
                const reference_file = try name(allocator, root_name, foundation.payload ++ "/data");
                defer allocator.free(reference_file);
                const candidate_file = try name(allocator, candidate_name, foundation.payload ++ "/data");
                defer allocator.free(candidate_file);
                try fixture.write(reference_file, "local modification\n", 0o644);
                try fixture.write(candidate_file, "local modification\n", 0o644);
            }
        }
        const reference_log = try name(allocator, scenario.operation, "reference.log");
        defer allocator.free(reference_log);
        try foundation.reference(fixture.*, reference_dpkg, reference_root, scenario.final, reference_log, false);
        var report = try foundation.native(
            fixture,
            executable,
            candidate_root,
            scenario.final,
            arch,
            scenario.operation,
            scenario.operation,
        );
        defer report.deinit();
        try assertApplied(report.value, scenario.operation);
        try foundation.compare(fixture.*, reference_root, candidate_root, scenario.operation);
        try foundation.assertDirectoryMtime(fixture.io, reference_root, candidate_root, foundation.payload ++ "/empty");
        std.debug.print("{s}: native/dpkg parity passed\n", .{scenario.operation});
    }

    const sequence_reference = try fixture.makeRoot("sequence/reference", arch);
    defer allocator.free(sequence_reference);
    const sequence_native = try fixture.makeRoot("sequence/native", arch);
    defer allocator.free(sequence_native);
    const steps = [_]struct { operation: []const u8, archive: []const u8 }{
        .{ .operation = "install", .archive = archive1 },
        .{ .operation = "upgrade", .archive = archive2 },
        .{ .operation = "downgrade", .archive = archive1 },
        .{ .operation = "reinstall", .archive = archive1 },
    };
    var lock_identity: ?u64 = null;
    for (steps, 0..) |step, index| {
        const case = try std.fmt.allocPrint(allocator, "sequence/{d}-{s}", .{ index, step.operation });
        defer allocator.free(case);
        try fixture.directory(case);
        const reference_log = try name(allocator, case, "reference.log");
        defer allocator.free(reference_log);
        try foundation.reference(fixture.*, reference_dpkg, sequence_reference, step.archive, reference_log, false);
        var report = try foundation.native(
            fixture,
            executable,
            sequence_native,
            step.archive,
            arch,
            step.operation,
            case,
        );
        defer report.deinit();
        try assertApplied(report.value, step.operation);
        var root_dir = try foundation.guardedRoot(fixture.io, sequence_native);
        defer root_dir.close(fixture.io);
        const root: root_fs.Root = .init(fixture.io, root_dir);
        const lock = try root.entry(try root_fs.Path.init("var/lib/debz/root-operation.lock"));
        if (lock_identity) |prior| {
            if (prior != lock.inode) return error.LockInodeChanged;
        }
        lock_identity = lock.inode;
        try foundation.compare(fixture.*, sequence_reference, sequence_native, case);
        try foundation.assertDirectoryMtime(fixture.io, sequence_reference, sequence_native, foundation.payload ++ "/empty");
    }
    std.debug.print("repeated unpack: native/dpkg parity passed\n", .{});

    for ([_]foundation.Fixture.Feature{ .conffile, .script, .zero_time }) |feature| {
        const feature_name = @tagName(feature);
        const archive = try fixture.makePackage(arch, "1", feature);
        defer allocator.free(archive);
        const root_name = try name(allocator, feature_name, "native");
        defer allocator.free(root_name);
        const candidate = try fixture.makeRoot(root_name, arch);
        defer allocator.free(candidate);
        const before = try foundation.capture(allocator, fixture.io, candidate);
        defer allocator.free(before);
        var report = try foundation.native(
            fixture,
            executable,
            candidate,
            archive,
            arch,
            "install",
            feature_name,
        );
        defer report.deinit();
        if (!std.mem.eql(u8, report.value.outcome, "handoff") and
            !std.mem.eql(u8, report.value.outcome, "refused"))
            return error.UnsafeNativeOutcome;
        if (feature == .zero_time and (!std.mem.eql(u8, report.value.outcome, "refused") or
            !std.mem.eql(u8, report.value.detail, "zero_directory_timestamp_unsupported")))
            return error.MissingExplicitRefusal;
        const after = try foundation.capture(allocator, fixture.io, candidate);
        defer allocator.free(after);
        if (!std.mem.eql(u8, before, after)) return error.HandoffChangedRoot;
        var root_dir = try foundation.guardedRoot(fixture.io, candidate);
        defer root_dir.close(fixture.io);
        const root: root_fs.Root = .init(fixture.io, root_dir);
        for ([_][]const u8{ "root-operation-v1.json", "root-mutation-v1.json" }) |evidence| {
            const path = try name(allocator, "var/lib/debz", evidence);
            defer allocator.free(path);
            if (try root.entryIfExists(try root_fs.Path.init(path)) != null)
                return error.StrandedHandoffEvidence;
        }
        std.debug.print("{s}: pre-mutation handoff passed\n", .{feature_name});
    }

    const invalid_reference = try fixture.makeRoot("truncated/reference", arch);
    defer allocator.free(invalid_reference);
    const invalid_native = try fixture.makeRoot("truncated/native", arch);
    defer allocator.free(invalid_native);
    const before_invalid = try foundation.capture(allocator, fixture.io, invalid_native);
    defer allocator.free(before_invalid);
    const archive_bytes = try bytes(allocator, fixture.io, archive1);
    defer allocator.free(archive_bytes);
    try fixture.write("truncated/truncated.deb", archive_bytes[0 .. archive_bytes.len / 2], 0o644);
    const truncated = try fixture.absolute("truncated/truncated.deb");
    defer allocator.free(truncated);
    fixture.diagnostics = false;
    defer fixture.diagnostics = true;
    if (foundation.reference(
        fixture.*,
        reference_dpkg,
        invalid_reference,
        truncated,
        "truncated/reference.log",
        false,
    )) |_| {
        return error.ReferenceAcceptedTruncatedArchive;
    } else |err| if (err != error.ChildFailed) return err;
    if (foundation.native(
        fixture,
        executable,
        invalid_native,
        truncated,
        arch,
        "install",
        "truncated",
    )) |result| {
        var unexpected = result;
        unexpected.deinit();
        return error.NativeAcceptedTruncatedArchive;
    } else |err| if (err != error.ChildFailed) return err;
    const after_invalid = try foundation.capture(allocator, fixture.io, invalid_native);
    defer allocator.free(after_invalid);
    if (!std.mem.eql(u8, before_invalid, after_invalid))
        return error.TruncatedArchiveChangedNativeRoot;
    if (fixture.dir.statFile(fixture.io, "truncated/native.report.json", .{})) |_| {
        return error.UnexpectedTruncatedArchiveReport;
    } else |err| if (err != error.FileNotFound) return err;
    std.debug.print("truncated archive: both refused; native root unchanged\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var args = init.minimal.args.iterate();
    _ = args.next();
    const executable = args.next() orelse return error.MissingNativeTestExecutable;
    var reference_dpkg_path: ?[]const u8 = null;
    if (args.next()) |option| {
        if (!std.mem.eql(u8, option, "--reference-dpkg"))
            return error.InvalidArguments;
        reference_dpkg_path = args.next() orelse return error.InvalidArguments;
    }
    if (args.next() != null) return error.InvalidArguments;
    const host_dpkg = try foundation.hostDpkg(allocator, init.io, init.environ_map.get("PATH") orelse "/bin:/usr/bin");
    defer allocator.free(host_dpkg);
    const arch = try foundation.hostArchitecture(allocator, init.io, host_dpkg);
    const reference_dpkg = try foundation.selectReference(allocator, init.io, reference_dpkg_path, arch, host_dpkg);
    const before = try foundation.hostStatusDigest(allocator, init.io);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    try execute(&fixture, executable, reference_dpkg, arch);
    const after = try foundation.hostStatusDigest(allocator, init.io);
    if (!std.mem.eql(u8, &before, &after)) return error.HostDpkgStatusChanged;
}

test "guarded roots reject host root, wrong guard and symlink" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const path = try fixture.makeRoot("root", "amd64");
    defer std.testing.allocator.free(path);
    try std.testing.expectError(error.NotDisposableRoot, foundation.guardedRoot(std.testing.io, "/"));
    try fixture.write("root/" ++ foundation.guard, "different\n", 0o600);
    try std.testing.expectError(error.NotDisposableRoot, foundation.guardedRoot(std.testing.io, path));
    try fixture.dir.deleteFile(std.testing.io, "root/" ++ foundation.guard);
    try fixture.dir.symLink(std.testing.io, "/etc/passwd", "root/" ++ foundation.guard, .{});
    try std.testing.expectError(error.NotDisposableRoot, foundation.guardedRoot(std.testing.io, path));
    try fixture.dir.symLink(std.testing.io, "root", "linked-root", .{ .is_directory = true });
    const linked = try fixture.absolute("linked-root");
    defer std.testing.allocator.free(linked);
    try std.testing.expectError(error.NotDisposableRoot, foundation.guardedRoot(std.testing.io, linked));
}

test "reference refuses unsafe roots before spawning the selected dpkg" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(root);
    const script = try std.fmt.allocPrint(std.testing.allocator, "#!/bin/sh\nprintf spawned > '{s}/spawned'\n", .{fixture.path});
    defer std.testing.allocator.free(script);
    try fixture.write("selected-dpkg", script, 0o755);
    const selected = try fixture.absolute("selected-dpkg");
    defer std.testing.allocator.free(selected);
    try fixture.write("reference/" ++ foundation.guard, "invalid fixture guard\n", 0o600);
    try std.testing.expectError(error.NotDisposableRoot, foundation.reference(
        fixture,
        selected,
        root,
        "unreadable.deb",
        "pre-spawn.log",
        false,
    ));
    try std.testing.expectError(error.NotDisposableRoot, foundation.reference(
        fixture,
        selected,
        "/",
        "unreadable.deb",
        "host-spawn.log",
        false,
    ));
    try assertAbsent(fixture, "pre-spawn.log");
    try assertAbsent(fixture, "host-spawn.log");
    try assertAbsent(fixture, "spawned");
}

test "selected reference and fixture PATH remain bound to the disposable root" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(root);
    const selected = try fixture.absolute("selected-dpkg");
    defer std.testing.allocator.free(selected);
    try fixture.write("selected-dpkg", "#!/bin/sh\nprintf '%s\\n' \"$0\" \"$PATH\" \"$@\"\n", 0o755);
    try foundation.reference(fixture, selected, root, "fixture.deb", "selected.log", false);
    const output_path = try fixture.absolute("selected.log");
    defer std.testing.allocator.free(output_path);
    const output = try bytes(std.testing.allocator, std.testing.io, output_path);
    defer std.testing.allocator.free(output);
    const rooted = try std.fmt.allocPrint(std.testing.allocator, "--root={s}", .{root});
    defer std.testing.allocator.free(rooted);
    for ([_][]const u8{ selected, rooted, "--force-not-root", "--unpack", "/usr/sbin:/usr/bin:/sbin:/bin" }) |value|
        try std.testing.expect(std.mem.indexOf(u8, output, value) != null);
}

test "PATH-selected host dpkg supplies architecture and remains the executed reference" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const fake = try fixture.absolute("bin/dpkg");
    defer std.testing.allocator.free(fake);
    try fixture.write(
        "bin/dpkg",
        "#!/bin/sh\ncase \"$1\" in\n" ++
            "  --print-architecture) printf 'arm64\\n' ;;\n" ++
            "  --version) printf 'dpkg (Debian) version 1.23.7 (arm64).\\n' ;;\n" ++
            "  *) printf '%s\\n' \"$0\" \"$PATH\" \"$@\" ;;\n" ++
            "esac\n",
        0o755,
    );
    try fixture.write("noexec/dpkg", "#!/bin/sh\nexit 1\n", 0o644);
    const search = try std.fmt.allocPrint(std.testing.allocator, "{s}/noexec:{s}/bin:/usr/bin", .{ fixture.path, fixture.path });
    defer std.testing.allocator.free(search);
    const selected = try foundation.hostDpkg(std.testing.allocator, std.testing.io, search);
    defer std.testing.allocator.free(selected);
    try std.testing.expectEqualStrings(fake, selected);
    const architecture = try foundation.hostArchitecture(std.testing.allocator, std.testing.io, selected);
    defer std.testing.allocator.free(architecture);
    try std.testing.expectEqualStrings("arm64", architecture);
    try std.testing.expectEqualStrings(selected, try foundation.selectReference(
        std.testing.allocator,
        std.testing.io,
        null,
        architecture,
        selected,
    ));
    const root = try fixture.makeRoot("reference", architecture);
    defer std.testing.allocator.free(root);
    try foundation.reference(fixture, selected, root, "fixture.deb", "reference.log", false);
    const log = try fixture.absolute("reference.log");
    defer std.testing.allocator.free(log);
    const result = try bytes(std.testing.allocator, std.testing.io, log);
    defer std.testing.allocator.free(result);
    try std.testing.expect(std.mem.indexOf(u8, result, fake) != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "--unpack") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "/usr/sbin:/usr/bin:/sbin:/bin") != null);
    const missing = try std.fmt.allocPrint(std.testing.allocator, "{s}/missing", .{fixture.path});
    defer std.testing.allocator.free(missing);
    try std.testing.expectError(error.ReferenceDpkgNotFound, foundation.hostDpkg(std.testing.allocator, std.testing.io, missing));
}

test "filesystem comparison detects payload, hardlink and empty directory timestamp differences" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const left = try fixture.makeRoot("left", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("right", "amd64");
    defer std.testing.allocator.free(right);
    for ([_][]const u8{ "left", "right" }) |root| {
        const file = try name(std.testing.allocator, root, foundation.payload ++ "/data");
        defer std.testing.allocator.free(file);
        try fixture.write(file, "payload\n", 0o644);
        try fixture.dir.setTimestamps(std.testing.io, file, .{
            .modify_timestamp = .{ .new = .{ .nanoseconds = foundation.epoch * std.time.ns_per_s } },
        });
        const empty = try name(std.testing.allocator, root, foundation.payload ++ "/empty");
        defer std.testing.allocator.free(empty);
        try fixture.directory(empty);
        try fixture.dir.setTimestamps(std.testing.io, empty, .{
            .modify_timestamp = .{ .new = .{ .nanoseconds = foundation.epoch * std.time.ns_per_s } },
        });
    }
    try foundation.compare(fixture, left, right, "equal");
    try foundation.assertDirectoryMtime(std.testing.io, left, right, foundation.payload ++ "/empty");
    try fixture.write("right/" ++ foundation.payload ++ "/data", "wrong bytes\n", 0o644);
    try std.testing.expectError(error.NativeDpkgMismatch, foundation.compare(fixture, left, right, "different"));
    try fixture.write("right/" ++ foundation.payload ++ "/data", "payload\n", 0o644);
    try fixture.dir.setTimestamps(std.testing.io, "right/" ++ foundation.payload ++ "/data", .{
        .modify_timestamp = .{ .new = .{ .nanoseconds = foundation.epoch * std.time.ns_per_s } },
    });
    try fixture.dir.setTimestamps(std.testing.io, "right/" ++ foundation.payload ++ "/empty", .{
        .modify_timestamp = .{ .new = .{ .nanoseconds = 1 * std.time.ns_per_s } },
    });
    try foundation.compare(fixture, left, right, "directory");
    try std.testing.expectError(error.EmptyDirectoryMtimeMismatch, foundation.assertDirectoryMtime(
        std.testing.io,
        left,
        right,
        foundation.payload ++ "/empty",
    ));
}

test "canonical comparison detects broken hardlink group" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const left = try fixture.makeRoot("left", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("right", "amd64");
    defer std.testing.allocator.free(right);
    for ([_][]const u8{ "left", "right" }) |root| {
        const data = try name(std.testing.allocator, root, "usr/share/data");
        defer std.testing.allocator.free(data);
        try fixture.write(data, "same bytes\n", 0o644);
        const link = try name(std.testing.allocator, root, "usr/share/data.link");
        defer std.testing.allocator.free(link);
        if (std.mem.eql(u8, root, "left")) {
            try std.Io.Dir.hardLink(fixture.dir, data, fixture.dir, link, std.testing.io, .{});
        } else {
            try fixture.write(link, "same bytes\n", 0o644);
        }
        for ([_][]const u8{ data, link }) |path| try fixture.dir.setTimestamps(std.testing.io, path, .{
            .modify_timestamp = .{ .new = .{ .nanoseconds = foundation.epoch * std.time.ns_per_s } },
        });
    }
    const expected = try foundation.capture(std.testing.allocator, std.testing.io, left);
    defer std.testing.allocator.free(expected);
    const observed = try foundation.capture(std.testing.allocator, std.testing.io, right);
    defer std.testing.allocator.free(observed);
    try std.testing.expect(!std.mem.eql(u8, expected, observed));
}

test "dpkg metadata normalization is order-independent and rejects malformed records" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const left = try fixture.makeRoot("left", "amd64");
    defer std.testing.allocator.free(left);
    const right = try fixture.makeRoot("right", "amd64");
    defer std.testing.allocator.free(right);
    try fixture.write(
        "left/var/lib/dpkg/diversions",
        "/usr/bin/z\n/usr/bin/z.distrib\n:\n/usr/bin/a\n/usr/bin/a.distrib\n:\n",
        0o644,
    );
    try fixture.write(
        "right/var/lib/dpkg/diversions",
        "/usr/bin/a\n/usr/bin/a.distrib\n:\n/usr/bin/z\n/usr/bin/z.distrib\n:\n",
        0o644,
    );
    try fixture.write("left/var/lib/dpkg/statoverride", "root root 0755 /usr/bin/z\nroot root 0644 /usr/bin/a\n", 0o644);
    try fixture.write("right/var/lib/dpkg/statoverride", "root root 0644 /usr/bin/a\nroot root 0755 /usr/bin/z\n", 0o644);
    try fixture.write("left/var/lib/dpkg/info/demo.list", "/usr/bin/z\n/usr/bin/a\n", 0o644);
    try fixture.write("right/var/lib/dpkg/info/demo.list", "/usr/bin/a\n/usr/bin/z\n", 0o644);
    const expected = try foundation.capture(std.testing.allocator, std.testing.io, left);
    defer std.testing.allocator.free(expected);
    const actual = try foundation.capture(std.testing.allocator, std.testing.io, right);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
    try fixture.write("right/var/lib/dpkg/diversions", "/usr/bin/a\n/usr/bin/a.distrib\n", 0o644);
    try std.testing.expectError(
        error.InvalidDiversions,
        foundation.capture(std.testing.allocator, std.testing.io, right),
    );
    try fixture.write("right/var/lib/dpkg/diversions", "/usr/bin/a\n/usr/bin/a.distrib\n:\n\n", 0o644);
    try std.testing.expectError(
        error.InvalidDiversions,
        foundation.capture(std.testing.allocator, std.testing.io, right),
    );
    try fixture.write("right/var/lib/dpkg/diversions", "", 0o644);
    try fixture.write("right/var/lib/dpkg/statoverride", "root root 0755 /usr/bin/a\n\n", 0o644);
    try std.testing.expectError(
        error.InvalidStatoverride,
        foundation.capture(std.testing.allocator, std.testing.io, right),
    );
    try fixture.write("right/var/lib/dpkg/statoverride", "", 0o644);
    try fixture.write("right/var/lib/dpkg/info/demo.list", "/usr/bin/a\n/usr/bin/a\n", 0o644);
    try std.testing.expectError(
        error.DuplicatePackagePath,
        foundation.capture(std.testing.allocator, std.testing.io, right),
    );
}

test "executed dpkg-deb fixture has explicit modes and a hardlink manifest" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const archive = try fixture.makePackage("amd64", "1", .data);
    defer std.testing.allocator.free(archive);
    const source = foundation.package ++ "_1_data.source";
    const data = source ++ "/" ++ foundation.payload ++ "/data";
    const link = source ++ "/" ++ foundation.payload ++ "/data.link";
    const data_entry = try fixture.dir.statFile(std.testing.io, data, .{ .follow_symlinks = false });
    const link_entry = try fixture.dir.statFile(std.testing.io, link, .{ .follow_symlinks = false });
    try std.testing.expectEqual(data_entry.inode, link_entry.inode);
    try std.testing.expectEqual(@as(u32, 0o755), (try fixture.dir.statFile(std.testing.io, source ++ "/DEBIAN", .{})).permissions.toMode() & 0o777);
    try std.testing.expectEqual(
        @as(u32, 0o600),
        (try fixture.dir.statFile(std.testing.io, source ++ "/" ++ foundation.payload ++ "/mode", .{})).permissions.toMode() & 0o777,
    );
    const manifest_path = try fixture.absolute(source ++ "/DEBIAN/md5sums");
    defer std.testing.allocator.free(manifest_path);
    const manifest = try bytes(std.testing.allocator, std.testing.io, manifest_path);
    defer std.testing.allocator.free(manifest);
    try std.testing.expect(std.mem.indexOf(u8, manifest, "  " ++ foundation.payload ++ "/data\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, manifest, "  " ++ foundation.payload ++ "/data.link\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, manifest, "  " ++ foundation.payload ++ "/current\n") == null);
}

test "a missing, stale, or invalid native report and tampered pin fail closed" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("native", "amd64");
    defer std.testing.allocator.free(root);
    try fixture.write("fake-dpkg", "changed reference", 0o755);
    const selected = try fixture.absolute("fake-dpkg");
    defer std.testing.allocator.free(selected);
    try std.testing.expectError(
        error.ReferenceDigestMismatch,
        foundation.selectReference(std.testing.allocator, std.testing.io, selected, "amd64", "/usr/bin/dpkg"),
    );
    try std.testing.expectError(
        error.MissingNativeReport,
        foundation.native(&fixture, "/usr/bin/true", root, selected, "amd64", "install", "native"),
    );
    const script = try std.fmt.allocPrint(
        std.testing.allocator,
        "#!/bin/sh\nprintf '%s\\n' '{{\"outcome\":\"unknown\",\"detail\":\"bad\"}}' > '{s}/native/native.report.json'\n",
        .{fixture.path},
    );
    defer std.testing.allocator.free(script);
    try fixture.write("fake-native", script, 0o755);
    const fake_native = try fixture.absolute("fake-native");
    defer std.testing.allocator.free(fake_native);
    try std.testing.expectError(
        error.InvalidNativeReport,
        foundation.native(&fixture, fake_native, root, selected, "amd64", "install", "native"),
    );
    try std.testing.expectError(
        error.StaleNativeReport,
        foundation.native(&fixture, "/usr/bin/true", root, selected, "amd64", "install", "native"),
    );
}

test "production reference selection rejects tampered and symlinked dpkg before spawning" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const program = try referencePreparation(std.testing.allocator);
    defer std.testing.allocator.free(program);
    const script = try std.fmt.allocPrint(std.testing.allocator, "#!/bin/sh\nprintf called > '{s}/spawned'\n", .{fixture.path});
    defer std.testing.allocator.free(script);
    try fixture.write("changed-dpkg", script, 0o755);
    const selected = try fixture.absolute("changed-dpkg");
    defer std.testing.allocator.free(selected);
    try expectCliFailure(&fixture, &.{
        "python3", program, "--architecture", "arm64", "--verify-only", selected,
    }, "changed.log", "pinned reference digest mismatch");
    try fixture.dir.symLink(std.testing.io, selected, "symlink-dpkg", .{});
    const link = try fixture.absolute("symlink-dpkg");
    defer std.testing.allocator.free(link);
    try expectCliFailure(&fixture, &.{
        "python3", program, "--architecture", "arm64", "--verify-only", link,
    }, "symlink.log", "absolute, non-symlink path");
    try assertAbsent(fixture, "spawned");
}

test "old host dpkg remains a fallback but cannot establish named statoverride coverage" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const program = try referencePreparation(std.testing.allocator);
    defer std.testing.allocator.free(program);
    try fixture.write("bin/dpkg", "#!/bin/sh\nprintf 'dpkg (Debian) version 1.22.6 (arm64).\\n'\n", 0o755);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/bin:/usr/sbin:/usr/bin:/sbin:/bin", .{fixture.path});
    defer std.testing.allocator.free(path);
    try fixture.environment.put("PATH", path);
    try fixture.run(&.{
        "python3", program, "--architecture", "arm64", "--check-host",
    }, "fallback.log", 10);
    const selected_log = try fixture.absolute("fallback.log");
    defer std.testing.allocator.free(selected_log);
    const output = try bytes(std.testing.allocator, std.testing.io, selected_log);
    defer std.testing.allocator.free(output);
    const selected = try fixture.absolute("bin/dpkg");
    defer std.testing.allocator.free(selected);
    try std.testing.expect(std.mem.indexOf(u8, output, selected) != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "Native reference: dpkg (1.22.6)") != null);
    try expectCliFailure(&fixture, &.{
        "python3", program, "--architecture", "arm64", "--check-host", "--root-accounts",
    }, "old-accounts.log", "requires dpkg >= 1.22.16");
}

test "pinned archive digest is verified before any extraction" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const program = try referencePreparation(std.testing.allocator);
    defer std.testing.allocator.free(program);
    const root = try fixture.makeRoot("download", "arm64");
    defer std.testing.allocator.free(root);
    const archive = try fixture.absolute("download/untrusted.deb");
    defer std.testing.allocator.free(archive);
    try fixture.write("download/untrusted.deb", "not the pinned archive", 0o644);
    const stub = try std.fmt.allocPrint(std.testing.allocator, "#!/bin/sh\nprintf extracted > '{s}/extracted'\n", .{fixture.path});
    defer std.testing.allocator.free(stub);
    try fixture.write("bin/dpkg-deb", stub, 0o755);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/bin:/usr/sbin:/usr/bin:/sbin:/bin", .{fixture.path});
    defer std.testing.allocator.free(path);
    try fixture.environment.put("PATH", path);
    try expectCliFailure(&fixture, &.{
        "python3", program, "--architecture", "arm64", "--fixture-root", root, "--fixture-archive", archive,
    }, "invalid-download.log", "pinned reference archive digest mismatch");
    try assertAbsent(fixture, "extracted");
    try assertAbsent(fixture, "download/.cache/native-dpkg-reference/1.22.22/arm64");
}

test "tampered reference cache cannot trigger download, repair or host installation" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const program = try referencePreparation(std.testing.allocator);
    defer std.testing.allocator.free(program);
    const root = try fixture.makeRoot("cache", "amd64");
    defer std.testing.allocator.free(root);
    const selected = "cache/.cache/native-dpkg-reference/1.22.22/amd64/usr/bin/dpkg";
    const changed = "changed reference";
    try fixture.write(selected, changed, 0o755);
    const missing_archive = try fixture.absolute("cache/missing.deb");
    defer std.testing.allocator.free(missing_archive);
    const stub = try std.fmt.allocPrint(std.testing.allocator, "#!/bin/sh\nprintf repaired > '{s}/repaired'\n", .{fixture.path});
    defer std.testing.allocator.free(stub);
    try fixture.write("bin/dpkg-deb", stub, 0o755);
    const path = try std.fmt.allocPrint(std.testing.allocator, "{s}/bin:/usr/sbin:/usr/bin:/sbin:/bin", .{fixture.path});
    defer std.testing.allocator.free(path);
    try fixture.environment.put("PATH", path);
    try expectCliFailure(&fixture, &.{
        "python3", program, "--architecture", "amd64", "--fixture-root", root, "--fixture-archive", missing_archive,
    }, "tampered-cache.log", "pinned reference digest mismatch");
    try assertAbsent(fixture, "repaired");
    try assertAbsent(fixture, "cache/.cache/native-dpkg-reference/1.22.22/amd64/reference-receipt-v1.json");
    const selected_path = try fixture.absolute(selected);
    defer std.testing.allocator.free(selected_path);
    const contents = try bytes(std.testing.allocator, std.testing.io, selected_path);
    defer std.testing.allocator.free(contents);
    try std.testing.expectEqualStrings(changed, contents);
}

test "reference preparation rejects root before inspecting cache or archive" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const program = try referencePreparation(std.testing.allocator);
    defer std.testing.allocator.free(program);
    const root = try fixture.makeRoot("unprivileged", "arm64");
    defer std.testing.allocator.free(root);
    const missing_archive = try fixture.absolute("unprivileged/missing.deb");
    defer std.testing.allocator.free(missing_archive);
    try expectCliFailure(&fixture, &.{
        "python3",           program,         "--architecture",  "arm64", "--fixture-root", root,
        "--fixture-archive", missing_archive, "--simulate-root",
    }, "root-refusal.log", "build user, not root");
    try assertAbsent(fixture, "unprivileged/.cache");
}

test "offline preparation refuses an unguarded root and escaping archive" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    const program = try referencePreparation(std.testing.allocator);
    defer std.testing.allocator.free(program);
    const unsafe = try fixture.makeRoot("unsafe", "arm64");
    defer std.testing.allocator.free(unsafe);
    try fixture.write("unsafe/" ++ foundation.guard, "wrong marker\n", 0o600);
    const archive = try fixture.absolute("unsafe/archive.deb");
    defer std.testing.allocator.free(archive);
    try expectCliFailure(&fixture, &.{
        "python3",           program, "--architecture", "arm64", "--fixture-root", unsafe,
        "--fixture-archive", archive,
    }, "wrong-guard.log", "requires a disposable fixture root");
    try assertAbsent(fixture, "unsafe/.cache");
    const guarded = try fixture.makeRoot("guarded", "arm64");
    defer std.testing.allocator.free(guarded);
    try fixture.dir.symLink(std.testing.io, "/etc/passwd", "guarded/archive.deb", .{});
    const escaping = try fixture.absolute("guarded/archive.deb");
    defer std.testing.allocator.free(escaping);
    try expectCliFailure(&fixture, &.{
        "python3",           program,  "--architecture", "arm64", "--fixture-root", guarded,
        "--fixture-archive", escaping,
    }, "escaping-archive.log", "fixture archive must be a real file inside the disposable root");
    try assertAbsent(fixture, "guarded/.cache/native-dpkg-reference/1.22.22/arm64");
}

test "bounded subprocess terminates and records an owned timeout log" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    try std.testing.expectError(
        error.Timeout,
        fixture.run(&.{ "/usr/bin/sleep", "3" }, "timeout.log", 1),
    );
    const path = try fixture.absolute("timeout.log");
    defer std.testing.allocator.free(path);
    const log = try bytes(std.testing.allocator, std.testing.io, path);
    defer std.testing.allocator.free(log);
    try std.testing.expect(std.mem.indexOf(u8, log, "timed out after 1s") != null);
}

test "a claimed success with the wrong resulting root is rejected" {
    var fixture = try foundation.Fixture.init(std.testing.allocator, std.testing.io, options.repository);
    defer fixture.deinit();
    fixture.diagnostics = false;
    const expected = try fixture.makeRoot("reference", "amd64");
    defer std.testing.allocator.free(expected);
    const candidate = try fixture.makeRoot("candidate", "amd64");
    defer std.testing.allocator.free(candidate);
    try fixture.write("reference/usr/share/payload", "reference data\n", 0o644);
    try fixture.directory("case");
    const script = try std.fmt.allocPrint(
        std.testing.allocator,
        "#!/bin/sh\nprintf '%s\\n' '{{\"outcome\":\"applied\",\"detail\":\"fake\"}}' > '{s}/case/native.report.json'\n",
        .{fixture.path},
    );
    defer std.testing.allocator.free(script);
    try fixture.write("fake-native", script, 0o755);
    const executable = try fixture.absolute("fake-native");
    defer std.testing.allocator.free(executable);
    var report = try foundation.native(&fixture, executable, candidate, executable, "amd64", "install", "case");
    defer report.deinit();
    try assertApplied(report.value, "install");
    try std.testing.expectError(error.NativeDpkgMismatch, foundation.compare(fixture, expected, candidate, "case"));
}
