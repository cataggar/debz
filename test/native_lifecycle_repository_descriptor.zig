const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");

const package = "packages-microsoft-prod";
const descriptor_fixture = "src/fixtures/packages-microsoft-prod_1.2-ubuntu24.04_all.deb";
const descriptor_sha256 = "c13f01ac7c3001b51a9281d40dde666db5e037e05512840c319832f7852bfec4";
const documentation = "usr/share/doc/packages-microsoft-prod/";
/// SHA-256 of the descriptor's control member `md5sums`: ten `./`-prefixed
/// lines in vendor order, which dpkg installs as `info/<pkg>.md5sums` verbatim.
const shipped_md5sums_sha256 = "3364e56e9a4856287014127008825fcf2404d937c7828451a9652654b7b0bf03";
const installed_md5sums = "var/lib/dpkg/info/" ++ package ++ ".md5sums";
const sides = [_][]const u8{ "reference", "native" };

const Managed = struct { path: []const u8, sha256: []const u8 };
const managed = [_]Managed{
    .{ .path = "etc/apt/sources.list.d/microsoft-prod.list", .sha256 = "b1603241c9619c02611a77a663f55e726608bde079c4f559bcccdf73847a45c8" },
    .{ .path = "usr/share/keyrings/microsoft-prod.gpg", .sha256 = "098f10efd65c0d0a856a980144b5f37c05374eaa575a208d46913fd8f7eae951" },
};

fn sidePath(case: *support.Scenario, side: []const u8, relative: []const u8) ![]u8 {
    return std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, relative });
}

fn hex(bytes: []const u8) [64]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return std.fmt.bytesToHex(digest, .lower);
}

/// Copies the checked-in upstream descriptor into the workspace after
/// confirming it is the exact reviewed artifact.
fn stageDescriptor(fixture: *foundation.Fixture) ![]u8 {
    const source = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}", .{ options.repository, descriptor_fixture });
    defer fixture.allocator.free(source);
    var file = try std.Io.Dir.openFileAbsolute(fixture.io, source, .{});
    defer file.close(fixture.io);
    var reader = file.reader(fixture.io, &.{});
    const bytes = try reader.interface.allocRemaining(fixture.allocator, .limited(64 * 1024));
    defer fixture.allocator.free(bytes);
    if (!std.mem.eql(u8, &hex(bytes), descriptor_sha256)) return error.ReviewedDescriptorChanged;
    const relative = "packages/repository-descriptor/packages-microsoft-prod_1.2-ubuntu24.04_all.deb";
    try fixture.write(relative, bytes, 0o644);
    return fixture.absolute(relative);
}

/// Requires the installed apt source and keyring, and their documentation
/// copies, to equal the reviewed payload bytes on both backends.
fn expectInstalled(case: *support.Scenario) !void {
    const allocator = case.fixture.allocator;
    for (sides) |side| {
        for (managed) |file| {
            const installed = try sidePath(case, side, file.path);
            defer allocator.free(installed);
            const bytes = try support.read(case.fixture, installed, 1024 * 1024);
            defer allocator.free(bytes);
            if (!std.mem.eql(u8, &hex(bytes), file.sha256)) return error.ManagedFileMismatch;
            const copy_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ documentation, std.fs.path.basenamePosix(file.path) });
            defer allocator.free(copy_path);
            const copy = try sidePath(case, side, copy_path);
            defer allocator.free(copy);
            const copy_bytes = try support.read(case.fixture, copy, 1024 * 1024);
            defer allocator.free(copy_bytes);
            if (!std.mem.eql(u8, bytes, copy_bytes)) return error.DocumentationCopyMismatch;
        }
        const status_path = try sidePath(case, side, "var/lib/dpkg/status");
        defer allocator.free(status_path);
        const status = try support.read(case.fixture, status_path, 64 * 1024);
        defer allocator.free(status);
        if (std.mem.indexOf(u8, status, "Package: " ++ package ++ "\nStatus: install ok installed\n") == null)
            return error.DescriptorNotInstalled;
    }
}

/// Requires both backends to publish the shipped md5sums member byte for byte.
fn expectShippedMd5sums(case: *support.Scenario) !void {
    for (sides) |side| {
        const installed = try sidePath(case, side, installed_md5sums);
        defer case.fixture.allocator.free(installed);
        const bytes = try support.read(case.fixture, installed, 64 * 1024);
        defer case.fixture.allocator.free(bytes);
        if (!std.mem.eql(u8, &hex(bytes), shipped_md5sums_sha256)) {
            std.debug.print("{s}/{s}: {s} is not the shipped member:\n{s}\n", .{ case.name, side, installed_md5sums, bytes });
            return error.Md5sumsNotVerbatim;
        }
    }
}

/// Runs pinned `dpkg --verify` against both roots, which reads each side's
/// `info/<pkg>.md5sums` through dpkg's own path resolution, and requires the
/// same report as `expected` and the same exit status on both.
fn expectVerify(case: *support.Scenario, label: []const u8, expected: []const u8) !void {
    const fixture = case.fixture;
    const allocator = fixture.allocator;
    var reports: [sides.len][]u8 = undefined;
    var statuses: [sides.len]u8 = undefined;
    var filled: usize = 0;
    defer for (reports[0..filled]) |report| allocator.free(report);
    for (sides, [_][]const u8{ case.reference_root, case.native_root }, 0..) |side, root, index| {
        const root_arg = try std.fmt.allocPrint(allocator, "--root={s}", .{root});
        defer allocator.free(root_arg);
        const log = try std.fmt.allocPrint(allocator, "{s}/verify-{s}-{s}.log", .{ case.name, label, side });
        defer allocator.free(log);
        statuses[index] = try support.runExit(fixture, &.{ case.dpkg, "--force-not-root", root_arg, "--verify", package }, log);
        reports[index] = try support.read(fixture, log, 64 * 1024);
        filled += 1;
    }
    for (sides, reports, statuses) |side, report, status| {
        if (status != statuses[0] or (expected.len == 0 and status != 0) or
            !std.mem.eql(u8, report, expected))
        {
            std.debug.print("{s}/verify-{s} {s}: exit {d}:\n{s}\n", .{ case.name, label, side, status, report });
            fixture.retain = true;
            return error.VerifyMismatch;
        }
    }
    std.debug.print("{s}/verify-{s}: pinned dpkg --verify agrees on both roots\n", .{ case.name, label });
}

/// Requires both roots to hold the reviewed descriptor, its shipped md5sums,
/// and a clean `dpkg --verify`.
fn expectInstalledEvidence(case: *support.Scenario, label: []const u8) !void {
    try expectInstalled(case);
    try expectShippedMd5sums(case);
    try expectVerify(case, label, "");
}

/// Changes a listed documentation file identically on both sides, so dpkg
/// must resolve the `./` spelling in each side's md5sums to report it.
fn expectTamperReported(case: *support.Scenario) !void {
    const fixture = case.fixture;
    for (sides) |side| {
        const changed = try sidePath(case, side, documentation ++ "copyright");
        defer fixture.allocator.free(changed);
        try fixture.write(changed, "changed by the administrator\n", 0o644);
        try fixture.dir.setTimestamps(fixture.io, changed, .{
            .modify_timestamp = .{ .new = .{ .nanoseconds = foundation.epoch * std.time.ns_per_s } },
        });
    }
    try expectVerify(case, "tampered", "??5??????   /" ++ documentation ++ "copyright\n");
}

/// `install` stamps files restored by the postinst with the wall clock.
fn normalizeRestored(case: *support.Scenario) !void {
    const fixture = case.fixture;
    for (sides) |side| {
        for (managed) |file| {
            const restored = try sidePath(case, side, file.path);
            defer fixture.allocator.free(restored);
            try fixture.dir.setTimestamps(fixture.io, restored, .{
                .modify_timestamp = .{ .new = .{ .nanoseconds = foundation.epoch * std.time.ns_per_s } },
            });
        }
    }
}

/// Interrupts native at `crash` on the root dpkg populated, recovers, and
/// requires the recovered root to match pinned dpkg completing `input`.
fn recoverInterrupted(case: *support.Scenario, input: support.Phase, crash: []const u8) !void {
    const fixture = case.fixture;
    const allocator = fixture.allocator;
    const destination = try std.fmt.allocPrint(allocator, "{s}/{d}-{s}-{s}", .{ case.name, case.index, input.operation, crash });
    defer allocator.free(destination);
    try fixture.directory(destination);
    case.index += 1;
    if (try support.reference(fixture, case.dpkg, case.reference_root, input, destination) != 0)
        return error.UnexpectedReferenceOutcome;
    var interrupted = input;
    interrupted.recovery = true;
    interrupted.crash_at = crash;
    if (support.native(fixture, case.executable, case.native_root, case.architecture, interrupted, destination)) |unexpected| {
        var result = unexpected;
        result.deinit();
        return error.CrashNotInjected;
    } else |err| if (err != error.ChildFailed) return err;
    const resumed_destination = try std.fmt.allocPrint(allocator, "{s}/recover", .{destination});
    defer allocator.free(resumed_destination);
    try fixture.directory(resumed_destination);
    var resumed = try support.native(fixture, case.executable, case.native_root, case.architecture, .{
        .operation = "recover",
        .recovery = true,
    }, resumed_destination);
    defer resumed.deinit();
    if (!std.mem.eql(u8, resumed.value.outcome, "applied")) {
        std.debug.print("{s}/recover after {s}: {s}: {s}\n", .{ destination, crash, resumed.value.outcome, resumed.value.detail });
        return error.UnexpectedRecoveryOutcome;
    }
    try support.assertNoActiveEvidence(fixture, case.native_root);
    if (std.mem.eql(u8, input.operation, "reinstall")) try normalizeRestored(case);
    support.compare(fixture, case.reference_root, case.native_root, resumed_destination, false) catch |err| {
        fixture.retain = true;
        return err;
    };
    std.debug.print("{s}/{s}: recovery after {s} native/dpkg parity passed\n", .{ case.name, input.operation, crash });
}

fn expectRemoved(case: *support.Scenario) !void {
    for (sides) |side| {
        for (managed) |file| {
            const installed = try sidePath(case, side, file.path);
            defer case.fixture.allocator.free(installed);
            try support.absent(case.fixture, installed);
        }
    }
}

/// Reinstalls after an administrator deleted the apt source. The upstream
/// preinst deletes the keyring on upgrade, dpkg keeps deleted conffiles
/// deleted, and the postinst restores both from the documentation copies.
fn restoreFromDocumentation(case: *support.Scenario, archive: []const u8) !void {
    const fixture = case.fixture;
    const allocator = fixture.allocator;
    for (sides) |side| {
        const listed = try sidePath(case, side, managed[0].path);
        defer allocator.free(listed);
        try fixture.dir.deleteFile(fixture.io, listed);
    }
    const destination = try std.fmt.allocPrint(allocator, "{s}/{d}-reinstall", .{ case.name, case.index });
    defer allocator.free(destination);
    try fixture.directory(destination);
    case.index += 1;
    const input: support.Phase = .{ .operation = "reinstall", .archives = &.{archive} };
    if (try support.reference(fixture, case.dpkg, case.reference_root, input, destination) != 0)
        return error.UnexpectedReferenceOutcome;
    const log_path = try support.path(allocator, destination, "reference.log");
    defer allocator.free(log_path);
    const log = try support.read(fixture, log_path, 1024 * 1024);
    defer allocator.free(log);
    for (managed) |file| {
        const message = try std.fmt.allocPrint(allocator, "File /{s} is missing. Installing...", .{file.path});
        defer allocator.free(message);
        if (std.mem.indexOf(u8, log, message) == null) return error.DocumentationRestoreDidNotRun;
    }
    if (fixture.oracle_only) {
        const oracle = try support.path(allocator, destination, "oracle");
        defer allocator.free(oracle);
        try fixture.directory(oracle);
        if (try support.reference(fixture, case.dpkg, case.native_root, input, oracle) != 0)
            return error.NonRepeatableReference;
    } else {
        var outcome = try support.native(fixture, case.executable, case.native_root, case.architecture, input, destination);
        defer outcome.deinit();
        if (!std.mem.eql(u8, outcome.value.outcome, "applied")) {
            std.debug.print("{s}/reinstall: {s}: {s}\n", .{ case.name, outcome.value.outcome, outcome.value.detail });
            return error.UnexpectedNativeOutcome;
        }
        try support.assertNoActiveEvidence(fixture, case.native_root);
    }
    try expectInstalled(case);
    try normalizeRestored(case);
    support.compare(fixture, case.reference_root, case.native_root, destination, false) catch |err| {
        fixture.retain = true;
        return err;
    };
    std.debug.print("{s}/reinstall: documentation restore {s} passed\n", .{
        case.name, if (fixture.oracle_only) "dpkg fixture repeatability" else "native/dpkg parity",
    });
}

fn scenario(
    fixture: *foundation.Fixture,
    name: []const u8,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    dependency: []const u8,
    descriptor: []const u8,
    imported: bool,
) !void {
    var case = try support.Scenario.init(fixture, name, driver, dpkg, arch, false);
    defer case.deinit();
    for (sides) |side| {
        const root = try support.path(fixture.allocator, case.name, side);
        defer fixture.allocator.free(root);
        try support.copyProgram(fixture, root, "/usr/bin/install", "/usr/bin/install");
        try support.copyProgram(fixture, root, "/usr/bin/rm", "/usr/bin/rm");
    }
    if (imported) {
        // dpkg installs the shipped `./`-prefixed md5sums verbatim, so the
        // native side must import a dpkg-owned copy before changing it.
        try case.seed(dependency);
        try case.seed(descriptor);
    } else {
        try case.phase(.{ .operation = "install", .archives = &.{ dependency, descriptor } }, false);
    }
    try expectInstalledEvidence(&case, "installed");
    try restoreFromDocumentation(&case, descriptor);
    try expectInstalledEvidence(&case, "reinstalled");
    const selected = [_]foundation.PackageIdentity{.{ .name = package, .architecture = "all" }};
    const remove: support.Phase = .{ .operation = "remove", .packages = &selected };
    if (imported and !fixture.oracle_only) {
        // Native recovery of a root dpkg populated, including its shipped
        // `./` md5sums, completes the operation exactly as dpkg does.
        try recoverInterrupted(&case, .{ .operation = "reinstall", .archives = &.{descriptor} }, "during_filesystem_publication");
        try expectInstalledEvidence(&case, "recovered");
        try expectTamperReported(&case);
        try recoverInterrupted(&case, remove, "after_script_outcome");
    } else {
        try expectTamperReported(&case);
        try case.phase(remove, false);
    }
    try expectRemoved(&case);
    try case.phase(.{ .operation = "purge", .packages = &selected }, false);
    try expectRemoved(&case);
}

/// Runs the unmodified upstream packages-microsoft-prod descriptor, with its
/// real maintainer scripts, through pinned dpkg and the native runtime, both
/// on a fresh root and on a root where dpkg installed it first.
pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const descriptor = try stageDescriptor(fixture);
    defer fixture.allocator.free(descriptor);
    const dependency = try support.makePackage(fixture, "all", "20240203", "ca-certificates", "packages/repository-descriptor", .{ .no_scripts = true });
    defer fixture.allocator.free(dependency);
    try scenario(fixture, "microsoft-repository-descriptor", driver, dpkg, arch, dependency, descriptor, false);
    try scenario(fixture, "microsoft-repository-descriptor-imported", driver, dpkg, arch, dependency, descriptor, true);
    std.debug.print("microsoft-repository-descriptor: install, verbatim md5sums, dpkg --verify, documentation restore, recovery, remove and purge {s}\n", .{
        if (fixture.oracle_only) "repeat with pinned dpkg" else "match pinned dpkg",
    });
}
