const std = @import("std");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");

const name = "removal-parity";
const configuration = "etc/debz-native.conf";

const Invocation = struct {
    version: []const u8 = "1",
    kind: []const u8,
    args: []const []const u8,
    payload: []const u8 = "<absent>",
};

fn relative(case: *support.Scenario, side: []const u8, path: []const u8) ![]u8 {
    return std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}/{s}", .{ case.name, side, path });
}

fn bothFile(case: *support.Scenario, path: []const u8, content: ?[]const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const file = try relative(case, side, path);
        defer case.fixture.allocator.free(file);
        if (content) |bytes|
            try support.fixtureFile(case.fixture, file, bytes, 0o644)
        else
            try case.fixture.dir.deleteFile(case.fixture.io, file);
    }
}

fn expectFile(case: *support.Scenario, path: []const u8, expected: ?[]const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const file = try relative(case, side, path);
        defer case.fixture.allocator.free(file);
        if (expected) |bytes| {
            const actual = try support.read(case.fixture, file, 1024 * 1024);
            defer case.fixture.allocator.free(actual);
            if (!std.mem.eql(u8, bytes, actual)) return error.UnexpectedRemovalFile;
        } else try support.absent(case.fixture, file);
    }
}

fn expectInfoContains(case: *support.Scenario, path: []const u8, needle: []const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const file = try relative(case, side, path);
        defer case.fixture.allocator.free(file);
        const bytes = try support.read(case.fixture, file, 1024 * 1024);
        defer case.fixture.allocator.free(bytes);
        if (std.mem.indexOf(u8, bytes, needle) == null) return error.MissingRemovalInfo;
    }
}

fn expectStatus(case: *support.Scenario, expected: ?[]const u8) !void {
    for ([_][]const u8{ "reference", "native" }) |side| {
        const file = try relative(case, side, "var/lib/dpkg/status");
        defer case.fixture.allocator.free(file);
        const status = try support.read(case.fixture, file, 1024 * 1024);
        defer case.fixture.allocator.free(status);
        const start = std.mem.indexOf(u8, status, "Package: " ++ name ++ "\n");
        if (expected) |value| {
            const begin = start orelse return error.MissingRemovalStatus;
            const end = std.mem.indexOfPos(u8, status, begin, "\n\n") orelse status.len;
            if (std.mem.indexOf(u8, status[begin..end], value) == null)
                return error.UnexpectedRemovalStatus;
        } else if (start != null) return error.UnexpectedRemovalStatus;
    }
}

fn trace(case: *support.Scenario) ![]u8 {
    const file = try relative(case, "reference", support.trace);
    defer case.fixture.allocator.free(file);
    return support.read(case.fixture, file, 16 * 1024 * 1024);
}

fn phase(
    case: *support.Scenario,
    input: support.Phase,
    failed: bool,
    callbacks: []const Invocation,
) !void {
    const before = try trace(case);
    defer case.fixture.allocator.free(before);
    try case.phase(input, failed);
    const after = try trace(case);
    defer case.fixture.allocator.free(after);
    var expected: std.Io.Writer.Allocating = .init(case.fixture.allocator);
    defer expected.deinit();
    try expected.writer.writeAll(before);
    for (callbacks) |callback| {
        try expected.writer.print("{s}@{s}:{s}\t{s}\t{s}\t{s}\t{d}", .{
            name, callback.version, callback.kind, name, callback.kind, case.architecture, callback.args.len,
        });
        for (callback.args) |arg|
            try expected.writer.print("\t{d}:{s}", .{ arg.len, arg });
        try expected.writer.print("\tpayload={s}\n", .{callback.payload});
    }
    if (!std.mem.eql(u8, expected.written(), after)) {
        std.debug.print("{s}/{s}: expected trace\n{s}actual trace\n{s}\n", .{
            case.name, input.operation, expected.written(), after,
        });
        return error.UnexpectedRemovalInvocation;
    }
}

fn expectRetryRefused(case: *support.Scenario, selected: []const foundation.PackageIdentity, label: []const u8) !void {
    const before = try foundation.capture(case.fixture.allocator, case.fixture.io, case.native_root);
    defer case.fixture.allocator.free(before);
    const destination = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{s}", .{ case.name, label });
    defer case.fixture.allocator.free(destination);
    try case.fixture.directory(destination);
    var report = try support.native(case.fixture, case.executable, case.native_root, case.architecture, .{
        .operation = "remove",
        .packages = selected,
    }, destination);
    defer report.deinit();
    if (!std.mem.eql(u8, report.value.outcome, "refused") or
        !std.mem.eql(u8, report.value.detail, "program_compile_rejected"))
        return error.UnexpectedUnsafeRetryOutcome;
    const after = try foundation.capture(case.fixture.allocator, case.fixture.io, case.native_root);
    defer case.fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.UnsafeRetryMutatedRoot;
    try support.assertNoActiveEvidence(case.fixture, case.native_root);
}

fn retryProofGuards(case: *support.Scenario, selected: []const foundation.PackageIdentity) !void {
    if (case.fixture.oracle_only) return;
    const marker = try relative(case, "native", "var/lib/debz/native-remove-retry-v1.json");
    defer case.fixture.allocator.free(marker);
    const original = try support.read(case.fixture, marker, 4096);
    defer case.fixture.allocator.free(original);
    const Proof = struct {
        package: struct { name: []const u8, version: []const u8, architecture: []const u8 },
        previous_attempt_id: []const u8,
        previous_program_sha256: []const u8,
        previous_exact_lock_sha256: []const u8,
        postrm_sha256: []const u8,
    };
    const decoded = try std.json.parseFromSlice(Proof, case.fixture.allocator, original, .{ .ignore_unknown_fields = true });
    defer decoded.deinit();
    const proof = decoded.value;
    if (!std.mem.eql(u8, proof.package.name, name) or
        !std.mem.eql(u8, proof.package.version, "1") or
        !std.mem.eql(u8, proof.package.architecture, case.architecture) or
        proof.previous_attempt_id.len != 64 or proof.previous_program_sha256.len != 64 or
        proof.previous_exact_lock_sha256.len != 64 or proof.postrm_sha256.len != 64)
        return error.InvalidPostrmRetryProof;
    try case.fixture.dir.deleteFile(case.fixture.io, marker);
    try expectRetryRefused(case, selected, "retry-without-proof");
    try support.fixtureFile(case.fixture, marker, original, 0o600);
    const changed = try case.fixture.allocator.dupe(u8, original);
    defer case.fixture.allocator.free(changed);
    const digest = std.mem.indexOf(u8, changed, proof.previous_attempt_id) orelse return error.InvalidPostrmRetryProof;
    changed[digest] = if (changed[digest] == '0') '1' else '0';
    try support.fixtureFile(case.fixture, marker, changed, 0o600);
    try expectRetryRefused(case, selected, "retry-corrupt-proof");
    try support.fixtureFile(case.fixture, marker, original, 0o600);
    const conffile = try relative(case, "native", configuration);
    defer case.fixture.allocator.free(conffile);
    try support.fixtureFile(case.fixture, conffile, "changed after failure\n", 0o644);
    try expectRetryRefused(case, selected, "retry-changed-root");
    try support.fixtureFile(case.fixture, conffile, "edited configuration\n", 0o644);
}

fn removedReinstallBlock(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, first: []const u8) !void {
    var case = try support.Scenario.init(fixture, "removal-config-files-same-version-reinstall", driver, dpkg, arch, false);
    defer case.deinit();
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    try case.seed(first);
    try bothFile(&case, configuration, "administrator configuration\n");
    try phase(&case, .{ .operation = "remove", .packages = &selected }, false, &.{
        .{ .kind = "prerm", .args = &.{"remove"}, .payload = "data version 1" },
        .{ .kind = "postrm", .args = &.{"remove"} },
    });
    try expectStatus(&case, "Status: deinstall ok config-files");
    const input: support.Phase = .{ .operation = "reinstall", .archives = &.{first}, .packages = &selected };
    if (fixture.oracle_only) {
        try case.phase(input, false);
        return;
    }
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    const earlier = try trace(&case);
    defer fixture.allocator.free(earlier);
    const destination = try support.path(fixture.allocator, case.name, "reinstall-removed");
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    if (try support.reference(fixture, dpkg, case.reference_root, input, destination) != 0)
        return error.UnexpectedRemovedReinstallReference;
    const installed = try trace(&case);
    defer fixture.allocator.free(installed);
    if (!std.mem.startsWith(u8, installed, earlier) or
        std.mem.indexOf(u8, installed[earlier.len..], name ++ "@1:preinst\t") == null or
        std.mem.indexOf(u8, installed[earlier.len..], name ++ "@1:postinst\t") == null)
        return error.ReferenceDidNotReinstallRemovedPackage;
    const status_path = try relative(&case, "reference", "var/lib/dpkg/status");
    defer fixture.allocator.free(status_path);
    const reference_status = try support.read(fixture, status_path, 1024 * 1024);
    defer fixture.allocator.free(reference_status);
    if (std.mem.indexOf(u8, reference_status, "Status: install ok installed") == null)
        return error.ReferenceDidNotReinstallRemovedPackage;
    var result = try support.native(fixture, driver, case.native_root, arch, input, destination);
    defer result.deinit();
    if (!std.mem.eql(u8, result.value.outcome, "refused") or
        !std.mem.eql(u8, result.value.detail, "program_compile_rejected"))
        return error.UnexpectedRemovedReinstallOutcome;
    const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(after);
    if (!std.mem.eql(u8, before, after)) return error.RemovedReinstallChangedNativeRoot;
    try support.assertNoActiveEvidence(fixture, case.native_root);
    const retained_status_path = try relative(&case, "native", "var/lib/dpkg/status");
    defer fixture.allocator.free(retained_status_path);
    const retained_status = try support.read(fixture, retained_status_path, 1024 * 1024);
    defer fixture.allocator.free(retained_status);
    if (std.mem.indexOf(u8, retained_status, "Status: deinstall ok config-files") == null)
        return error.RemovedReinstallLostResidualStatus;
    try expectFile(&case, configuration, "administrator configuration\n");
    const reference = try foundation.capture(fixture.allocator, fixture.io, case.reference_root);
    defer fixture.allocator.free(reference);
    if (std.mem.eql(u8, reference, after)) return error.RemovedReinstallAccidentallyMatched;
    std.debug.print("{s}/reinstall: dpkg exit 0, native refused before mutation (not parity)\n", .{case.name});
}

fn expectScriptFailure(case: *support.Scenario, index: usize, operation: []const u8, kind: []const u8) !void {
    if (case.fixture.oracle_only) return;
    const path = try std.fmt.allocPrint(case.fixture.allocator, "{s}/{d}-{s}/native.report.json", .{ case.name, index, operation });
    defer case.fixture.allocator.free(path);
    const bytes = try support.read(case.fixture, path, 64 * 1024);
    defer case.fixture.allocator.free(bytes);
    const parsed = try std.json.parseFromSlice(support.Report, case.fixture.allocator, bytes, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    if (!std.mem.eql(u8, parsed.value.outcome, "script_failed") or
        !std.mem.eql(u8, parsed.value.detail, kind))
        return error.WrongRemovalScriptFailure;
}

fn residueAndReinstall(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    first: []const u8,
    second: []const u8,
) !void {
    var case = try support.Scenario.init(fixture, "removal-residue-reinstall-versions", driver, dpkg, arch, false);
    defer case.deinit();
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    try case.seed(first);
    try bothFile(&case, configuration, "administrator configuration\n");
    try case.phase(.{ .operation = "reinstall", .archives = &.{first}, .packages = &selected }, false);
    try expectStatus(&case, "Status: install ok installed");
    try expectFile(&case, configuration, "administrator configuration\n");
    try case.phase(.{ .operation = "upgrade", .archives = &.{second}, .packages = &selected }, false);
    try expectStatus(&case, "Version: 2");
    try expectFile(&case, "usr/share/" ++ name ++ "/obsolete", null);
    try expectFile(&case, "usr/share/" ++ name ++ "/introduced", "only in 2\n");
    try case.phase(.{ .operation = "downgrade", .archives = &.{first}, .packages = &selected }, false);
    try expectStatus(&case, "Version: 1");
    try expectFile(&case, "usr/share/" ++ name ++ "/obsolete", "only in 1\n");
    try expectFile(&case, "usr/share/" ++ name ++ "/introduced", null);
    try phase(&case, .{ .operation = "remove", .packages = &selected }, false, &.{
        .{ .kind = "prerm", .args = &.{"remove"}, .payload = "data version 1" },
        .{ .kind = "postrm", .args = &.{"remove"} },
    });
    try expectStatus(&case, "Status: deinstall ok config-files");
    try expectFile(&case, configuration, "administrator configuration\n");
    try expectStatus(&case, "Conffiles:\n /" ++ configuration ++ " ");
    try expectInfoContains(&case, "var/lib/dpkg/info/" ++ name ++ ".list", "/" ++ configuration ++ "\n");
    try expectInfoContains(&case, "var/lib/dpkg/info/" ++ name ++ ".postrm", name ++ "@1:postrm");
    try expectFile(&case, "usr/share/" ++ name ++ "/data", null);
    try phase(&case, .{ .operation = "purge", .packages = &selected }, false, &.{
        .{ .kind = "postrm", .args = &.{"purge"} },
    });
    try expectStatus(&case, null);
    try expectFile(&case, configuration, null);
    try expectFile(&case, "var/lib/dpkg/info/" ++ name ++ ".list", null);
    try expectFile(&case, "var/lib/dpkg/info/" ++ name ++ ".postrm", null);
}

fn failureAndRetry(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    first: []const u8,
) !void {
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    for ([_]struct {
        label: []const u8,
        operation: []const u8,
        marker: []const u8,
        callbacks: []const Invocation,
    }{
        .{ .label = "prerm", .operation = "remove", .marker = name ++ "@1:prerm:remove\n", .callbacks = &.{
            .{ .kind = "prerm", .args = &.{"remove"}, .payload = "data version 1" },
            .{ .kind = "postinst", .args = &.{"abort-remove"}, .payload = "data version 1" },
        } },
        .{ .label = "postrm", .operation = "remove", .marker = name ++ "@1:postrm:remove\n", .callbacks = &.{
            .{ .kind = "prerm", .args = &.{"remove"}, .payload = "data version 1" },
            .{ .kind = "postrm", .args = &.{"remove"} },
        } },
        .{ .label = "purge-postrm", .operation = "purge", .marker = name ++ "@1:postrm:purge\n", .callbacks = &.{
            .{ .kind = "postrm", .args = &.{"purge"} },
        } },
    }) |entry| {
        const label = try std.fmt.allocPrint(fixture.allocator, "removal-failure-{s}", .{entry.label});
        defer fixture.allocator.free(label);
        var case = try support.Scenario.init(fixture, label, driver, dpkg, arch, false);
        defer case.deinit();
        try case.seed(first);
        try bothFile(&case, configuration, "edited configuration\n");
        if (std.mem.eql(u8, entry.operation, "purge")) {
            try phase(&case, .{ .operation = "remove", .packages = &selected }, false, &.{
                .{ .kind = "prerm", .args = &.{"remove"}, .payload = "data version 1" },
                .{ .kind = "postrm", .args = &.{"remove"} },
            });
        }
        try bothFile(&case, support.failure, entry.marker);
        const failure_index = case.index;
        try phase(&case, .{ .operation = entry.operation, .packages = &selected }, true, entry.callbacks);
        try expectScriptFailure(&case, failure_index, entry.operation, if (std.mem.eql(u8, entry.label, "prerm")) "prerm" else "postrm");
        if (!fixture.oracle_only and !std.mem.eql(u8, entry.label, "postrm")) {
            const marker = try relative(&case, "native", "var/lib/debz/native-remove-retry-v1.json");
            defer fixture.allocator.free(marker);
            try support.absent(fixture, marker);
        }
        try expectFile(&case, configuration, if (std.mem.eql(u8, entry.operation, "purge"))
            null
        else
            "edited configuration\n");
        if (std.mem.eql(u8, entry.operation, "purge")) {
            try expectStatus(&case, "Status: purge ok config-files");
            try expectInfoContains(&case, "var/lib/dpkg/info/" ++ name ++ ".postrm", name ++ "@1:postrm");
        }
        try bothFile(&case, support.failure, null);
        if (std.mem.eql(u8, entry.label, "postrm")) {
            try retryProofGuards(&case, &selected);
            try phase(&case, .{ .operation = "remove", .packages = &selected }, false, &.{
                .{ .kind = "postrm", .args = &.{"remove"} },
            });
            try expectStatus(&case, "Status: deinstall ok config-files");
            try expectFile(&case, configuration, "edited configuration\n");
            try expectInfoContains(&case, "var/lib/dpkg/info/" ++ name ++ ".list", "/" ++ configuration ++ "\n");
            try expectInfoContains(&case, "var/lib/dpkg/info/" ++ name ++ ".postrm", name ++ "@1:postrm");
            try expectFile(&case, "usr/share/" ++ name ++ "/data", null);
            if (!fixture.oracle_only) {
                const marker = try relative(&case, "native", "var/lib/debz/native-remove-retry-v1.json");
                defer fixture.allocator.free(marker);
                try support.absent(fixture, marker);
            }
            continue;
        }
        try phase(&case, .{ .operation = entry.operation, .packages = &selected }, false, if (std.mem.eql(u8, entry.operation, "purge")) &.{
            .{ .kind = "postrm", .args = &.{"purge"} },
        } else &.{
            .{ .kind = "prerm", .args = &.{"remove"}, .payload = "data version 1" },
            .{ .kind = "postrm", .args = &.{"remove"} },
        });
        if (std.mem.eql(u8, entry.operation, "remove")) {
            try expectStatus(&case, "Status: deinstall ok config-files");
            try expectFile(&case, configuration, "edited configuration\n");
            try phase(&case, .{ .operation = "purge", .packages = &selected }, false, &.{
                .{ .kind = "postrm", .args = &.{"purge"} },
            });
        }
        try expectStatus(&case, null);
        try expectFile(&case, configuration, null);
    }
}

fn interruptedPostrmRetry(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    first: []const u8,
) !void {
    var case = try support.Scenario.init(fixture, "removal-failure-postrm-interrupted-retry", driver, dpkg, arch, false);
    defer case.deinit();
    try case.seed(first);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    try bothFile(&case, configuration, "edited configuration\n");
    try bothFile(&case, support.failure, name ++ "@1:postrm:remove\n");
    try phase(&case, .{ .operation = "remove", .packages = &selected }, true, &.{
        .{ .kind = "prerm", .args = &.{"remove"}, .payload = "data version 1" },
        .{ .kind = "postrm", .args = &.{"remove"} },
    });
    try bothFile(&case, support.failure, null);
    if (fixture.oracle_only) {
        try phase(&case, .{ .operation = "remove", .packages = &selected }, false, &.{
            .{ .kind = "postrm", .args = &.{"remove"} },
        });
        return;
    }
    const destination = try support.path(fixture.allocator, case.name, "interrupted-retry");
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "remove",
        .packages = &selected,
    }, destination) != 0) return error.UnexpectedReferenceRetry;
    var interrupted = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "remove",
        .packages = &selected,
        .fault = "after_script_before_record",
    }, destination);
    defer interrupted.deinit();
    if (!std.mem.eql(u8, interrupted.value.outcome, "recovery_required") or
        !std.mem.eql(u8, interrupted.value.detail, "script_outcome_unknown"))
        return error.RetryInterruptionNotOwned;
    const reference_trace = try trace(&case);
    defer fixture.allocator.free(reference_trace);
    const native_trace_path = try relative(&case, "native", support.trace);
    defer fixture.allocator.free(native_trace_path);
    const native_trace = try support.read(fixture, native_trace_path, 64 * 1024);
    defer fixture.allocator.free(native_trace);
    if (!std.mem.eql(u8, reference_trace, native_trace) or
        std.mem.count(u8, native_trace, name ++ "@1:prerm\t") != 1 or
        std.mem.count(u8, native_trace, name ++ "@1:postrm\t") != 2)
        return error.RetryReplayedSuccessfulScript;
    const operation_path = try relative(&case, "native", "var/lib/debz/root-operation-v1.json");
    defer fixture.allocator.free(operation_path);
    const script_path = try relative(&case, "native", "var/lib/debz/native-lifecycle-script-v1.json");
    defer fixture.allocator.free(script_path);
    const operation = try support.read(fixture, operation_path, 64 * 1024);
    defer fixture.allocator.free(operation);
    const active = try support.read(fixture, script_path, 64 * 1024);
    defer fixture.allocator.free(active);
    const Owner = struct {
        attempt_id: []const u8,
        program_sha256: []const u8,
        state: []const u8,
        mutation_started: bool,
    };
    const Script = struct {
        program_sha256: []const u8,
        kind: []const u8,
        arguments: []const []const u8,
        outcome: []const u8,
    };
    const owner = try std.json.parseFromSlice(Owner, fixture.allocator, operation, .{ .ignore_unknown_fields = true });
    defer owner.deinit();
    const script = try std.json.parseFromSlice(Script, fixture.allocator, active, .{ .ignore_unknown_fields = true });
    defer script.deinit();
    if (!std.mem.eql(u8, owner.value.state, "recovery_required") or !owner.value.mutation_started or
        owner.value.attempt_id.len != 64 or
        !std.mem.eql(u8, owner.value.program_sha256, script.value.program_sha256) or
        !std.mem.eql(u8, script.value.kind, "postrm") or
        script.value.arguments.len != 1 or
        !std.mem.eql(u8, script.value.arguments[0], "remove") or
        !std.mem.eql(u8, script.value.outcome, "in_flight"))
        return error.RetryInterruptionBinding;
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    for ([_][]const u8{ "remove", "purge", "recover" }) |operation_name| {
        const next = try std.fmt.allocPrint(fixture.allocator, "{s}/retry-{s}", .{ case.name, operation_name });
        defer fixture.allocator.free(next);
        try fixture.directory(next);
        var blocked = try support.native(fixture, driver, case.native_root, arch, .{
            .operation = operation_name,
            .packages = if (std.mem.eql(u8, operation_name, "recover")) &.{} else &selected,
            .recovery = std.mem.eql(u8, operation_name, "recover"),
        }, next);
        defer blocked.deinit();
        if (!std.mem.eql(u8, blocked.value.outcome, "recovery_required"))
            return error.RetryInterruptionAllowedMutation;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        const operation_after = try support.read(fixture, operation_path, 64 * 1024);
        defer fixture.allocator.free(operation_after);
        const active_after = try support.read(fixture, script_path, 64 * 1024);
        defer fixture.allocator.free(active_after);
        if (!std.mem.eql(u8, before, after) or
            !std.mem.eql(u8, operation, operation_after) or
            !std.mem.eql(u8, active, active_after))
            return error.RetryInterruptionLostOwner;
    }
}

fn recoverEarlyPostrmRetry(
    fixture: *foundation.Fixture,
    driver: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    first: []const u8,
    changed_root: bool,
) !void {
    var case = try support.Scenario.init(
        fixture,
        if (changed_root) "removal-failure-postrm-early-recovery-changed-root" else "removal-failure-postrm-early-recovery",
        driver,
        dpkg,
        arch,
        false,
    );
    defer case.deinit();
    try case.seed(first);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    try bothFile(&case, configuration, "edited configuration\n");
    try bothFile(&case, support.failure, name ++ "@1:postrm:remove\n");
    try phase(&case, .{ .operation = "remove", .packages = &selected }, true, &.{
        .{ .kind = "prerm", .args = &.{"remove"}, .payload = "data version 1" },
        .{ .kind = "postrm", .args = &.{"remove"} },
    });
    try bothFile(&case, support.failure, null);
    if (fixture.oracle_only) {
        if (changed_root) return;
        try phase(&case, .{ .operation = "remove", .packages = &selected }, false, &.{
            .{ .kind = "postrm", .args = &.{"remove"} },
        });
        return;
    }
    const destination = try support.path(fixture.allocator, case.name, "interrupted-before-remove");
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "remove",
        .packages = &selected,
    }, destination) != 0) return error.UnexpectedReferenceRetry;
    if (support.native(fixture, driver, case.native_root, arch, .{
        .operation = "remove",
        .packages = &selected,
        .recovery = true,
        .crash_at = "after_execution_intent",
    }, destination)) |unexpected| {
        var result = unexpected;
        result.deinit();
        return error.EarlyRetryCrashNotInjected;
    } else |err| if (err != error.ChildFailed) return err;
    const pre_resume_trace = try relative(&case, "native", support.trace);
    defer fixture.allocator.free(pre_resume_trace);
    const prior_trace = try support.read(fixture, pre_resume_trace, 64 * 1024);
    defer fixture.allocator.free(prior_trace);
    if (std.mem.count(u8, prior_trace, name ++ "@1:prerm\t") != 1 or
        std.mem.count(u8, prior_trace, name ++ "@1:postrm\t") != 1)
        return error.EarlyRetryReplayedScript;
    const marker = try relative(&case, "native", "var/lib/debz/native-remove-retry-v1.json");
    defer fixture.allocator.free(marker);
    var before: ?[]u8 = null;
    defer if (before) |value| fixture.allocator.free(value);
    var original_marker: ?[]u8 = null;
    defer if (original_marker) |value| fixture.allocator.free(value);
    if (changed_root) {
        const conffile = try relative(&case, "native", configuration);
        defer fixture.allocator.free(conffile);
        try support.fixtureFile(fixture, conffile, "changed after crash\n", 0o644);
        before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        original_marker = try support.read(fixture, marker, 4096);
    }
    const destination_resume = try support.path(fixture.allocator, case.name, "resume");
    defer fixture.allocator.free(destination_resume);
    try fixture.directory(destination_resume);
    var resumed = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "recover",
        .recovery = true,
    }, destination_resume);
    defer resumed.deinit();
    if (changed_root) {
        if (!std.mem.eql(u8, resumed.value.outcome, "recovery_required") or
            !std.mem.eql(u8, resumed.value.detail, "removal_retry_recovery_binding_changed"))
            return error.EarlyRetryChangedRootAccepted;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        const retained_marker = try support.read(fixture, marker, 4096);
        defer fixture.allocator.free(retained_marker);
        const retained_trace = try support.read(fixture, pre_resume_trace, 64 * 1024);
        defer fixture.allocator.free(retained_trace);
        if (!std.mem.eql(u8, before.?, after) or
            !std.mem.eql(u8, original_marker.?, retained_marker) or
            !std.mem.eql(u8, prior_trace, retained_trace))
            return error.EarlyRetryChangedRootMutated;
        const next = try support.path(fixture.allocator, case.name, "changed-root-second-mutation");
        defer fixture.allocator.free(next);
        try fixture.directory(next);
        var blocked = try support.native(fixture, driver, case.native_root, arch, .{
            .operation = "remove",
            .packages = &selected,
        }, next);
        defer blocked.deinit();
        if (!std.mem.eql(u8, blocked.value.outcome, "recovery_required"))
            return error.EarlyRetryChangedRootAllowedMutation;
        const final = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(final);
        if (!std.mem.eql(u8, before.?, final))
            return error.EarlyRetryChangedRootMutated;
        return;
    }
    if (!std.mem.eql(u8, resumed.value.outcome, "applied"))
        return error.EarlyRetryRecoveryFailed;
    const reference = try foundation.capture(fixture.allocator, fixture.io, case.reference_root);
    defer fixture.allocator.free(reference);
    const native = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(native);
    if (!std.mem.eql(u8, reference, native))
        return error.EarlyRetryRecoveryMismatch;
    const after_trace = try support.read(fixture, pre_resume_trace, 64 * 1024);
    defer fixture.allocator.free(after_trace);
    const reference_trace = try trace(&case);
    defer fixture.allocator.free(reference_trace);
    if (!std.mem.eql(u8, after_trace, reference_trace) or
        std.mem.count(u8, after_trace, name ++ "@1:prerm\t") != 1 or
        std.mem.count(u8, after_trace, name ++ "@1:postrm\t") != 2)
        return error.EarlyRetryReplayedScript;
    try support.absent(fixture, marker);
    try support.assertNoActiveEvidence(fixture, case.native_root);
}

fn unknownRemoval(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8, first: []const u8) !void {
    var case = try support.Scenario.init(fixture, "removal-prerm-outcome-unknown", driver, dpkg, arch, false);
    defer case.deinit();
    try case.seed(first);
    const selected = [_]foundation.PackageIdentity{.{ .name = name, .architecture = arch }};
    if (fixture.oracle_only) {
        try case.phase(.{ .operation = "remove", .packages = &selected }, false);
        return;
    }
    const destination = try support.path(fixture.allocator, case.name, "reference-terminal");
    defer fixture.allocator.free(destination);
    try fixture.directory(destination);
    if (try support.reference(fixture, dpkg, case.reference_root, .{
        .operation = "remove",
        .packages = &selected,
    }, destination) != 0) return error.UnexpectedReferenceRemoval;
    const interrupted = try support.path(fixture.allocator, case.name, "interrupted");
    defer fixture.allocator.free(interrupted);
    try fixture.directory(interrupted);
    var report = try support.native(fixture, driver, case.native_root, arch, .{
        .operation = "remove",
        .packages = &selected,
        .fault = "after_script_before_record",
    }, interrupted);
    defer report.deinit();
    if (!std.mem.eql(u8, report.value.outcome, "recovery_required"))
        return error.UnknownRemovalOutcomeAccepted;
    const operation_path = try relative(&case, "native", "var/lib/debz/root-operation-v1.json");
    defer fixture.allocator.free(operation_path);
    const script_path = try relative(&case, "native", "var/lib/debz/native-lifecycle-script-v1.json");
    defer fixture.allocator.free(script_path);
    const operation_bytes = try support.read(fixture, operation_path, 1024 * 1024);
    defer fixture.allocator.free(operation_bytes);
    const script_bytes = try support.read(fixture, script_path, 1024 * 1024);
    defer fixture.allocator.free(script_bytes);
    const Operation = struct {
        state: []const u8,
        phase: []const u8,
        mutation_started: bool,
        program_sha256: []const u8,
    };
    const Script = struct {
        program_sha256: []const u8,
        package: []const u8,
        version: []const u8,
        kind: []const u8,
        source: []const u8,
        script_sha256: []const u8,
        arguments: []const []const u8,
        outcome: []const u8,
        exit_code: ?u8,
    };
    const operation = try std.json.parseFromSlice(Operation, fixture.allocator, operation_bytes, .{ .ignore_unknown_fields = true });
    defer operation.deinit();
    const script = try std.json.parseFromSlice(Script, fixture.allocator, script_bytes, .{ .ignore_unknown_fields = true });
    defer script.deinit();
    const installed_path = try relative(&case, "native", "var/lib/dpkg/info/" ++ name ++ ".prerm");
    defer fixture.allocator.free(installed_path);
    const installed_script = try support.read(fixture, installed_path, 64 * 1024);
    defer fixture.allocator.free(installed_script);
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(installed_script, &hash, .{});
    if (!std.mem.eql(u8, operation.value.state, "recovery_required") or
        !std.mem.eql(u8, operation.value.phase, "script") or
        !operation.value.mutation_started or
        !std.mem.eql(u8, script.value.program_sha256, operation.value.program_sha256) or
        !std.mem.eql(u8, script.value.package, name) or
        !std.mem.eql(u8, script.value.version, "1") or
        !std.mem.eql(u8, script.value.kind, "prerm") or
        !std.mem.eql(u8, script.value.source, "installed_package") or
        !std.mem.eql(u8, script.value.script_sha256, &std.fmt.bytesToHex(hash, .lower)) or
        script.value.arguments.len != 1 or !std.mem.eql(u8, script.value.arguments[0], "remove") or
        !std.mem.eql(u8, script.value.outcome, "in_flight") or script.value.exit_code != null)
        return error.InvalidRemovalRecoveryBinding;
    const seen = try std.fmt.allocPrint(fixture.allocator, "{s}@1:prerm\t{s}\tprerm\t{s}\t1\t6:remove\tpayload=data version 1\n", .{
        name, name, arch,
    });
    defer fixture.allocator.free(seen);
    const trace_path = try relative(&case, "native", support.trace);
    defer fixture.allocator.free(trace_path);
    const executed = try support.read(fixture, trace_path, 64 * 1024);
    defer fixture.allocator.free(executed);
    if (!std.mem.eql(u8, executed, seen)) return error.UnknownRemovalSkippedOrRepeatedScript;
    const before = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
    defer fixture.allocator.free(before);
    for ([_][]const u8{ "remove", "purge", "recover" }) |operation_name| {
        const next = try support.path(fixture.allocator, case.name, operation_name);
        defer fixture.allocator.free(next);
        try fixture.directory(next);
        var blocked = try support.native(fixture, driver, case.native_root, arch, .{
            .operation = operation_name,
            .packages = if (std.mem.eql(u8, operation_name, "recover")) &.{} else &selected,
            .recovery = std.mem.eql(u8, operation_name, "recover"),
        }, next);
        defer blocked.deinit();
        if (!std.mem.eql(u8, blocked.value.outcome, "recovery_required"))
            return error.UnknownRemovalAllowedReplay;
        const after = try foundation.capture(fixture.allocator, fixture.io, case.native_root);
        defer fixture.allocator.free(after);
        const operation_after = try support.read(fixture, operation_path, 1024 * 1024);
        defer fixture.allocator.free(operation_after);
        const script_after = try support.read(fixture, script_path, 1024 * 1024);
        defer fixture.allocator.free(script_after);
        if (!std.mem.eql(u8, before, after) or
            !std.mem.eql(u8, operation_bytes, operation_after) or
            !std.mem.eql(u8, script_bytes, script_after))
            return error.UnknownRemovalChangedRootOrOwnership;
    }
}

pub fn run(fixture: *foundation.Fixture, driver: []const u8, dpkg: []const u8, arch: []const u8) !void {
    const first = try support.makePackage(fixture, arch, "1", name, "packages/removal", .{
        .conffile_content = "configuration 1\n",
        .full_payload = true,
    });
    defer fixture.allocator.free(first);
    const second = try support.makePackage(fixture, arch, "2", name, "packages/removal", .{
        .conffile_content = "configuration 1\n",
        .full_payload = true,
    });
    defer fixture.allocator.free(second);
    try residueAndReinstall(fixture, driver, dpkg, arch, first, second);
    try removedReinstallBlock(fixture, driver, dpkg, arch, first);
    try failureAndRetry(fixture, driver, dpkg, arch, first);
    try interruptedPostrmRetry(fixture, driver, dpkg, arch, first);
    try recoverEarlyPostrmRetry(fixture, driver, dpkg, arch, first, false);
    if (!fixture.oracle_only)
        try recoverEarlyPostrmRetry(fixture, driver, dpkg, arch, first, true);
    try unknownRemoval(fixture, driver, dpkg, arch, first);
}
