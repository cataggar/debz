const std = @import("std");
const linux = std.os.linux;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");

const marker = "debz native projection fixture v1\n";
const root_mount = "/run/debz/system-root";

const Selector = struct { name: []const u8, architecture: ?[]const u8 = null };
const Verification = struct {
    lock_path: []const u8 = "/fixture/lock.json",
    lock_sha256: [32]u8,
    lock_schema: []const u8 = "https://debz.dev/schema/exact-closure-lock-v3",
    lock_version: u32 = 3,
    backend: []const u8 = "native",
    state: []const u8,
    outcome: []const u8 = "succeeded",
    expected_error: ?[]const u8 = null,
    review: ?[]const u8 = null,
    review_generation: u64 = 1,
};
const Step = struct {
    mode: []const u8,
    selected: []const Selector,
    owner: bool = false,
    review_evidence: bool = false,
    crash: bool = false,
    crash_at: []const u8 = "after_native_receipt",
    facade_recover: bool = false,
    defer_clear: bool = false,
    withhold_projection: bool = false,
    architecture_override: ?[]const u8 = null,
    recommends: bool = false,
    acknowledgment: ?[]const u8 = null,
    verification: ?Verification = null,
    prepare_acknowledged_review: ?struct {
        lock_path: []const u8 = "/fixture/lock.json",
        lock_sha256: [32]u8,
        generation: u64,
    } = null,
    prepare_cleared_review: ?struct {
        lock_path: []const u8 = "/fixture/lock.json",
        lock_sha256: [32]u8,
        receipt_sha256: [32]u8,
        generation: u64,
    } = null,
};

fn same(value: []const u8, expected: []const u8) !void {
    if (!std.mem.eql(u8, value, expected)) {
        std.debug.print("expected {s}, observed {s}\n", .{ expected, value });
        return error.UnexpectedProjectedWorkflowEvidence;
    }
}

fn field(value: std.json.Value, name: []const u8) !std.json.Value {
    if (value != .object) return error.InvalidProjectedWorkflowEvidence;
    return value.object.get(name) orelse error.MissingProjectedWorkflowEvidence;
}

fn text(value: std.json.Value, name: []const u8) ![]const u8 {
    const member = try field(value, name);
    if (member != .string) return error.InvalidProjectedWorkflowEvidence;
    return member.string;
}

fn parse(fixture: *foundation.Fixture, relative: []const u8, maximum: usize) !std.json.Parsed(std.json.Value) {
    const bytes = try support.read(fixture, relative, maximum);
    defer fixture.allocator.free(bytes);
    return std.json.parseFromSlice(std.json.Value, fixture.allocator, bytes, .{ .allocate = .alloc_always });
}

fn rootPath(fixture: *foundation.Fixture, root: []const u8, path: []const u8) ![]const u8 {
    if (root.len <= fixture.path.len or !std.mem.startsWith(u8, root, fixture.path) or root[fixture.path.len] != '/')
        return error.InvalidProjectedRoot;
    return support.path(fixture.allocator, root[fixture.path.len + 1 ..], path);
}

fn mount(args: []const []const u8, init: std.process.Init, allocator: std.mem.Allocator) !void {
    const result = try std.process.run(allocator, init.io, .{
        .argv = args,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("private workflow mount {any}: {s}\n", .{ result.term, result.stderr });
        return error.PrivateProjectedMountFailed;
    }
}

pub fn inside(init: std.process.Init, allocator: std.mem.Allocator, root: []const u8) !void {
    const prefix = try std.fmt.allocPrint(allocator, "{s}/.tmp/native-zig-", .{options.repository});
    const section = "/executed/projected-";
    if (!std.mem.startsWith(u8, root, prefix) or linux.getpid() != 1 or linux.geteuid() != 0)
        return error.DisposableProjectedRootRequired;
    const remainder = root[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, remainder, '/') orelse return error.DisposableProjectedRootRequired;
    if (slash == 0 or !std.mem.startsWith(u8, remainder[slash..], section) or
        !std.mem.endsWith(u8, remainder, "/native")) return error.DisposableProjectedRootRequired;
    const outcome = remainder[slash + section.len .. remainder.len - "/native".len];
    if (!std.mem.eql(u8, outcome, "success") and !std.mem.eql(u8, outcome, "recovered") and
        !std.mem.eql(u8, outcome, "failed") and !std.mem.eql(u8, outcome, "readonly"))
        return error.DisposableProjectedRootRequired;
    var guarded = foundation.guardedRoot(init.io, root) catch return error.DisposableProjectedRootRequired;
    defer guarded.close(init.io);
    const observed = try guarded.readFileAlloc(init.io, ".debz-native-projection", allocator, .limited(128));
    if (!std.mem.eql(u8, observed, marker)) return error.DisposableProjectedRootRequired;
    try mount(&.{ "/usr/bin/mount", "--bind", root, root }, init, allocator);
    try mount(&.{ "/usr/bin/mount", "-t", "proc", "proc", try std.fmt.allocPrint(allocator, "{s}/proc", .{root}) }, init, allocator);
    const absolute = try allocator.dupeZ(u8, root);
    if (linux.errno(linux.chdir(absolute)) != .SUCCESS or
        linux.errno(linux.chroot(".")) != .SUCCESS or
        linux.errno(linux.chdir("/")) != .SUCCESS) return error.PrivateProjectedChrootFailed;
    const environment: []const []const u8 = if (std.mem.eql(u8, outcome, "readonly"))
        &.{ "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TMPDIR=/tmp", "XDG_CACHE_HOME=/tmp/.cache", "DEBZ_NATIVE_PROJECTION_FIXTURE=1" }
    else
        &.{ "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TMPDIR=/tmp", "XDG_CACHE_HOME=/tmp/.cache", "DEBZ_NATIVE_WORKFLOW_REQUEST=/fixture/request.json" };
    const argv = [_:null]?[*:0]const u8{"/fixture/native-test"};
    var envp = try allocator.allocSentinel(?[*:0]const u8, environment.len, null);
    for (environment, 0..) |entry, index| envp[index] = (try allocator.dupeZ(u8, entry)).ptr;
    if (linux.errno(linux.execve("/fixture/native-test", &argv, envp.ptr)) != .SUCCESS)
        return error.PrivateProjectedExecFailed;
    unreachable;
}

fn assertMountCleared(fixture: *foundation.Fixture, root: []const u8) !void {
    var directory = fixture.dir.openDir(fixture.io, try rootPath(fixture, root, "run/debz/system-root"), .{ .iterate = true, .follow_symlinks = false }) catch |err| {
        if (err == error.FileNotFound) return;
        return err;
    };
    defer directory.close(fixture.io);
    var iterator = directory.iterate();
    if (try iterator.next(fixture.io) != null) return error.ProjectedWorkflowMountLeaked;
}

pub fn evidenceInventory(fixture: *foundation.Fixture, root: []const u8, include_metadata: bool) ![]const u8 {
    return inventory(fixture, root, "var/lib/debz", include_metadata);
}

pub fn rootInventory(fixture: *foundation.Fixture, root: []const u8, include_metadata: bool) ![]const u8 {
    return inventory(fixture, root, ".", include_metadata);
}

fn inventory(fixture: *foundation.Fixture, root: []const u8, scope: []const u8, include_metadata: bool) ![]const u8 {
    const namespace = try rootPath(fixture, root, scope);
    var directory = try fixture.dir.openDir(fixture.io, namespace, .{ .iterate = true, .follow_symlinks = false });
    defer directory.close(fixture.io);
    var walker = try directory.walk(fixture.allocator);
    defer walker.deinit();
    const Entry = struct {
        path: []const u8,
        kind: []const u8,
        mode: u32,
        inode: ?u64,
        size: u64,
        mtime_ns: ?i128,
        data_hex: ?[]const u8,
    };
    var rows: std.ArrayList(Entry) = .empty;
    var total: usize = 0;
    while (try walker.next(fixture.io)) |item| {
        if (rows.items.len >= 4096) return error.ProjectedEvidenceInventoryTooLarge;
        const path = try support.path(fixture.allocator, namespace, item.path);
        const stat = try fixture.dir.statFile(fixture.io, path, .{ .follow_symlinks = false });
        const bytes: ?[]const u8 = if (item.kind == .file) try support.read(fixture, path, 16 * 1024 * 1024) else null;
        const encoded: ?[]const u8 = if (bytes) |raw| encoded: {
            total = try std.math.add(usize, total, raw.len);
            if (total > 32 * 1024 * 1024) return error.ProjectedEvidenceInventoryTooLarge;
            const hex = try fixture.allocator.alloc(u8, raw.len * 2);
            const alphabet = "0123456789abcdef";
            for (raw, 0..) |byte, index| {
                hex[index * 2] = alphabet[byte >> 4];
                hex[index * 2 + 1] = alphabet[byte & 15];
            }
            break :encoded hex;
        } else null;
        try rows.append(fixture.allocator, .{
            .path = try fixture.allocator.dupe(u8, item.path),
            .kind = @tagName(item.kind),
            .mode = stat.permissions.toMode(),
            .inode = if (include_metadata) stat.inode else null,
            .size = stat.size,
            .mtime_ns = if (include_metadata) stat.mtime.nanoseconds else null,
            .data_hex = encoded,
        });
    }
    std.mem.sort(Entry, rows.items, {}, struct {
        fn lessThan(_: void, left: Entry, right: Entry) bool {
            return std.mem.lessThan(u8, left.path, right.path);
        }
    }.lessThan);
    return std.json.Stringify.valueAlloc(fixture.allocator, rows.items, .{});
}

fn invoke(
    fixture: *foundation.Fixture,
    self: []const u8,
    root: []const u8,
    label: []const u8,
    step: Step,
) !?std.json.Parsed(std.json.Value) {
    const evidence_before = if (step.verification) |check|
        if (check.review != null and (std.mem.eql(u8, check.review.?, "transfer") or
            std.mem.eql(u8, check.review.?, "publish") or
            std.mem.eql(u8, check.review.?, "publish_stale") or
            std.mem.eql(u8, check.review.?, "clear"))) null else try evidenceInventory(fixture, root, true)
    else
        null;
    const request = try rootPath(fixture, root, "fixture/request.json");
    const report = try rootPath(fixture, root, "fixture/report.json");
    fixture.dir.deleteFile(fixture.io, report) catch |err| if (err != error.FileNotFound) return err;
    const planning = std.mem.eql(u8, step.mode, "plan_only");
    const recovering = std.mem.eql(u8, step.mode, "recover");
    const payload = try std.json.Stringify.valueAlloc(fixture.allocator, .{
        .workflow = .{
            .operation = "install",
            .mode = step.mode,
            .selectors = step.selected,
            .options = .{
                .install_root = root_mount,
                .architecture = step.architecture_override orelse std.mem.trim(u8, try support.read(fixture, try rootPath(fixture, root, "var/lib/dpkg/arch"), 32), " \r\n"),
                .cache_path = if (recovering) "/fixture/unused-cache" else "/fixture/cache",
                .state_path = if (recovering) "/fixture/unused-state" else "/fixture/state",
                .source_paths = if (recovering) &.{} else &.{"/fixture/workflow.sources"},
                .keyring_paths = if (recovering) &.{} else &.{"/fixture/repository/fixture-keyring.gpg"},
                .lock_output_path = if (planning) "/fixture/lock.json" else null,
                .lock_input_path = if (!planning and !recovering) "/fixture/lock.json" else null,
                .conffile = "keep_existing",
                .recommends = step.recommends,
                .assume_yes = true,
                .noninteractive = true,
            },
            .orchestration_id = if (planning) @as(?[32]u8, null) else @as(?[32]u8, @splat(23)),
            .defer_recovery_clear = recovering and step.defer_clear,
        },
        .report = "/fixture/report.json",
        .projected = true,
        .withhold_projection = step.withhold_projection,
        .completion_crash = if (step.crash) step.crash_at else null,
        .facade_recover = step.facade_recover,
        .owner_evidence = if (step.owner) @as(?[]const u8, "/fixture/owner.json") else null,
        .review_evidence = if (step.review_evidence) @as(?[]const u8, "/fixture/owner.json.review-claim") else null,
        .acknowledgment = step.acknowledgment,
        .owned_verification = step.verification,
        .prepare_acknowledged_review = step.prepare_acknowledged_review,
        .prepare_cleared_review = step.prepare_cleared_review,
    }, .{});
    try fixture.write(request, payload, 0o644);
    const result = try std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", "/usr/bin/unshare", "--mount", "--pid", "--fork", "--", self, "--inside-projected", root },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    });
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const output = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    const log = try std.fmt.allocPrint(fixture.allocator, "{s}.log", .{label});
    try fixture.write(log, output, 0o644);
    if (result.term != .exited or result.term.exited != @as(u8, if (step.crash) 86 else 0)) {
        std.debug.print("projected {s} exited {any}; {s}\n", .{ label, result.term, output[output.len - @min(output.len, 12_000) ..] });
        return error.UnexpectedProjectedWorkflowExit;
    }
    try assertMountCleared(fixture, root);
    if (evidence_before) |before| {
        const after = try evidenceInventory(fixture, root, true);
        if (!std.mem.eql(u8, before, after)) {
            try fixture.write(try std.fmt.allocPrint(fixture.allocator, "{s}.inventory-before.json", .{label}), before, 0o644);
            try fixture.write(try std.fmt.allocPrint(fixture.allocator, "{s}.inventory-after.json", .{label}), after, 0o644);
            return error.ProjectedVerificationChangedEvidence;
        }
    }
    if (step.crash) {
        try support.absent(fixture, report);
        return null;
    }
    return try parse(fixture, report, 64 * 1024);
}

fn setup(
    fixture: *foundation.Fixture,
    driver: []const u8,
    reference: []const u8,
    arch: []const u8,
    name: []const u8,
) !support.Scenario {
    var scenario = try support.Scenario.init(fixture, name, driver, reference, arch, true);
    errdefer scenario.deinit();
    for ([_][]const u8{ "native-helper-target", "essential-core" }) |package| {
        const archive = try fixture.absolute(try std.fmt.allocPrint(fixture.allocator, "executed/repository/pool/main/{s}_1.0-1_{s}.deb", .{ package, arch }));
        try scenario.seed(archive);
    }
    const relative = scenario.native_root[fixture.path.len + 1 ..];
    try fixture.write(try support.path(fixture.allocator, relative, ".debz-native-projection"), marker, 0o600);
    for ([_][]const u8{ "proc", "run", "tmp", "dev", "fixture" }) |directory|
        try fixture.directory(try support.path(fixture.allocator, relative, directory));
    try fixture.run(&.{
        "/usr/bin/mknod", "-m", "666", try fixture.absolute(try support.path(fixture.allocator, relative, "dev/null")), "c", "1", "3",
    }, try support.path(fixture.allocator, name, "mknod.log"), 10);
    const driver_path = if (std.fs.path.isAbsolute(driver)) driver else try std.fs.path.resolve(fixture.allocator, &.{ options.repository, driver });
    try support.copyProgram(fixture, relative, driver_path, "/fixture/native-test");
    const reference_relative = scenario.reference_root[fixture.path.len + 1 ..];
    try fixture.directory(try support.path(fixture.allocator, reference_relative, "fixture"));
    try support.copyProgram(fixture, reference_relative, driver_path, "/fixture/native-test");
    const destination = try fixture.absolute(try support.path(fixture.allocator, relative, "fixture/repository"));
    try fixture.run(&.{ "/usr/bin/cp", "-a", try fixture.absolute("executed/repository"), destination }, try support.path(fixture.allocator, name, "copy-repository.log"), 60);
    try fixture.write(try support.path(fixture.allocator, relative, "fixture/workflow.sources"), try std.fmt.allocPrint(
        fixture.allocator,
        "Types: deb\nURIs: file:///fixture/repository\nSuites: debian-stable\nComponents: main\nArchitectures: {s}\nSigned-By: /fixture/repository/fixture-keyring.gpg\n",
        .{arch},
    ), 0o644);
    return scenario;
}

fn compare(fixture: *foundation.Fixture, scenario: *support.Scenario) !void {
    const excludes: []const []const u8 = &.{
        foundation.guard, "usr/bin/dpkg-trigger", ".debz-native-projection", "fixture", "proc", "run", "tmp", "dev",
    };
    const expected = try foundation.captureRealRoot(fixture.allocator, fixture.io, scenario.reference_root, .{}, excludes);
    const actual = try foundation.captureRealRoot(fixture.allocator, fixture.io, scenario.native_root, .{}, excludes);
    if (!std.mem.eql(u8, expected, actual)) {
        const location = try support.path(fixture.allocator, scenario.name, "reference.snapshot.json");
        try fixture.write(location, expected, 0o644);
        try fixture.write(try support.path(fixture.allocator, scenario.name, "projected.snapshot.json"), actual, 0o644);
        return error.ProjectedDpkgMismatch;
    }
}

pub fn run(fixture: *foundation.Fixture, self: []const u8, driver: []const u8, reference: []const u8, arch: []const u8) !void {
    try runReadOnly(fixture, self, driver, arch);
    const runner = if (std.fs.path.isAbsolute(self)) self else try std.fs.path.resolve(fixture.allocator, &.{ options.repository, self });
    for ([_][]const u8{ "success", "recovered", "failed" }) |outcome|
        try caseRun(fixture, runner, driver, reference, arch, outcome);
}

pub fn runReadOnly(fixture: *foundation.Fixture, self: []const u8, driver: []const u8, arch: []const u8) !void {
    try fixture.directory("executed");
    const runner = if (std.fs.path.isAbsolute(self)) self else try std.fs.path.resolve(fixture.allocator, &.{ options.repository, self });
    try readOnlyProjection(fixture, runner, driver, arch);
}

fn readOnlyProjection(fixture: *foundation.Fixture, self: []const u8, driver: []const u8, arch: []const u8) !void {
    const root = try fixture.makeRoot("executed/projected-readonly/native", arch);
    const relative = root[fixture.path.len + 1 ..];
    try fixture.write(try rootPath(fixture, root, ".debz-native-projection"), marker, 0o644);
    for ([_][]const u8{ "proc", "run", "tmp", "fixture" }) |directory|
        try fixture.directory(try rootPath(fixture, root, directory));
    try fixture.write(try rootPath(fixture, root, "var/lib/debz/root-operation.lock"), "", 0o600);
    const driver_path = if (std.fs.path.isAbsolute(driver)) driver else try std.fs.path.resolve(fixture.allocator, &.{ options.repository, driver });
    try support.copyProgram(fixture, relative, driver_path, "/fixture/native-test");
    const before = try evidenceInventory(fixture, root, true);
    const result = try std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", "/usr/bin/unshare", "--mount", "--pid", "--fork", "--", self, "--inside-projected", root },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    });
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    try fixture.write("executed/projected-readonly.log", result.stderr, 0o644);
    if (result.term != .exited or result.term.exited != 0 or
        std.mem.indexOf(u8, result.stderr, "native_transaction_result.test.projected root external fixture...OK") == null or
        std.mem.indexOf(u8, result.stderr, "apt_system_orchestrator.test.projected native dispatch external fixture...OK") == null)
    {
        std.debug.print("read-only projected tests exited {any}: {s}\n", .{ result.term, result.stderr });
        return error.ProjectedReadOnlyTestsFailed;
    }
    try assertMountCleared(fixture, root);
    if (!std.mem.eql(u8, before, try evidenceInventory(fixture, root, true)))
        return error.ProjectedReadOnlyChangedEvidence;
    const lock = try support.read(fixture, try rootPath(fixture, root, "var/lib/debz/root-operation.lock"), 64);
    if (lock.len != 0) return error.ProjectedReadOnlyChangedLock;
    std.debug.print("projected read-only: two real root-bound unit fixtures, unchanged evidence and mount cleanup passed\n", .{});
}

fn archiveAt(fixture: *foundation.Fixture, arch: []const u8, name: []const u8) ![]const u8 {
    return fixture.absolute(try std.fmt.allocPrint(fixture.allocator, "executed/repository/pool/main/{s}_1.0-1_{s}.deb", .{ name, arch }));
}

fn caseRun(fixture: *foundation.Fixture, runner: []const u8, driver: []const u8, reference: []const u8, arch: []const u8, outcome: []const u8) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "executed/projected-{s}", .{outcome});
    const success = std.mem.eql(u8, outcome, "success");
    const failed = std.mem.eql(u8, outcome, "failed");
    var scenario = try setup(fixture, driver, reference, arch, name);
    defer scenario.deinit();
    const selected: []const Selector = if (failed) &.{.{ .name = "fail-script" }} else &.{ .{ .name = "scenario-main" }, .{ .name = "conffile-pkg" } };
    var plan = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "plan"), .{ .mode = "plan_only", .selected = selected })) orelse return error.MissingProjectedReport;
    defer plan.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(plan.value, "exit_status")).integer);
    var lock = try parse(fixture, try rootPath(fixture, scenario.native_root, "fixture/lock.json"), 1024 * 1024);
    defer lock.deinit();
    var lock_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&lock_digest, try text(lock.value, "digest_sha256"));
    const original_status = try support.read(fixture, try rootPath(fixture, scenario.native_root, "var/lib/dpkg/status"), 1024 * 1024);
    var refused = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "withheld-reserve"), .{
        .mode = "reserve",
        .selected = selected,
        .withhold_projection = true,
    })) orelse return error.MissingProjectedReport;
    defer refused.deinit();
    try std.testing.expect((try field(refused.value, "exit_status")).integer != 0);
    try std.testing.expect(!(try field(refused.value, "changed")).bool);
    try std.testing.expectEqualSlices(u8, original_status, try support.read(fixture, try rootPath(fixture, scenario.native_root, "var/lib/dpkg/status"), 1024 * 1024));
    const withheld_operation = try rootPath(fixture, scenario.native_root, "var/lib/debz/root-operation-v1.json");
    try support.absent(fixture, withheld_operation);
    try support.absent(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/root-operation-deferred-ack-v1.json"));
    var reserved = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "reserve"), .{
        .mode = "reserve",
        .selected = selected,
    })) orelse return error.MissingProjectedReport;
    defer reserved.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(reserved.value, "exit_status")).integer);
    const owner = try rootPath(fixture, scenario.native_root, "var/lib/debz/root-operation-deferred-ack-v1.json");
    const owner_file = try rootPath(fixture, scenario.native_root, "fixture/owner.json");
    try fixture.write(owner_file, try support.read(fixture, owner, 64 * 1024), 0o644);
    const result = try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "execute"), .{
        .mode = "execute",
        .selected = selected,
        .owner = true,
        .crash = !success,
    });
    if (result) |document| {
        var executed = document;
        defer executed.deinit();
        if (!success) return error.MissingProjectedCrash;
        try std.testing.expectEqual(@as(i64, 0), (try field(executed.value, "exit_status")).integer);
        try std.testing.expect((try field(executed.value, "changed")).bool);
    } else if (success) return error.MissingProjectedReport;
    try fixture.write(owner_file, try support.read(fixture, owner, 64 * 1024), 0o644);
    if (!success) {
        for ([_][]const u8{ "recover", "recover-again" }) |phase| {
            var recovery = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, phase), .{
                .mode = "recover",
                .selected = selected,
                .owner = true,
                .facade_recover = true,
                .defer_clear = true,
            })) orelse return error.MissingProjectedReport;
            defer recovery.deinit();
            try std.testing.expectEqual(@as(i64, if (failed) 7 else 0), (try field(recovery.value, "exit_status")).integer);
            try fixture.write(owner_file, try support.read(fixture, owner, 64 * 1024), 0o644);
        }
    }
    var receipt = try parse(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/native-transaction-provenance-v2.json"), 16 * 1024 * 1024);
    defer receipt.deinit();
    try same(try text(receipt.value, "install_root"), root_mount);
    try same(try text(receipt.value, "outcome"), if (failed) "failed" else "succeeded");
    try same(try text(receipt.value, "exact_lock_sha256"), try text(lock.value, "digest_sha256"));
    var completion = try parse(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/root-operation-completion-v2.json"), 64 * 1024);
    defer completion.deinit();
    try same(try text(try field(completion.value, "transaction_provenance"), "document_sha256"), try text(receipt.value, "digest_sha256"));
    try same(try text(try field(completion.value, "discharge"), "operation"), if (success) "install" else "recover");
    const reference_log = try support.path(fixture.allocator, name, "reference-execute");
    try fixture.directory(reference_log);
    const archives: []const []const u8 = if (failed)
        &.{try archiveAt(fixture, arch, "fail-script")}
    else
        &.{ try archiveAt(fixture, arch, "base-dep"), try archiveAt(fixture, arch, "scenario-main"), try archiveAt(fixture, arch, "conffile-pkg") };
    const reference_exit = try support.reference(fixture, reference, scenario.reference_root, .{
        .operation = "install",
        .archives = archives,
        .triggers = true,
    }, reference_log);
    if (reference_exit != @as(u8, if (failed) 1 else 0)) return error.ReferenceProjectedInstallFailed;
    try compare(fixture, &scenario);
    const status_path = try rootPath(fixture, scenario.native_root, "var/lib/dpkg/status");
    const status_before = try support.read(fixture, status_path, 1024 * 1024);
    const owner_before = try support.read(fixture, owner, 64 * 1024);
    const receipt_before = try support.read(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/native-transaction-provenance-v2.json"), 16 * 1024 * 1024);
    const completion_path = try rootPath(fixture, scenario.native_root, "var/lib/debz/root-operation-completion-v2.json");
    const completion_before = try support.read(fixture, completion_path, 64 * 1024);
    for ([_]bool{ true, false }) |valid| {
        var verification = (try invoke(fixture, runner, scenario.native_root, try std.fmt.allocPrint(fixture.allocator, "{s}/verify-{s}", .{ name, if (valid) "valid" else "wrong-digest" }), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .defer_clear = !success,
            .verification = .{
                .lock_sha256 = if (valid) lock_digest else @splat(0),
                .state = if (success) "released" else "pending",
                .outcome = if (failed) "failed" else "succeeded",
                .expected_error = if (valid) null else "OperationalVerificationFailure",
            },
        })) orelse return error.MissingProjectedReport;
        defer verification.deinit();
        try std.testing.expectEqual(valid, (try field(verification.value, "verified")).bool);
        if (valid) try same(try text(verification.value, "outcome"), if (failed) "failed" else "succeeded");
        try std.testing.expectEqualSlices(u8, owner_before, try support.read(fixture, owner, 64 * 1024));
        try std.testing.expectEqualSlices(u8, status_before, try support.read(fixture, status_path, 1024 * 1024));
        try std.testing.expectEqualSlices(u8, receipt_before, try support.read(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/native-transaction-provenance-v2.json"), 16 * 1024 * 1024));
    }
    for (0..7) |index| {
        var check: Verification = .{
            .lock_sha256 = lock_digest,
            .state = if (success) "released" else "pending",
            .outcome = if (failed) "failed" else "succeeded",
            .expected_error = "OperationalVerificationFailure",
        };
        var step: Step = .{ .mode = "recover", .selected = selected, .owner = true, .defer_clear = !success };
        switch (index) {
            0 => check.backend = "legacy_dpkg",
            1 => check.lock_version = 1,
            2 => check.lock_schema = "https://debz.dev/schema/exact-closure-lock-v1",
            3 => check.outcome = if (failed) "succeeded" else "failed",
            4 => step.recommends = true,
            5 => step.selected = &.{.{ .name = "different-package" }},
            6 => step.architecture_override = if (std.mem.eql(u8, arch, "arm64")) "amd64" else "arm64",
            else => unreachable,
        }
        step.verification = check;
        var rejected = (try invoke(fixture, runner, scenario.native_root, try std.fmt.allocPrint(fixture.allocator, "{s}/invalid-verification-{d}", .{ name, index }), step)) orelse return error.MissingProjectedReport;
        defer rejected.deinit();
        try std.testing.expect(!(try field(rejected.value, "verified")).bool);
        try std.testing.expectEqualSlices(u8, owner_before, try support.read(fixture, owner, 64 * 1024));
        try std.testing.expectEqualSlices(u8, status_before, try support.read(fixture, status_path, 1024 * 1024));
        try std.testing.expectEqualSlices(u8, receipt_before, try support.read(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/native-transaction-provenance-v2.json"), 16 * 1024 * 1024));
        try std.testing.expectEqualSlices(u8, completion_before, try support.read(fixture, completion_path, 64 * 1024));
    }
    const receipt_path = try rootPath(fixture, scenario.native_root, "var/lib/debz/native-transaction-provenance-v2.json");
    const lock_path = try rootPath(fixture, scenario.native_root, "fixture/lock.json");
    for ([_][]const u8{ lock_path, receipt_path, status_path }, 0..) |damaged_path, index| {
        const original = try support.read(fixture, damaged_path, 16 * 1024 * 1024);
        try fixture.write(damaged_path, "{}\n", 0o644);
        var rejected = (try invoke(fixture, runner, scenario.native_root, try std.fmt.allocPrint(fixture.allocator, "{s}/damaged-verification-{d}", .{ name, index }), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .defer_clear = !success,
            .verification = .{
                .lock_sha256 = lock_digest,
                .state = if (success) "released" else "pending",
                .outcome = if (failed) "failed" else "succeeded",
                .expected_error = "OperationalVerificationFailure",
            },
        })) orelse return error.MissingProjectedReport;
        defer rejected.deinit();
        try std.testing.expect(!(try field(rejected.value, "verified")).bool);
        try std.testing.expectEqualSlices(u8, owner_before, try support.read(fixture, owner, 64 * 1024));
        try std.testing.expectEqualSlices(u8, completion_before, try support.read(fixture, completion_path, 64 * 1024));
        try fixture.write(damaged_path, original, 0o644);
        try std.testing.expectEqualSlices(u8, status_before, try support.read(fixture, status_path, 1024 * 1024));
        try std.testing.expectEqualSlices(u8, receipt_before, try support.read(fixture, receipt_path, 16 * 1024 * 1024));
    }
    if (success) {
        var transferred = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "review-transfer"), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .verification = .{
                .lock_sha256 = lock_digest,
                .state = "released",
                .review = "transfer",
                .expected_error = "OperationalVerificationFailure",
            },
        })) orelse return error.MissingProjectedReport;
        defer transferred.deinit();
        try std.testing.expect(!(try field(transferred.value, "verified")).bool);
        const transferred_owner = try rootPath(fixture, scenario.native_root, "fixture/owner.json.review-owner");
        var owner_v2 = try parse(fixture, transferred_owner, 64 * 1024);
        defer owner_v2.deinit();
        try std.testing.expectEqual(@as(i64, 2), (try field(owner_v2.value, "version")).integer);
        try fixture.write(owner_file, try support.read(fixture, transferred_owner, 64 * 1024), 0o644);
    }
    const review_baseline = try evidenceInventory(fixture, scenario.native_root, false);
    var published_bytes: ?[]const u8 = null;
    for ([_]struct { review: []const u8, refused: bool }{
        .{ .review = "publish", .refused = true },
        .{ .review = "authorized", .refused = false },
        .{ .review = "foreign", .refused = true },
        .{ .review = "clear", .refused = false },
        .{ .review = "publish_stale", .refused = true },
        .{ .review = "authorized", .refused = true },
        .{ .review = "clear", .refused = false },
    }, 0..) |review_case, index| {
        var reviewed = (try invoke(fixture, runner, scenario.native_root, try std.fmt.allocPrint(fixture.allocator, "{s}/review-{d}-{s}", .{ name, index, review_case.review }), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .defer_clear = !success,
            .verification = .{
                .lock_sha256 = lock_digest,
                .state = if (success) "released" else "pending",
                .outcome = if (failed) "failed" else "succeeded",
                .review = review_case.review,
                .expected_error = if (review_case.refused) "OperationalVerificationFailure" else null,
            },
        })) orelse return error.MissingProjectedReport;
        defer reviewed.deinit();
        try std.testing.expectEqual(!review_case.refused, (try field(reviewed.value, "verified")).bool);
        const review_bytes = try evidenceInventory(fixture, scenario.native_root, false);
        switch (index) {
            0, 4 => published_bytes = review_bytes,
            1, 2, 5 => if (!std.mem.eql(u8, review_bytes, published_bytes orelse return error.MissingPublishedReview)) return error.ProjectedReviewEvidenceChanged,
            3, 6 => if (!std.mem.eql(u8, review_bytes, review_baseline)) return error.ProjectedReviewNotCleared,
            else => unreachable,
        }
        try std.testing.expectEqualSlices(u8, status_before, try support.read(fixture, status_path, 1024 * 1024));
        try std.testing.expectEqualSlices(u8, receipt_before, try support.read(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/native-transaction-provenance-v2.json"), 16 * 1024 * 1024));
        if (!success and index == 0) {
            const marker_before = try support.read(fixture, owner, 64 * 1024);
            var refused_ack = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "unconfirmed-acknowledgment"), .{
                .mode = "recover",
                .selected = selected,
                .owner = true,
                .defer_clear = true,
                .acknowledgment = "recovery",
            })) orelse return error.MissingProjectedReport;
            defer refused_ack.deinit();
            try std.testing.expectEqual(@as(i64, 8), (try field(refused_ack.value, "exit_status")).integer);
            try std.testing.expectEqualSlices(u8, marker_before, try support.read(fixture, owner, 64 * 1024));
        }
    }
    const owner_after_review = try support.read(fixture, owner, 64 * 1024);
    for ([_]u64{ 2, 3 }) |generation| {
        var published = (try invoke(fixture, runner, scenario.native_root, try std.fmt.allocPrint(fixture.allocator, "{s}/generation-{d}-publish", .{ name, generation }), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .defer_clear = !success,
            .verification = .{
                .lock_sha256 = lock_digest,
                .state = if (success) "released" else "pending",
                .outcome = if (failed) "failed" else "succeeded",
                .review = "publish",
                .review_generation = generation,
                .expected_error = "OperationalVerificationFailure",
            },
        })) orelse return error.MissingProjectedReport;
        defer published.deinit();
        try std.testing.expect(!(try field(published.value, "verified")).bool);
        try std.testing.expect((try invoke(fixture, runner, scenario.native_root, try std.fmt.allocPrint(fixture.allocator, "{s}/generation-{d}-ack-crash", .{ name, generation }), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .review_evidence = true,
            .defer_clear = !success,
            .acknowledgment = if (success) "ownership" else "recovery",
            .crash = true,
            .crash_at = if (success) "before_ownership_marker_clear" else "before_deferred_acknowledged",
        })) == null);
        try std.testing.expectEqualSlices(u8, owner_after_review, try support.read(fixture, owner, 64 * 1024));
        var verified = (try invoke(fixture, runner, scenario.native_root, try std.fmt.allocPrint(fixture.allocator, "{s}/generation-{d}-verify-after-crash", .{ name, generation }), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .defer_clear = !success,
            .verification = .{ .lock_sha256 = lock_digest, .state = if (success) "released" else "pending", .outcome = if (failed) "failed" else "succeeded" },
        })) orelse return error.MissingProjectedReport;
        defer verified.deinit();
        try std.testing.expect((try field(verified.value, "verified")).bool);
        try std.testing.expectEqualSlices(u8, status_before, try support.read(fixture, status_path, 1024 * 1024));
    }
    var fourth = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "generation-4-publish"), .{
        .mode = "recover",
        .selected = selected,
        .owner = true,
        .defer_clear = !success,
        .verification = .{
            .lock_sha256 = lock_digest,
            .state = if (success) "released" else "pending",
            .outcome = if (failed) "failed" else "succeeded",
            .review = "publish",
            .review_generation = 4,
            .expected_error = "OperationalVerificationFailure",
        },
    })) orelse return error.MissingProjectedReport;
    defer fourth.deinit();
    try std.testing.expect(!(try field(fourth.value, "verified")).bool);
    var review_for_ack = true;
    if (!success) {
        try std.testing.expect((try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "generation-4-ack-crash"), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .review_evidence = true,
            .defer_clear = true,
            .acknowledgment = "recovery",
            .crash = true,
            .crash_at = "after_deferred_acknowledged",
        })) == null);
        const acknowledged_bytes = try support.read(fixture, owner, 64 * 1024);
        var acknowledged = try parse(fixture, owner, 64 * 1024);
        defer acknowledged.deinit();
        try same(try text(acknowledged.value, "state"), "acknowledged");
        try std.testing.expectEqualSlices(u8, owner_after_review, try support.read(fixture, owner_file, 64 * 1024));
        var stale = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "generation-4-stale-verification"), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .defer_clear = true,
            .verification = .{
                .lock_sha256 = lock_digest,
                .state = "pending",
                .outcome = if (failed) "failed" else "succeeded",
                .expected_error = "OperationalVerificationFailure",
            },
        })) orelse return error.MissingProjectedReport;
        defer stale.deinit();
        try std.testing.expect(!(try field(stale.value, "verified")).bool);
        try std.testing.expect((try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "generation-5-record-clear-crash"), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .review_evidence = true,
            .defer_clear = true,
            .acknowledgment = "recovery",
            .crash = true,
            .crash_at = "after_deferred_record_cleared",
            .prepare_acknowledged_review = .{ .lock_sha256 = lock_digest, .generation = 5 },
        })) == null);
        try support.absent(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/root-operation-v1.json"));
        try std.testing.expectEqualSlices(u8, acknowledged_bytes, try support.read(fixture, owner, 64 * 1024));
        try std.testing.expectEqualSlices(u8, owner_after_review, try support.read(fixture, owner_file, 64 * 1024));
        var prepared = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "generation-6-acknowledged-review"), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .review_evidence = true,
            .defer_clear = true,
            .acknowledgment = "recovery",
            .prepare_acknowledged_review = .{ .lock_sha256 = lock_digest, .generation = 6 },
        })) orelse return error.MissingProjectedReport;
        defer prepared.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(prepared.value, "exit_status")).integer);
        review_for_ack = false;
    }
    for ([_][]const u8{ "acknowledge", "acknowledge-again" }) |phase| {
        var ack = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, phase), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .review_evidence = review_for_ack,
            .defer_clear = !success,
            .acknowledgment = if (success) "ownership" else "recovery",
        })) orelse return error.MissingProjectedReport;
        defer ack.deinit();
        try std.testing.expectEqual(@as(i64, 0), (try field(ack.value, "exit_status")).integer);
    }
    try support.absent(fixture, owner);
    try std.testing.expectEqualSlices(u8, status_before, try support.read(fixture, status_path, 1024 * 1024));
    try std.testing.expectEqualSlices(u8, receipt_before, try support.read(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/native-transaction-provenance-v2.json"), 16 * 1024 * 1024));
    var receipt_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&receipt_digest, try text(receipt.value, "digest_sha256"));
    try fixture.write(receipt_path, "{}\n", 0o644);
    const completion_bytes = try support.read(fixture, completion_path, 64 * 1024);
    if (!success) try fixture.dir.deleteFile(fixture.io, completion_path);
    const intent_path = try rootPath(fixture, scenario.native_root, "var/lib/debz/native-execution-intent-v1.json");
    for ([_][]const u8{ "before", "after" }, 0..) |phase, index| {
        try std.testing.expect((try invoke(fixture, runner, scenario.native_root, try std.fmt.allocPrint(fixture.allocator, "{s}/generation-7-{s}-marker-clear", .{ name, phase }), .{
            .mode = "recover",
            .selected = selected,
            .owner = true,
            .review_evidence = true,
            .defer_clear = !success,
            .acknowledgment = if (success) "ownership" else "recovery",
            .crash = true,
            .crash_at = if (success)
                (if (index == 0) "before_ownership_marker_clear" else "after_ownership_marker_clear")
            else
                (if (index == 0) "before_deferred_marker_cleared" else "after_deferred_marker_cleared"),
            .prepare_cleared_review = if (index == 0) .{ .lock_sha256 = lock_digest, .receipt_sha256 = receipt_digest, .generation = 7 } else null,
        })) == null);
        try support.absent(fixture, try rootPath(fixture, scenario.native_root, "var/lib/debz/root-operation-v1.json"));
        if (index == 0) {
            const reviewed_bytes = try support.read(fixture, owner, 64 * 1024);
            if (success) {
                try fixture.dir.deleteFile(fixture.io, completion_path);
            } else {
                try fixture.write(completion_path, completion_bytes, 0o644);
            }
            const damaged_state = try evidenceInventory(fixture, scenario.native_root, true);
            var damaged_completion = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "generation-7-damaged-completion"), .{
                .mode = "recover",
                .selected = selected,
                .owner = true,
                .review_evidence = true,
                .defer_clear = !success,
                .acknowledgment = if (success) "ownership" else "recovery",
            })) orelse return error.MissingProjectedReport;
            defer damaged_completion.deinit();
            try std.testing.expectEqual(@as(i64, 8), (try field(damaged_completion.value, "exit_status")).integer);
            try std.testing.expectEqualSlices(u8, reviewed_bytes, try support.read(fixture, owner, 64 * 1024));
            try std.testing.expectEqualSlices(u8, damaged_state, try evidenceInventory(fixture, scenario.native_root, true));
            if (success) {
                try fixture.write(completion_path, completion_bytes, 0o644);
            } else {
                try fixture.dir.deleteFile(fixture.io, completion_path);
            }
            try fixture.write(intent_path, "{}\n", 0o644);
            const orphan_state = try evidenceInventory(fixture, scenario.native_root, true);
            var orphan = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "generation-7-orphan-intent"), .{
                .mode = "recover",
                .selected = selected,
                .owner = true,
                .review_evidence = true,
                .defer_clear = !success,
                .acknowledgment = if (success) "ownership" else "recovery",
            })) orelse return error.MissingProjectedReport;
            defer orphan.deinit();
            try std.testing.expectEqual(@as(i64, 8), (try field(orphan.value, "exit_status")).integer);
            try std.testing.expectEqualSlices(u8, reviewed_bytes, try support.read(fixture, owner, 64 * 1024));
            try std.testing.expectEqualSlices(u8, "{}\n", try support.read(fixture, intent_path, 64 * 1024));
            try std.testing.expectEqualSlices(u8, orphan_state, try evidenceInventory(fixture, scenario.native_root, true));
            try fixture.dir.deleteFile(fixture.io, intent_path);
        }
    }
    try support.absent(fixture, owner);
    var stale_final = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "generation-7-stale-final"), .{
        .mode = "recover",
        .selected = selected,
        .owner = true,
        .review_evidence = true,
        .defer_clear = !success,
        .acknowledgment = if (success) "ownership" else "recovery",
    })) orelse return error.MissingProjectedReport;
    defer stale_final.deinit();
    try std.testing.expectEqual(@as(i64, 8), (try field(stale_final.value, "exit_status")).integer);
    var cleared = (try invoke(fixture, runner, scenario.native_root, try support.path(fixture.allocator, name, "generation-8-cleared-review"), .{
        .mode = "recover",
        .selected = selected,
        .owner = true,
        .review_evidence = true,
        .defer_clear = !success,
        .acknowledgment = if (success) "ownership" else "recovery",
        .prepare_cleared_review = .{ .lock_sha256 = lock_digest, .receipt_sha256 = receipt_digest, .generation = 8 },
    })) orelse return error.MissingProjectedReport;
    defer cleared.deinit();
    try std.testing.expectEqual(@as(i64, 0), (try field(cleared.value, "exit_status")).integer);
    try support.absent(fixture, owner);
    try std.testing.expectEqualSlices(u8, "{}\n", try support.read(fixture, receipt_path, 16 * 1024 * 1024));
    try std.testing.expectEqualSlices(u8, owner_after_review, try support.read(fixture, owner_file, 64 * 1024));
    try std.testing.expectEqualSlices(u8, status_before, try support.read(fixture, status_path, 1024 * 1024));
    try support.absent(fixture, try rootPath(fixture, scenario.native_root, "fixture/unused-cache"));
    try support.absent(fixture, try rootPath(fixture, scenario.native_root, "fixture/unused-state"));
    try fixture.write(receipt_path, receipt_before, 0o644);
    if (!success) try fixture.write(completion_path, completion_bytes, 0o644);
    try compare(fixture, &scenario);
    std.debug.print("projected workflow {s}: isolated real signed transaction, owner proof, acknowledgment and pinned-dpkg parity passed\n", .{outcome});
}
