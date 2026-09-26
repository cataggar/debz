const std = @import("std");
const linux = std.os.linux;
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const options = @import("native_test_options");
const debz = @import("debz");
const api = debz.repository_api;
const oracle = @import("native_recovery_oracle.zig");
const parity_evidence = @import("native_recovery_parity_evidence.zig");

const projection_marker = "debz native projection fixture v1\n";
const namespace = "var/lib/debz/";

const Mode = enum { projection, execution, cli };
const cli_cases = [_][]const u8{
    "success",       "no_refresh",      "unchanged", "unchanged_no_refresh",
    "known_failure", "refresh_failure", "signal",    "lock_wait",
    "lock_signal",   "unsafe_runtime",  "deadline",  "network",
};

fn selectMode(workflow: bool, projection: bool, execution: bool, cli: bool) !?Mode {
    if (@as(u8, @intFromBool(workflow)) + @as(u8, @intFromBool(projection)) +
        @as(u8, @intFromBool(execution)) +
        @as(u8, @intFromBool(cli)) > 1) return error.ProjectionFixturesMutuallyExclusive;
    if (projection) return .projection;
    if (execution) return .execution;
    if (cli) return .cli;
    return null;
}

fn privateRoot(allocator: std.mem.Allocator, io: std.Io, root: []const u8, pid: i32, uid: u32) !void {
    const prefix = try std.fmt.allocPrint(allocator, "{s}/.tmp/native-zig-", .{options.repository});
    defer allocator.free(prefix);
    if (!std.mem.startsWith(u8, root, prefix) or pid != 1 or uid != 0)
        return error.DisposableRootAndPrivatePidNamespaceRequired;
    const remainder = root[prefix.len..];
    const slash = std.mem.indexOfScalar(u8, remainder, '/') orelse
        return error.DisposableRootAndPrivatePidNamespaceRequired;
    if (slash == 0 or !std.mem.startsWith(u8, remainder[slash..], "/repository-") or
        !std.mem.endsWith(u8, remainder, "/root") or
        std.mem.indexOfScalar(u8, remainder[slash + 1 .. remainder.len - "/root".len], '/') != null)
        return error.DisposableRootAndPrivatePidNamespaceRequired;
    var dir = foundation.guardedRoot(io, root) catch
        return error.DisposableRootAndPrivatePidNamespaceRequired;
    defer dir.close(io);
    const bytes = dir.readFileAlloc(io, ".debz-native-projection", allocator, .limited(128)) catch
        return error.DisposableRootAndPrivatePidNamespaceRequired;
    defer allocator.free(bytes);
    if (!std.mem.eql(u8, bytes, projection_marker))
        return error.DisposableRootAndPrivatePidNamespaceRequired;
}

fn projected(
    fixture: *foundation.Fixture,
    self: []const u8,
    root: []const u8,
    mode: Mode,
    name: []const u8,
    expected_success: bool,
    expected_diagnostic: ?[]const u8,
) !void {
    if (!std.fs.path.isAbsolute(self)) return error.InvalidRunnerPath;
    if (!std.mem.startsWith(u8, root, fixture.path) or root.len <= fixture.path.len or
        root[fixture.path.len] != '/') return error.DisposableRootAndPrivatePidNamespaceRequired;
    var guarded = try foundation.guardedRoot(fixture.io, root);
    guarded.close(fixture.io);
    const log = try std.fmt.allocPrint(fixture.allocator, "{s}.log", .{name});
    defer fixture.allocator.free(log);
    const limit_seconds: i64 = if (std.mem.eql(u8, name, "repository-execution-success")) 240 else 120;
    const limit = try std.fmt.allocPrint(fixture.allocator, "{d}s", .{limit_seconds});
    defer fixture.allocator.free(limit);
    const result = std.process.run(fixture.allocator, fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", limit, "/usr/bin/unshare", "--mount", "--pid", "--fork", "--", self, "--inside", @tagName(mode), root },
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(limit_seconds + 5), .clock = .awake } },
    }) catch |err| {
        std.debug.print("{s}: transport {s}, fixture {s}\n", .{ name, @errorName(err), fixture.path });
        return err;
    };
    defer fixture.allocator.free(result.stdout);
    defer fixture.allocator.free(result.stderr);
    const combined = try std.mem.concat(fixture.allocator, u8, &.{ result.stdout, result.stderr });
    defer fixture.allocator.free(combined);
    try fixture.write(log, combined, 0o644);
    const succeeded = result.term == .exited and result.term.exited == 0;
    if (succeeded != expected_success or result.term == .exited and result.term.exited == 124) {
        std.debug.print("{s}: child {any}, expected success={}; {s}/{s}:\n{s}\n", .{
            name,                                                   result.term, expected_success, fixture.path, log,
            combined[combined.len - @min(combined.len, 12_000) ..],
        });
        return error.UnexpectedRepositoryProcessExit;
    }
    if (expected_diagnostic) |diagnostic|
        if (std.mem.indexOf(u8, combined, diagnostic) == null) {
            std.debug.print("{s}: missing diagnostic {s}; {s}\n", .{ name, diagnostic, combined });
            return error.MissingRepositoryDiagnostic;
        };
}

fn mountAt(allocator: std.mem.Allocator, io: std.Io, args: []const []const u8) !void {
    const result = try std.process.run(allocator, io, .{
        .argv = args,
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("private mount {any}: {s}\n", .{ result.term, result.stderr });
        return error.PrivateMountFailed;
    }
}

fn inside(init: std.process.Init, allocator: std.mem.Allocator, root: []const u8, mode: Mode) !void {
    try privateRoot(allocator, init.io, root, linux.getpid(), linux.geteuid());
    try mountAt(allocator, init.io, &.{ "/usr/bin/mount", "--bind", root, root });
    const proc = try std.fmt.allocPrint(allocator, "{s}/proc", .{root});
    try mountAt(allocator, init.io, &.{ "/usr/bin/mount", "-t", "proc", "proc", proc });
    const zroot = try allocator.dupeZ(u8, root);
    if (linux.errno(linux.chdir(zroot)) != .SUCCESS or
        linux.errno(linux.chroot(".")) != .SUCCESS or
        linux.errno(linux.chdir("/")) != .SUCCESS) return error.PrivateChrootFailed;
    if (mode == .cli) return cliInside(init.io, allocator);
    const environment: []const []const u8 = switch (mode) {
        .projection => &.{ "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TMPDIR=/tmp", "XDG_CACHE_HOME=/tmp/.cache", "DEBZ_NATIVE_REPOSITORY_PROJECTION_FIXTURE=1" },
        .execution => &.{ "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "TMPDIR=/tmp", "XDG_CACHE_HOME=/tmp/.cache", "DEBZ_NATIVE_REPOSITORY_EXECUTION_FIXTURE=1" },
        .cli => unreachable,
    };
    const argv = [_:null]?[*:0]const u8{"/fixture/native-test"};
    var envp = try allocator.allocSentinel(?[*:0]const u8, environment.len, null);
    for (environment, 0..) |entry, index| envp[index] = (try allocator.dupeZ(u8, entry)).ptr;
    if (linux.errno(linux.execve("/fixture/native-test", &argv, envp.ptr)) != .SUCCESS)
        return error.PrivateExecFailed;
    unreachable;
}

fn cliWatchdog(arguments: []const []const u8, step: i64, case: []const u8) !u64 {
    const calls: i64 = if (std.mem.eql(u8, case, "lock_wait") or
        std.mem.eql(u8, case, "lock_signal") or
        std.mem.eql(u8, case, "unsafe_runtime") or
        std.mem.eql(u8, case, "deadline")) 1 else 3;
    if (step < 0 or step >= calls) return error.InvalidRepositoryInvocation;
    var deadline: ?i64 = null;
    for (arguments, 0..) |argument, index| {
        if (!std.mem.eql(u8, argument, "--deadline-ms")) continue;
        if (deadline != null or index + 1 == arguments.len) return error.InvalidRepositoryInvocation;
        deadline = std.fmt.parseInt(i64, arguments[index + 1], 10) catch
            return error.InvalidRepositoryInvocation;
    }
    const milliseconds = deadline orelse return error.InvalidRepositoryInvocation;
    if (milliseconds < 0) return error.InvalidRepositoryInvocation;
    const watchdog = @divTrunc(milliseconds + 999, 1000) + 5;
    if (watchdog <= 0 or watchdog >= 120) return error.UnboundedRepositoryWatchdog;
    return @intCast(watchdog);
}

fn childExited(pid: i32) bool {
    while (true) {
        var info: linux.siginfo_t = std.mem.zeroes(linux.siginfo_t);
        const status = linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOHANG | linux.W.NOWAIT, null);
        switch (linux.errno(status)) {
            .SUCCESS => return info.fields.common.first.piduid.pid == pid,
            .INTR => continue,
            else => return true,
        }
    }
}

fn waitingOnLock(io: std.Io, allocator: std.mem.Allocator, pid: i32) !bool {
    const path = try std.fmt.allocPrint(allocator, "/proc/{d}/fd", .{pid});
    var descriptors = std.Io.Dir.openDirAbsolute(io, path, .{ .iterate = true }) catch |err|
        return if (err == error.FileNotFound) false else err;
    defer descriptors.close(io);
    var iterator = descriptors.iterate();
    while (try iterator.next(io)) |entry| {
        var buffer: [4096]u8 = undefined;
        const count = descriptors.readLink(io, entry.name, &buffer) catch |err| {
            if (err == error.FileNotFound) continue;
            return err;
        };
        if (std.mem.eql(u8, buffer[0..count], "/run/debz/live-root.lock")) return true;
    }
    return false;
}

fn cliInside(io: std.Io, allocator: std.mem.Allocator) !void {
    const dir = std.Io.Dir.cwd();
    const bytes = try dir.readFileAlloc(io, "fixture/cli-arguments.json", allocator, .limited(64 * 1024));
    const parsed = try std.json.parseFromSlice([]const []const u8, allocator, bytes, .{ .allocate = .alloc_always });
    defer parsed.deinit();
    const case = try dir.readFileAlloc(io, "fixture/cli-case", allocator, .limited(64));
    const step_bytes = try dir.readFileAlloc(io, "fixture/cli-step", allocator, .limited(16));
    const step = std.fmt.parseInt(i64, step_bytes, 10) catch return error.InvalidRepositoryInvocation;
    const watchdog = try cliWatchdog(parsed.value, step, case);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(allocator, "/fixture/debz");
    try argv.appendSlice(allocator, parsed.value);
    var lock: ?std.Io.File = null;
    if (std.mem.eql(u8, case, "lock_wait") or std.mem.eql(u8, case, "lock_signal")) {
        try dir.createDirPath(io, "run/debz");
        try dir.setFilePermissions(io, "run/debz", .fromMode(0o700), .{});
        lock = try dir.createFile(io, "run/debz/live-root.lock", .{ .permissions = .fromMode(0o600) });
        if (linux.errno(linux.flock(lock.?.handle, 2)) != .SUCCESS) return error.RepositoryLockSetupFailed;
    } else if (std.mem.eql(u8, case, "unsafe_runtime")) {
        try dir.createDirPath(io, "run/debz");
        try dir.setFilePermissions(io, "run/debz", .fromMode(0o777), .{});
    }
    defer if (lock) |held| held.close(io);
    const stdout_path = try std.fmt.allocPrint(allocator, "fixture/cli-{d}.stdout", .{step});
    const stderr_path = try std.fmt.allocPrint(allocator, "fixture/cli-{d}.stderr", .{step});
    var stdout_file = try dir.createFile(io, stdout_path, .{});
    defer stdout_file.close(io);
    var stderr_file = try dir.createFile(io, stderr_path, .{});
    defer stderr_file.close(io);
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    try environment.put("LANG", "C");
    try environment.put("TMPDIR", "/tmp");
    try environment.put("XDG_CACHE_HOME", "/tmp/.cache");
    const started = std.Io.Clock.awake.now(io);
    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = &environment,
        .stdin = .ignore,
        .stdout = .{ .file = stdout_file },
        .stderr = .{ .file = stderr_file },
    });
    defer child.kill(io);
    const pid = child.id orelse return error.RepositoryCliDidNotSpawn;
    const deadline_ms: i64 = @intCast(watchdog * 1000);
    var adjusted = false;
    var sent_signal = false;
    while (!childExited(pid)) {
        const elapsed = started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds();
        if (elapsed >= deadline_ms) {
            std.debug.print("repository CLI {s} step {d} exceeded {d}s; root-state retained under fixture\n", .{ case, step, watchdog });
            return error.RepositoryCliWatchdogExpired;
        }
        if (std.mem.eql(u8, case, "lock_signal") and !sent_signal and
            try waitingOnLock(io, allocator, pid))
        {
            if (linux.errno(linux.kill(pid, .TERM)) != .SUCCESS) return error.RepositoryCliSignalFailed;
            sent_signal = true;
        }
        if (step == 0 and (std.mem.eql(u8, case, "refresh_failure") or
            std.mem.eql(u8, case, "signal")) and !adjusted)
        {
            if (dir.statFile(io, "fixture/postinst-entered", .{})) |_| {
                if (std.mem.eql(u8, case, "signal")) {
                    if (linux.errno(linux.kill(pid, .TERM)) != .SUCCESS) return error.RepositoryCliSignalFailed;
                    sent_signal = true;
                } else {
                    try dir.rename("fixture/repository/dists/debian-stable/InRelease", dir, "fixture/repository/dists/debian-stable/InRelease.saved", io);
                    try dir.writeFile(io, .{ .sub_path = "fixture/finish-script", .data = "" });
                }
                adjusted = true;
            } else |err| if (err != error.FileNotFound) return err;
        }
        if (std.mem.eql(u8, case, "lock_signal") and !sent_signal and elapsed >= 10_000)
            return error.RepositoryCliDidNotWaitOnLock;
        if (std.mem.eql(u8, case, "signal") and step == 0 and !adjusted and elapsed >= 10_000)
            return error.RepositoryCliDidNotReachScript;
        try io.sleep(.fromMilliseconds(10), .awake);
    }
    const term = try child.wait(io);
    if (term != .exited) return error.UnexpectedRepositoryCliTermination;
    if (std.mem.eql(u8, case, "lock_signal") and !sent_signal)
        return error.RepositoryCliDidNotWaitOnLock;
    if (step == 0 and (std.mem.eql(u8, case, "refresh_failure") or
        std.mem.eql(u8, case, "signal")) and !adjusted)
        return error.RepositoryCliDidNotReachScript;
    const stdout = try dir.readFileAlloc(io, stdout_path, allocator, .limited(1024 * 1024));
    const stderr = try dir.readFileAlloc(io, stderr_path, allocator, .limited(1024 * 1024));
    const output = try std.fmt.allocPrint(allocator, "fixture/cli-{d}.json", .{step});
    try dir.writeFile(io, .{ .sub_path = output, .data = stdout });
    const exit_path = try std.fmt.allocPrint(allocator, "fixture/cli-{d}.exit", .{step});
    const exit_bytes = try std.fmt.allocPrint(allocator, "{d}", .{term.exited});
    try dir.writeFile(io, .{ .sub_path = exit_path, .data = exit_bytes });
    const elapsed_path = try std.fmt.allocPrint(allocator, "fixture/cli-{d}.elapsed", .{step});
    const elapsed = try std.fmt.allocPrint(allocator, "{d}", .{started.durationTo(std.Io.Clock.awake.now(io)).toMilliseconds()});
    try dir.writeFile(io, .{ .sub_path = elapsed_path, .data = elapsed });
    if (stderr.len != 0) {
        std.debug.print("repository CLI stderr: {s}\n", .{stderr});
        return error.UnexpectedRepositoryCliStderr;
    }
    var response = try std.json.parseFromSlice(std.json.Value, allocator, stdout, .{});
    defer response.deinit();
    if (response.value != .object) return error.InvalidRepositoryCliResponse;
    const status = response.value.object.get("exit_status") orelse return error.InvalidRepositoryCliResponse;
    if (status != .integer or status.integer != term.exited) return error.InvalidRepositoryCliResponse;
    if (step == 0 and !std.mem.eql(u8, case, "lock_wait") and
        !std.mem.eql(u8, case, "lock_signal") and
        !std.mem.eql(u8, case, "unsafe_runtime") and
        !std.mem.eql(u8, case, "deadline"))
    {
        try dir.deleteFile(io, "fixture/descriptor.deb");
        if (std.mem.eql(u8, case, "refresh_failure"))
            try dir.rename("fixture/repository/dists/debian-stable/InRelease.saved", dir, "fixture/repository/dists/debian-stable/InRelease", io);
        if (std.mem.eql(u8, case, "signal"))
            try dir.writeFile(io, .{ .sub_path = "fixture/finish-script", .data = "" });
    }
}

fn makeRoot(fixture: *foundation.Fixture, name: []const u8, arch: []const u8) ![]u8 {
    const root_name = try support.path(fixture.allocator, name, "root");
    defer fixture.allocator.free(root_name);
    const root = try fixture.makeRoot(root_name, arch);
    try fixture.write(try support.path(fixture.allocator, root_name, ".debz-native-projection"), projection_marker, 0o600);
    for ([_][]const u8{ "proc", "run", "tmp", "dev" }) |entry| {
        const path = try support.path(fixture.allocator, root_name, entry);
        defer fixture.allocator.free(path);
        try fixture.directory(path);
    }
    if (linux.geteuid() == 0) {
        const null_path = try support.path(fixture.allocator, root_name, "dev/null");
        defer fixture.allocator.free(null_path);
        const absolute = try fixture.absolute(null_path);
        defer fixture.allocator.free(absolute);
        const log = try support.path(fixture.allocator, name, "mknod.log");
        defer fixture.allocator.free(log);
        try fixture.run(&.{ "/usr/bin/mknod", "-m", "666", absolute, "c", "1", "3" }, log, 10);
    }
    return root;
}

fn copyRunner(fixture: *foundation.Fixture, root: []const u8, executable: []const u8, destination: []const u8) !void {
    try support.copyProgram(fixture, root[fixture.path.len + 1 ..], executable, destination);
}

fn assertText(fixture: *foundation.Fixture, name: []const u8, expected: []const u8) !void {
    const bytes = try support.read(fixture, name, 1024 * 1024);
    defer fixture.allocator.free(bytes);
    if (!std.mem.eql(u8, bytes, expected)) {
        std.debug.print("{s}: expected {s}, got {s}\n", .{ name, expected, bytes });
        return error.UnexpectedRepositoryEvidence;
    }
}

fn assertEmpty(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !void {
    const relative = try support.path(fixture.allocator, root[fixture.path.len + 1 ..], name);
    defer fixture.allocator.free(relative);
    var directory = fixture.dir.openDir(fixture.io, relative, .{ .iterate = true, .follow_symlinks = false }) catch |err| {
        if (err == error.FileNotFound) return;
        return err;
    };
    defer directory.close(fixture.io);
    var entries = directory.iterate();
    if (try entries.next(fixture.io) != null) return error.RepositoryProjectionLeaked;
}

fn resultAt(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !api.OwnedResult {
    const relative = try support.path(fixture.allocator, root[fixture.path.len + 1 ..], name);
    defer fixture.allocator.free(relative);
    const bytes = try support.read(fixture, relative, api.maximum_document_bytes);
    defer fixture.allocator.free(bytes);
    var result = try api.decode(fixture.allocator, bytes, api.maximum_document_bytes);
    errdefer result.deinit();
    const canonical = try result.result.canonicalJson(fixture.allocator);
    defer fixture.allocator.free(canonical);
    if (!std.mem.eql(u8, bytes, canonical)) return error.NoncanonicalRepositoryResult;
    return result;
}

fn absent(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !void {
    const relative = try support.path(fixture.allocator, root[fixture.path.len + 1 ..], name);
    defer fixture.allocator.free(relative);
    try support.absent(fixture, relative);
}

const HelperIdentity = struct { inode: u64, sha256: [32]u8 };

fn pinnedHelper(fixture: *foundation.Fixture, root: []const u8) !HelperIdentity {
    const path = try support.path(fixture.allocator, root[fixture.path.len + 1 ..], "usr/bin/dpkg-trigger");
    const metadata = try fixture.dir.statFile(fixture.io, path, .{ .follow_symlinks = false });
    if (metadata.kind != .file) return error.RepositoryHelperChanged;
    const bytes = try support.read(fixture, path, 8 * 1024 * 1024);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .inode = metadata.inode, .sha256 = digest };
}

fn checkHelper(fixture: *foundation.Fixture, root: []const u8, prior: HelperIdentity) !void {
    const current = try pinnedHelper(fixture, root);
    if (current.inode != prior.inode or !std.mem.eql(u8, &current.sha256, &prior.sha256))
        return error.RepositoryHelperChanged;
}

fn checkpointAt(fixture: *foundation.Fixture, root: []const u8, logical: []const u8) !debz.repository_state.OwnedState {
    const bytes = try readLogical(fixture, root, logical, debz.repository_state.maximum_document_bytes);
    return debz.repository_state.decode(fixture.allocator, bytes, debz.repository_state.maximum_document_bytes);
}

fn managedFiles(fixture: *foundation.Fixture, root: []const u8, state: debz.repository_state.State, manifest: debz.target_apt_config.Manifest) !void {
    for (state.managed_files) |expected| {
        if (!std.mem.startsWith(u8, expected.logical_path, "/") or
            std.mem.indexOf(u8, expected.logical_path, "..") != null)
            return error.InvalidRepositoryManagedPath;
        const path = try support.path(fixture.allocator, root[fixture.path.len + 1 ..], expected.logical_path[1..]);
        const actual = try support.read(fixture, path, 1024 * 1024);
        var sha256: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(actual, &sha256, .{});
        if (actual.len != expected.size or !std.mem.eql(u8, &sha256, &expected.sha256))
            return error.RepositoryManagedFileChanged;
        var found: usize = 0;
        for (manifest.sources) |source| {
            if (!std.mem.eql(u8, source.logical_path, expected.logical_path)) continue;
            if (!std.mem.eql(u8, &source.sha256, &expected.sha256)) return error.RepositoryManifestChanged;
            found += 1;
        }
        for (manifest.keyrings) |keyring| {
            if (!std.mem.eql(u8, keyring.logical_path, expected.logical_path)) continue;
            if (!std.mem.eql(u8, &keyring.sha256, &expected.sha256)) return error.RepositoryManifestChanged;
            found += 1;
        }
        if (found != 1) return error.RepositoryManifestChanged;
    }
}

fn proofAt(fixture: *foundation.Fixture, root: []const u8, logical: []const u8) !debz.native_provenance.OwnedDocument {
    const bytes = try readLogical(fixture, root, logical, 16 * 1024 * 1024);
    return debz.native_provenance.decode(fixture.allocator, bytes);
}

fn unchangedBindings(
    fixture: *foundation.Fixture,
    root: []const u8,
    state: debz.repository_state.State,
    abandoned: debz.root_operation.Record,
    publisher: debz.root_operation.Record,
) !void {
    const logical = state.provenance_path orelse return error.MissingRepositoryUnchangedEvidence;
    if (!std.mem.endsWith(u8, logical, "/native-repository-unchanged-v1.json"))
        return error.InvalidRepositoryUnchangedEvidence;
    const bytes = try readLogical(fixture, root, logical, 64 * 1024);
    try unchangedEvidence(fixture, bytes);
    var parsed = try std.json.parseFromSlice(std.json.Value, fixture.allocator, bytes, .{});
    defer parsed.deinit();
    const value = parsed.value;
    const Field = struct {
        fn text(doc: std.json.Value, key: []const u8) ![]const u8 {
            if (doc != .object) return error.InvalidRepositoryUnchangedEvidence;
            const member = doc.object.get(key) orelse return error.InvalidRepositoryUnchangedEvidence;
            if (member != .string) return error.InvalidRepositoryUnchangedEvidence;
            return member.string;
        }
    };
    for ([_]struct { name: []const u8, digest: [32]u8 }{
        .{ .name = "caller_attempt_id", .digest = publisher.attempt_id },
        .{ .name = "caller_request_sha256", .digest = abandoned.request_sha256 },
        .{ .name = "caller_policy_sha256", .digest = abandoned.policy_sha256 },
        .{ .name = "plan_sha256", .digest = state.plan_sha256 orelse return error.MissingRepositoryPlan },
        .{ .name = "descriptor_sha256", .digest = (state.descriptor orelse return error.MissingRepositoryDescriptor).sha256 },
    }) |binding| {
        if (!std.mem.eql(u8, try Field.text(value, binding.name), &std.fmt.bytesToHex(binding.digest, .lower)))
            return error.InvalidRepositoryUnchangedBinding;
    }
    for ([_]struct { name: []const u8, expected: []const u8 }{
        .{ .name = "schema", .expected = "https://debz.dev/schema/native-repository-unchanged-v1" },
        .{ .name = "backend", .expected = "native" },
        .{ .name = "surface", .expected = "repository_bootstrap" },
        .{ .name = "operation", .expected = "add" },
        .{ .name = "target_architecture", .expected = abandoned.target_architecture },
    }) |field| {
        if (!std.mem.eql(u8, try Field.text(value, field.name), field.expected))
            return error.InvalidRepositoryUnchangedBinding;
    }
    if (std.mem.eql(u8, &abandoned.attempt_id, &publisher.attempt_id) or
        abandoned.outcome != .abandoned_before_mutation or abandoned.mutation_started or
        abandoned.program_sha256 != null or abandoned.authorization_sha256 != null or
        publisher.outcome != .pending or publisher.mutation_started or
        publisher.program_sha256 != null or publisher.authorization_sha256 != null)
        return error.InvalidRepositoryUnchangedCaller;
    if (!std.mem.eql(u8, try Field.text(value, "install_root"), debz.live_root.logical_root_path))
        return error.InvalidRepositoryUnchangedBinding;
    const inode = value.object.get("root_inode") orelse return error.InvalidRepositoryUnchangedBinding;
    const metadata = try std.Io.Dir.cwd().statFile(fixture.io, root, .{ .follow_symlinks = false });
    if (inode != .integer or inode.integer != metadata.inode) return error.InvalidRepositoryUnchangedBinding;
    const lock_path = state.exact_lock_path orelse return error.MissingRepositoryExactLock;
    var lock = try debz.exact_lock_v3.decode(fixture.allocator, try readLogical(fixture, root, lock_path, 1024 * 1024), 1024 * 1024);
    defer lock.deinit();
    if (!std.mem.eql(u8, try Field.text(value, "exact_lock_sha256"), &std.fmt.bytesToHex(lock.lock.digest_sha256, .lower)))
        return error.InvalidRepositoryUnchangedLock;
    const manifest_path = state.manifest_path orelse return error.MissingRepositoryManifest;
    var manifest = try debz.target_apt_config.decodeManifest(fixture.allocator, try readLogical(fixture, root, manifest_path, 1024 * 1024), 1024 * 1024);
    defer manifest.deinit();
    try managedFiles(fixture, root, state, manifest.manifest);
    const archive = try std.fmt.allocPrint(fixture.allocator, "{s}/native-unchanged-descriptor.deb", .{
        std.fs.path.dirname(state.provenance_path.?) orelse return error.MissingRepositoryUnchangedEvidence,
    });
    const path = try support.path(fixture.allocator, root[fixture.path.len + 1 ..], archive[1..]);
    const source = try support.read(fixture, path, 16 * 1024 * 1024);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(source, &digest, .{});
    if (!std.mem.eql(u8, &digest, &(state.descriptor orelse return error.MissingRepositoryDescriptor).sha256) or
        (try fixture.dir.statFile(fixture.io, path, .{ .follow_symlinks = false })).permissions.toMode() & 0o777 != 0o600)
        return error.RepositoryUnchangedDescriptorChanged;
}

fn terminalEvidence(fixture: *foundation.Fixture, root: []const u8, relative: []const u8, case: []const u8, resuming: bool, logical: []const u8, receipt: []const u8, helper: HelperIdentity) !void {
    const allocator = fixture.allocator;
    const failed = std.mem.eql(u8, case, "known_failure");
    const interrupted = std.mem.eql(u8, case, "interrupted");
    var proof = try debz.native_provenance.decode(allocator, receipt);
    defer proof.deinit();
    if (proof.document.outcome != (if (failed) debz.native_provenance.Outcome.failed else .succeeded) or
        !std.mem.eql(u8, proof.document.install_root, debz.live_root.logical_root_path))
        return error.InvalidRepositoryNativeProvenance;
    var guarded = try foundation.guardedRoot(fixture.io, root);
    defer guarded.close(fixture.io);
    const root_fs: debz.root_fs.Root = .init(fixture.io, guarded);
    try debz.native_provenance.verifyEvidence(allocator, root_fs, proof.document);
    const parent = std.fs.path.dirname(logical) orelse return error.InvalidRetainedRepositoryReceipt;
    const operation_id = std.fs.path.basename(parent);
    if (operation_id.len != 64 or
        !std.mem.startsWith(u8, parent, "/" ++ namespace ++ "repository/operations/"))
        return error.InvalidRetainedRepositoryReceipt;
    for (operation_id) |byte| if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f'))
        return error.InvalidRetainedRepositoryReceipt;
    const retained_path = try support.path(allocator, relative, logical[1..]);
    if ((try fixture.dir.statFile(fixture.io, retained_path, .{ .follow_symlinks = false })).permissions.toMode() & 0o777 != 0o600)
        return error.RepositoryReceiptPermissions;
    try absent(fixture, root, try std.fmt.allocPrint(allocator, "{s}/transaction-result-v2.json", .{parent[1..]}));
    const checkpoint_path = try std.fmt.allocPrint(allocator, "{s}/repo-add-state-v1.json", .{parent});
    var state = try checkpointAt(fixture, root, checkpoint_path);
    defer state.deinit();
    const original_bytes = try support.read(fixture, try support.path(allocator, relative, "fixture/repository-original-locked-state.json"), debz.repository_state.maximum_document_bytes);
    var original = try debz.repository_state.decode(allocator, original_bytes, debz.repository_state.maximum_document_bytes);
    defer original.deinit();
    if (original.state.phase != .locked or
        !std.mem.eql(u8, state.state.root, original.state.root) or
        !std.mem.eql(u8, state.state.architecture, original.state.architecture) or
        state.state.no_refresh != interrupted or
        state.state.no_refresh != original.state.no_refresh or
        state.state.phase != (if (failed) debz.repository_state.Phase.failed else .complete) or
        state.state.installed == failed or state.state.refreshed != std.mem.eql(u8, case, "success") or
        state.state.diagnostic_id != (if (failed) api.DiagnosticId.transaction_failed else null) or
        !std.mem.eql(u8, state.state.provenance_path orelse "", logical) or
        state.state.descriptor == null or original.state.descriptor == null or
        !std.meta.eql(state.state.plan_sha256, original.state.plan_sha256) or
        !std.mem.eql(u8, state.state.plan_path orelse "", original.state.plan_path orelse "") or
        !std.mem.eql(u8, state.state.exact_lock_path orelse "", original.state.exact_lock_path orelse "") or
        state.state.managed_files.len != original.state.managed_files.len)
        return error.RepositoryCheckpointChanged;
    const descriptor = state.state.descriptor.?;
    const previous_descriptor = original.state.descriptor.?;
    if (!std.mem.eql(u8, descriptor.package, previous_descriptor.package) or
        !std.mem.eql(u8, descriptor.version, previous_descriptor.version) or
        !std.mem.eql(u8, descriptor.architecture, previous_descriptor.architecture) or
        !std.mem.eql(u8, descriptor.effective_url, previous_descriptor.effective_url) or
        !std.mem.eql(u8, &descriptor.sha256, &previous_descriptor.sha256) or
        descriptor.size != previous_descriptor.size or descriptor.trust_mode != previous_descriptor.trust_mode)
        return error.RepositoryCheckpointChanged;
    for (state.state.managed_files, original.state.managed_files) |actual, previous| {
        if (!std.mem.eql(u8, actual.logical_path, previous.logical_path) or
            !std.mem.eql(u8, &actual.sha256, &previous.sha256) or actual.size != previous.size)
            return error.RepositoryCheckpointChanged;
    }
    const caller_bytes = try support.read(fixture, try support.path(allocator, relative, "fixture/repository-pending-caller.json"), 64 * 1024);
    var caller = try debz.root_operation.decode(allocator, caller_bytes, 64 * 1024);
    defer caller.deinit();
    const pending = caller.record;
    if (pending.outcome != .pending or !pending.operation.eql(.{ .repository_bootstrap = .add }) or
        !std.mem.eql(u8, &(state.state.plan_sha256 orelse return error.MissingRepositoryPlan),
            &(pending.plan_sha256 orelse return error.MissingRepositoryPlan)))
        return error.RepositoryCallerCheckpointMismatch;
    const checkpoint_file = try support.path(allocator, relative, checkpoint_path[1..]);
    if ((try fixture.dir.statFile(fixture.io, checkpoint_file, .{ .follow_symlinks = false })).permissions.toMode() & 0o777 != 0o600)
        return error.RepositoryCheckpointPermissions;
    var manifest_digest: ?[32]u8 = null;
    if (failed) {
        if (state.state.manifest_path != null) return error.UnexpectedRepositoryManifest;
        try absent(fixture, root, try std.fmt.allocPrint(allocator, "{s}/apt-config-snapshot-v1.json", .{parent[1..]}));
    } else {
        const manifest_path = state.state.manifest_path orelse return error.MissingRepositoryManifest;
        if (!std.mem.eql(u8, manifest_path, try std.fmt.allocPrint(allocator, "{s}/apt-config-snapshot-v1.json", .{parent})))
            return error.InvalidRepositoryManifestPath;
        const bytes = try readLogical(fixture, root, manifest_path, 1024 * 1024);
        var manifest = try debz.target_apt_config.decodeManifest(allocator, bytes, 1024 * 1024);
        defer manifest.deinit();
        manifest_digest = manifest.manifest.digest_sha256;
        try managedFiles(fixture, root, state.state, manifest.manifest);
        const relative_manifest = try support.path(allocator, relative, manifest_path[1..]);
        if ((try fixture.dir.statFile(fixture.io, relative_manifest, .{ .follow_symlinks = false })).permissions.toMode() & 0o777 != 0o600)
            return error.RepositoryManifestPermissions;
        if (interrupted) {
            const metadata_path = try std.fmt.allocPrint(allocator, "var/cache/debz/{s}", .{debz.metadata_cache.namespace});
            try absent(fixture, root, metadata_path);
        }
    }
    const shared_path = try support.path(allocator, relative, namespace ++ "root-operation-completion-v2.json");
    const local_path = try support.path(allocator, relative, try std.fmt.allocPrint(allocator, "{s}/root-operation-completion-v2.json", .{parent[1..]}));
    const shared_bytes = try support.read(fixture, shared_path, 64 * 1024);
    if (!std.mem.eql(u8, shared_bytes, try support.read(fixture, local_path, 64 * 1024)))
        return error.RepositoryCompletionCopyChanged;
    for ([_][]const u8{ shared_path, local_path }) |path| {
        if ((try fixture.dir.statFile(fixture.io, path, .{ .follow_symlinks = false })).permissions.toMode() & 0o777 != 0o600)
            return error.RepositoryCompletionPermissions;
    }
    var completed = try debz.root_operation_completion.decode(allocator, shared_bytes, 64 * 1024);
    defer completed.deinit();
    const completion = completed.document;
    const completed_bytes = try support.read(fixture, try support.path(allocator, relative, "fixture/repository-completed-caller.json"), 64 * 1024);
    var record = try debz.root_operation.decode(allocator, completed_bytes, 64 * 1024);
    defer record.deinit();
    var receipt_digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&receipt_digest, &proof.document.digest_sha256);
    if (record.record.state != .completed or record.record.provenance != .published or
        !std.mem.eql(u8, &(record.record.provenance_sha256 orelse return error.MissingRepositoryCompletion), &completion.digest_sha256) or
        record.record.generation != completion.record_generation + 1 or
        !completion.bindsRecord(record.record) or
        !std.mem.eql(u8, &completion.attempt_id, &pending.attempt_id) or
        !std.mem.eql(u8, &completion.request_sha256, &pending.request_sha256) or
        !std.mem.eql(u8, &completion.policy_sha256, &pending.policy_sha256) or
        !std.meta.eql(completion.program_sha256, pending.program_sha256) or
        !std.meta.eql(completion.authorization_sha256, pending.authorization_sha256) or
        !std.meta.eql(completion.plan_sha256, pending.plan_sha256) or
        completion.exact_lock == null or pending.exact_lock == null or
        !completion.exact_lock.?.eql(pending.exact_lock.?) or
        completion.foreign_architectures.len != pending.foreign_architectures.len or
        completion.outcome != (if (failed) debz.root_operation.Outcome.failed_after_mutation else .succeeded) or
        (completion.transaction_provenance.status != .already_present and completion.transaction_provenance.status != .recovered) or
        !std.mem.eql(u8, &(completion.transaction_provenance.document_sha256 orelse return error.MissingRepositoryCompletion), &receipt_digest) or
        completion.journal.status != .absent or completion.journal.document_sha256 != null)
        return error.RepositoryCompletionBindingMismatch;
    for (completion.foreign_architectures, pending.foreign_architectures) |actual, previous| {
        if (!std.mem.eql(u8, actual, previous)) return error.RepositoryCompletionBindingMismatch;
    }
    try parity_evidence.verifyProjected(fixture, root, debz.live_root.logical_root_path, state.state.architecture,
        &proof.document.exact_lock_sha256, failed);
    var discharge = std.crypto.hash.sha2.Sha256.init(.{});
    discharge.update("debz-native-repository-completion-request-v1\x00");
    discharge.update(&pending.attempt_id);
    discharge.update(&pending.request_sha256);
    discharge.update(&pending.policy_sha256);
    discharge.update(&proof.document.digest_sha256);
    discharge.update(&state.state.digest_sha256);
    discharge.update(&[_]u8{@intFromBool(!failed)});
    if (manifest_digest) |digest| discharge.update(&digest);
    const expected_discharge = discharge.finalResult();
    if (completion.discharge.surface != .repository_bootstrap or
        !std.mem.eql(u8, completion.discharge.operation, "add") or
        !std.mem.eql(u8, &completion.discharge.request_sha256, &expected_discharge))
        return error.RepositoryDischargeMismatch;
    try checkHelper(fixture, root, helper);
    var script_count: usize = 0;
    for (proof.document.evidence_files) |evidence| {
        if (evidence.kind != .script_outcome) continue;
        const bytes = try root_fs.readFileAlloc(allocator, try debz.root_fs.Path.init(evidence.path), 1024 * 1024);
        var parsed = try std.json.parseFromSlice(debz.native_recovery.ScriptOutcome, allocator, bytes, .{ .ignore_unknown_fields = false, .allocate = .alloc_always });
        defer parsed.deinit();
        const script = parsed.value;
        try debz.native_recovery.validateScriptOutcome(script);
        if (script.disposition != .exited or script.exit_code != (if (failed and script.kind == .postinst) @as(u8, 12) else 0) or
            !script.spawned or !std.mem.eql(u8, &script.digest_sha256, &(evidence.document_sha256 orelse return error.MissingRepositoryScriptDigest)))
            return error.RepositoryScriptOutcomeChanged;
        const expected_source = try std.fmt.allocPrint(allocator, "#!/bin/sh\nprintf '{s}\\n' >> /repository-trace\n{s}", .{
            @tagName(script.kind), if (failed and script.kind == .postinst) "exit 12\n" else "",
        });
        var sha256: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(expected_source, &sha256, .{});
        if (!std.mem.eql(u8, &script.script_sha256, &std.fmt.bytesToHex(sha256, .lower)))
            return error.RepositoryScriptSourceChanged;
        const request_binding = for (proof.document.evidence_files) |bound| {
            if (bound.kind != .execution_request) continue;
            const raw = try root_fs.readFileAlloc(allocator, try debz.root_fs.Path.init(bound.path), 1024 * 1024);
            break try debz.native_execution_request.decodePersisted(allocator, raw);
        } else return error.MissingRepositoryExecutionRequest;
        var request = request_binding;
        defer request.deinit();
        const execution = request.execution();
        if (!std.mem.eql(u8, &execution.caller.attempt_id, &std.fmt.bytesToHex(pending.attempt_id, .lower)) or
            !std.mem.eql(u8, &execution.caller.request_sha256, &std.fmt.bytesToHex(pending.request_sha256, .lower)) or
            !std.mem.eql(u8, &execution.caller.policy_sha256, &std.fmt.bytesToHex(pending.policy_sha256, .lower)))
            return error.RepositoryExecutionRequestChanged;
        const mount = request.helper() orelse return error.MissingRepositoryHelperBinding;
        try oracle.validateHelperInvocation(allocator, debz.live_root.logical_root_path, mount.source_path, mount.target_path, mount.sha256,
            execution.program.script_policy_sha256, .{ .package = script.package, .version = script.package_version,
                .architecture = script.architecture, .kind = @tagName(script.kind), .source = script.source,
                .arguments = script.arguments, .environment = script.environment, .script_sha256 = script.script_sha256,
                .invocation_sha256 = script.invocation_sha256 });
        script_count += 1;
    }
    if (script_count != 2) return error.MissingRepositoryScripts;
    if (resuming) {
        const historical_bytes = try support.read(fixture, try support.path(allocator, relative, "fixture/repository-history-caller.json"), 64 * 1024);
        var historical = try debz.root_operation.decode(allocator, historical_bytes, 64 * 1024);
        defer historical.deinit();
        if (std.mem.eql(u8, &historical.record.attempt_id, &pending.attempt_id) or
            historical.record.outcome != .pending or historical.record.mutation_started or
            historical.record.program_sha256 != null or
            historical.record.target_architecture.len != pending.target_architecture.len or
            !std.mem.eql(u8, historical.record.target_architecture, pending.target_architecture) or
            !std.mem.eql(u8, &historical.record.request_sha256, &pending.request_sha256) or
            !std.mem.eql(u8, &historical.record.policy_sha256, &pending.policy_sha256))
            return error.RepositoryResumeHistoryChanged;
        if (historical.record.foreign_architectures.len != pending.foreign_architectures.len)
            return error.RepositoryResumeHistoryChanged;
        for (historical.record.foreign_architectures, pending.foreign_architectures) |actual, previous| {
            if (!std.mem.eql(u8, actual, previous)) return error.RepositoryResumeHistoryChanged;
        }
        if (std.mem.eql(u8, case, "success")) {
            const historical_path = try support.path(allocator, relative, "fixture/repository-history-preserved.json");
            const history_bytes = try support.read(fixture, historical_path, 64 * 1024);
            const Row = struct { path: []const u8, inode: u64, sha256: [32]u8 };
            var preserved = try std.json.parseFromSlice([]const Row, allocator, history_bytes, .{ .allocate = .alloc_always, .ignore_unknown_fields = false });
            defer preserved.deinit();
            if (preserved.value.len != 8) return error.RepositoryHistoryEvidenceChanged;
            for (preserved.value, 0..) |row, index| {
                _ = try debz.root_fs.Path.init(row.path);
                for (preserved.value[0..index]) |prior| if (std.mem.eql(u8, prior.path, row.path))
                    return error.RepositoryHistoryEvidenceChanged;
                const path = try support.path(allocator, relative, row.path);
                const bytes = try support.read(fixture, path, 16 * 1024 * 1024);
                const metadata = try fixture.dir.statFile(fixture.io, path, .{ .follow_symlinks = false });
                var sha256: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(bytes, &sha256, .{});
                if (metadata.inode != row.inode or !std.mem.eql(u8, &sha256, &row.sha256))
                    return error.RepositoryHistoryEvidenceChanged;
            }
        }
    }
}

fn projectionCase(fixture: *foundation.Fixture, self: []const u8, runner: []const u8, arch: []const u8) !void {
    const name = "repository-projection";
    const root = try makeRoot(fixture, name, arch);
    defer fixture.allocator.free(root);
    try copyRunner(fixture, root, runner, "/fixture/native-test");
    try projected(fixture, self, root, .projection, name, true, null);
    const relative = root[fixture.path.len + 1 ..];
    const complete = try support.path(fixture.allocator, relative, "fixture/repository-projection-complete");
    defer fixture.allocator.free(complete);
    try assertText(fixture, complete, "native repository projection fixture complete\n");
    try assertEmpty(fixture, root, "run/debz/system-root");
    const locked = try support.path(fixture.allocator, relative, namespace);
    defer fixture.allocator.free(locked);
    var evidence = try fixture.dir.openDir(fixture.io, locked, .{ .iterate = true, .follow_symlinks = false });
    defer evidence.close(fixture.io);
    var names = evidence.iterate();
    const only = (try names.next(fixture.io)) orelse return error.MissingRepositoryLock;
    if (!std.mem.eql(u8, only.name, "root-operation.lock") or try names.next(fixture.io) != null)
        return error.RepositoryProjectionLeaked;
    try absent(fixture, root, namespace ++ "root-operation-v1.json");
    try absent(fixture, root, namespace ++ "native-execution-intent-v1.json");
    try absent(fixture, root, "var/lib/dpkg/info/packages-microsoft-prod.list");
    try assertText(fixture, try support.path(fixture.allocator, relative, "usr/share/held"), "untouched\n");
    std.debug.print("{s}: real private PID/mount root caller preparation and cleanup passed\n", .{name});
}

fn executionCase(
    fixture: *foundation.Fixture,
    self: []const u8,
    runner: []const u8,
    arch: []const u8,
    case: []const u8,
    resuming: bool,
) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "repository-{s}-{s}", .{ if (resuming) "resume" else "execution", case });
    const root = try makeRoot(fixture, name, arch);
    defer fixture.allocator.free(root);
    try copyRunner(fixture, root, runner, "/fixture/native-test");
    const relative = root[fixture.path.len + 1 ..];
    const selected = try support.path(fixture.allocator, relative, "fixture/repository-execution-case");
    try fixture.write(selected, case, 0o600);
    if (resuming) {
        const marker = try support.path(fixture.allocator, relative, "fixture/repository-resume");
        try fixture.write(marker, "", 0o600);
    }
    const terminal = std.mem.eql(u8, case, "success") or
        std.mem.eql(u8, case, "known_failure") or std.mem.eql(u8, case, "interrupted");
    if (terminal) {
        try copyRunner(fixture, root, "/bin/sh", "/bin/sh");
        try copyRunner(fixture, root, "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
    }
    const helper_before: ?HelperIdentity = if (terminal) try pinnedHelper(fixture, root) else null;
    try projected(fixture, self, root, .execution, name, true, null);
    const complete = try support.path(fixture.allocator, relative, "fixture/repository-execution-complete");
    try assertText(fixture, complete, case);
    try assertEmpty(fixture, root, "run/debz/system-root");
    try assertEmpty(fixture, root, "fixture/package-cache/packages-v2/objects");
    try absent(fixture, root, namespace ++ "root-operation-v1.json");
    try absent(fixture, root, namespace ++ "native-execution-intent-v1.json");
    if (terminal) {
        const retained_name = try support.path(fixture.allocator, relative, "fixture/repository-retained-receipt-path");
        const logical = try support.read(fixture, retained_name, 4096);
        if (!std.mem.startsWith(u8, logical, "/" ++ namespace ++ "repository/operations/") or
            !std.mem.endsWith(u8, logical, "/native-transaction-provenance-v2.json"))
            return error.InvalidRetainedRepositoryReceipt;
        const retained = try support.path(fixture.allocator, relative, logical[1..]);
        const copied = try support.path(fixture.allocator, relative, "fixture/repository-native-receipt.json");
        const retained_bytes = try support.read(fixture, retained, 16 * 1024 * 1024);
        const copied_bytes = try support.read(fixture, copied, 16 * 1024 * 1024);
        if (!std.mem.eql(u8, retained_bytes, copied_bytes)) return error.RetainedRepositoryReceiptChanged;
        const completion = try support.path(fixture.allocator, relative, namespace ++ "root-operation-completion-v2.json");
        _ = try support.read(fixture, completion, 64 * 1024);
        const caller = try support.path(fixture.allocator, relative, "fixture/repository-pending-caller.json");
        const caller_bytes = try support.read(fixture, caller, 64 * 1024);
        var pending = try std.json.parseFromSlice(std.json.Value, fixture.allocator, caller_bytes, .{});
        defer pending.deinit();
        if (pending.value != .object or pending.value.object.get("outcome") == null or
            !std.mem.eql(u8, pending.value.object.get("outcome").?.string, "pending"))
            return error.InvalidRepositoryCaller;
        const trace = try support.path(fixture.allocator, relative, "repository-trace");
        try assertText(fixture, trace, "preinst\npostinst\n");
        const status = try support.path(fixture.allocator, relative, "var/lib/dpkg/status");
        const status_bytes = try support.read(fixture, status, 64 * 1024);
        if (std.mem.indexOf(u8, status_bytes, if (std.mem.eql(u8, case, "known_failure")) "Status: install ok half-configured\n" else "Status: install ok installed\n") == null) return error.InvalidRepositoryStatus;
        try terminalEvidence(fixture, root, relative, case, resuming, logical, retained_bytes, helper_before.?);
    } else {
        try absent(fixture, root, namespace ++ "root-operation-completion-v2.json");
        try absent(fixture, root, "fixture/repository-native-receipt.json");
        for ([_][]const u8{
            "fixture/repository-retained-receipt-path", namespace ++ "repository", "repository-trace",
            "usr/bin/dpkg-trigger", namespace ++ "native-helper-cache-v1",
            "usr/share/doc/debz-native-repository/README",
        }) |path| try absent(fixture, root, path);
    }
    try assertText(fixture, try support.path(fixture.allocator, relative, "usr/share/held"), "untouched\n");
    std.debug.print("{s}: real typed caller recovery, receipt and cleanup passed\n", .{name});
}

fn unchangedCases(fixture: *foundation.Fixture, self: []const u8, runner: []const u8, arch: []const u8) !void {
    for ([_]bool{ false, true }) |no_refresh| {
        const name = if (no_refresh) "repository-unchanged-no-refresh" else "repository-unchanged-refresh";
        const root = try makeRoot(fixture, name, arch);
        defer fixture.allocator.free(root);
        try copyRunner(fixture, root, runner, "/fixture/native-test");
        const relative = root[fixture.path.len + 1 ..];
        try fixture.write(try support.path(fixture.allocator, relative, "fixture/repository-execution-case"), "unchanged", 0o600);
        try fixture.write(try support.path(fixture.allocator, relative, "fixture/repository-unchanged-bootstrap"), if (no_refresh) "no-refresh" else "refresh", 0o600);
        try projected(fixture, self, root, .execution, name, true, null);
        try assertText(fixture, try support.path(fixture.allocator, relative, "fixture/repository-execution-complete"), "unchanged");
        try assertEmpty(fixture, root, "run/debz/system-root");
        try assertEmpty(fixture, root, "fixture/package-cache/packages-v2/objects");
        try absent(fixture, root, "repository-trace");
        try absent(fixture, root, "usr/bin/dpkg-trigger");
        try absent(fixture, root, namespace ++ "root-operation-v1.json");
        try absent(fixture, root, namespace ++ "root-operation-completion-v2.json");
        const original = try support.read(fixture, try support.path(fixture.allocator, relative, "fixture/unchanged-original-status"), 64 * 1024);
        const status = try support.read(fixture, try support.path(fixture.allocator, relative, "var/lib/dpkg/status"), 64 * 1024);
        if (!std.mem.eql(u8, original, status)) return error.UnchangedRepositoryModifiedStatus;
        const abandoned_bytes = try support.read(fixture, try support.path(fixture.allocator, relative, "fixture/repository-unchanged-caller.json"), 64 * 1024);
        var abandoned = try debz.root_operation.decode(fixture.allocator, abandoned_bytes, 64 * 1024);
        defer abandoned.deinit();
        const publisher_bytes = try support.read(fixture, try support.path(fixture.allocator, relative, "fixture/unchanged-proof-caller.json"), 64 * 1024);
        var publisher = try debz.root_operation.decode(fixture.allocator, publisher_bytes, 64 * 1024);
        defer publisher.deinit();
        const operations = try support.path(fixture.allocator, relative, namespace ++ "repository/operations");
        var operation_dir = try fixture.dir.openDir(fixture.io, operations, .{ .iterate = true, .follow_symlinks = false });
        defer operation_dir.close(fixture.io);
        var iterator = operation_dir.iterate();
        const only = (try iterator.next(fixture.io)) orelse return error.MissingRepositoryCheckpoint;
        if (only.kind != .directory or try iterator.next(fixture.io) != null)
            return error.UnexpectedRepositoryOperations;
        const path = try support.path(fixture.allocator, operations, try support.path(fixture.allocator, only.name, "repo-add-state-v1.json"));
        const state_bytes = try support.read(fixture, path, debz.repository_state.maximum_document_bytes);
        var state = try debz.repository_state.decode(fixture.allocator, state_bytes, debz.repository_state.maximum_document_bytes);
        defer state.deinit();
        if (state.state.phase != .complete or !state.state.installed or state.state.no_refresh != no_refresh or
            state.state.refreshed == no_refresh or state.state.diagnostic_id != null)
            return error.InvalidRepositoryCheckpoint;
        try unchangedBindings(fixture, root, state.state, abandoned.record, publisher.record);
        try absent(fixture, root, namespace ++ "native-transaction-provenance-v2.json");
        std.debug.print("{s}: real no-receipt recovery retained status and discarded inputs\n", .{name});
    }
}

fn dispatchCases(fixture: *foundation.Fixture, self: []const u8, runner: []const u8, arch: []const u8) !void {
    for ([_][]const u8{
        "success",     "no_refresh",             "unchanged",          "unchanged_no_refresh", "known_failure",
        "interrupted", "completion_interrupted", "locked_interrupted", "scope_lost",           "refresh_failure",
        "expired",
    }) |case| {
        const name = try std.fmt.allocPrint(fixture.allocator, "repository-dispatch-{s}", .{case});
        const root = try makeRoot(fixture, name, arch);
        defer fixture.allocator.free(root);
        const relative = root[fixture.path.len + 1 ..];
        try copyRunner(fixture, root, runner, "/fixture/native-test");
        try fixture.write(try support.path(fixture.allocator, relative, "fixture/repository-execution-case"), "success", 0o600);
        try fixture.write(try support.path(fixture.allocator, relative, "fixture/repository-dispatch"), case, 0o600);
        const unchanged = std.mem.startsWith(u8, case, "unchanged");
        const no_refresh = std.mem.eql(u8, case, "no_refresh") or
            std.mem.eql(u8, case, "unchanged_no_refresh");
        var original_helper: ?HelperIdentity = null;
        if (!unchanged) {
            try copyRunner(fixture, root, "/bin/sh", "/bin/sh");
            try copyRunner(fixture, root, "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
            original_helper = try pinnedHelper(fixture, root);
        }
        try projected(fixture, self, root, .execution, name, true, null);
        try assertText(fixture, try support.path(fixture.allocator, relative, "fixture/repository-execution-complete"), case);
        var results: [3]api.OwnedResult = undefined;
        var count: usize = 0;
        defer for (results[0..count]) |*result| result.deinit();
        for (0..3) |index| {
            const path = try std.fmt.allocPrint(fixture.allocator, "fixture/native-dispatch-{d}.json", .{index});
            results[index] = try resultAt(fixture, root, path);
            count += 1;
        }
        const first = results[0].result;
        const recovered = results[1].result;
        const repeated = results[2].result;
        if (std.mem.eql(u8, case, "known_failure")) {
            if (first.exit_status != .transaction or recovered.exit_status != .transaction or
                repeated.exit_status != .transaction or repeated.installed)
                return error.InvalidRepositoryDispatchResult;
        } else {
            if (recovered.exit_status != .success or repeated.exit_status != .success or
                !recovered.installed or !repeated.installed or repeated.changed or
                repeated.refreshed_phase != (if (no_refresh) api.PhaseState.skipped else .complete) or
                repeated.refreshed == no_refresh)
                return error.InvalidRepositoryDispatchResult;
        }
        if (std.mem.eql(u8, case, "refresh_failure")) {
            if (first.exit_status != .post_install or !first.installed or !first.changed or
                first.diagnostic_count == 0 or first.diagnostics[0].id != .refresh_failed)
                return error.InvalidRepositoryDispatchResult;
        }
        if (std.mem.eql(u8, case, "interrupted") or std.mem.eql(u8, case, "completion_interrupted") or
            std.mem.eql(u8, case, "locked_interrupted") or std.mem.eql(u8, case, "scope_lost") or
            std.mem.eql(u8, case, "refresh_failure") or std.mem.eql(u8, case, "expired"))
            if (first.exit_status == .success) return error.RepositoryDispatchIgnoredInterruption;
        try assertEmpty(fixture, root, "run/debz/system-root");
        try assertEmpty(fixture, root, "var/cache/debz/packages-v2/objects");
        try absent(fixture, root, namespace ++ "root-operation-v1.json");
        try absent(fixture, root, namespace ++ "native-execution-intent-v1.json");
        try absent(fixture, root, namespace ++ "native-recovery-v1");
        const checkpoint = repeated.paths.operation_state orelse return error.MissingRepositoryCheckpoint;
        var state = try checkpointAt(fixture, root, checkpoint);
        defer state.deinit();
        if (state.state.phase != (if (std.mem.eql(u8, case, "known_failure")) debz.repository_state.Phase.failed else .complete) or
            state.state.installed == std.mem.eql(u8, case, "known_failure") or
            state.state.no_refresh != no_refresh or
            state.state.diagnostic_id != (if (std.mem.eql(u8, case, "known_failure")) api.DiagnosticId.transaction_failed else null) or
            !std.mem.eql(u8, state.state.root, debz.live_root.logical_root_path))
            return error.InvalidRepositoryCheckpoint;
        const parent = std.fs.path.dirname(checkpoint) orelse return error.MissingRepositoryCheckpoint;
        try absent(fixture, root, try std.fmt.allocPrint(fixture.allocator, "{s}/transaction-result-v2.json", .{parent[1..]}));
        const logical = repeated.paths.provenance orelse return error.MissingRepositoryProvenance;
        if (!std.mem.eql(u8, logical, state.state.provenance_path orelse return error.MissingRepositoryCheckpoint))
            return error.RepositoryCheckpointProvenanceMismatch;
        if (unchanged) {
            for (results) |result| if (result.result.changed)
                return error.RepositoryDispatchChangedHeldSelection;
            try absent(fixture, root, "repository-trace");
            try absent(fixture, root, "usr/bin/dpkg-trigger");
            try absent(fixture, root, namespace ++ "root-operation-completion-v2.json");
            try unchangedEvidence(fixture, try readLogical(fixture, root, logical, 64 * 1024));
            const status = try support.read(fixture, try support.path(fixture.allocator, relative, "var/lib/dpkg/status"), 64 * 1024);
            const before = try support.read(fixture, try support.path(fixture.allocator, relative, "fixture/dispatch-original-status"), 64 * 1024);
            if (!std.mem.eql(u8, status, before)) return error.RepositoryDispatchChangedHeldStatus;
            const lock_path = state.state.exact_lock_path orelse return error.MissingRepositoryExactLock;
            var lock = try debz.exact_lock_v3.decode(fixture.allocator, try readLogical(fixture, root, lock_path, 1024 * 1024), 1024 * 1024);
            defer lock.deinit();
            if (lock.lock.packages.len != 1 or !lock.lock.packages[0].dpkg_selection_hold)
                return error.RepositoryDispatchLostHold;
        } else {
            try assertText(fixture, try support.path(fixture.allocator, relative, "repository-trace"), "preinst\npostinst\n");
            try checkHelper(fixture, root, original_helper orelse return error.MissingRepositoryHelper);
            var receipt = try proofAt(fixture, root, logical);
            defer receipt.deinit();
            if (receipt.document.outcome != (if (std.mem.eql(u8, case, "known_failure")) debz.native_provenance.Outcome.failed else .succeeded) or
                !std.mem.eql(u8, receipt.document.install_root, debz.live_root.logical_root_path))
                return error.InvalidRepositoryDispatchProvenance;
            var guarded = try foundation.guardedRoot(fixture.io, root);
            defer guarded.close(fixture.io);
            try debz.native_provenance.verifyEvidence(fixture.allocator, .init(fixture.io, guarded), receipt.document);
        }
        try assertText(fixture, try support.path(fixture.allocator, relative, "usr/share/held"), "untouched\n");
        std.debug.print("{s}: real original request, typed result and repeat passed\n", .{name});
    }
}

const NetworkServer = struct {
    child: std.process.Child,
    stderr: std.Io.File,
    url: []const u8,
    requests: []const u8,
    io: std.Io,

    fn stop(self: *NetworkServer) void {
        if (self.child.id) |pid| {
            _ = linux.kill(pid, .TERM);
            const started = std.Io.Clock.awake.now(self.io);
            while (!childExited(pid) and
                started.durationTo(std.Io.Clock.awake.now(self.io)).toMilliseconds() < 10_000)
            {
                self.io.sleep(.fromMilliseconds(10), .awake) catch break;
            }
        }
        self.child.kill(self.io);
        self.stderr.close(self.io);
    }
};

fn startNetworkServer(fixture: *foundation.Fixture, python: []const u8) !NetworkServer {
    try fixture.directory("repository-http/root/fixture");
    const script = try std.fmt.allocPrint(fixture.allocator, "{s}/tools/http-fixture-server.py", .{options.repository});
    const root = try fixture.absolute("repository-http/root/fixture");
    const port_path = try fixture.absolute("repository-http/http.port");
    const requests = try fixture.absolute("repository-http/http.requests");
    var stderr = try fixture.dir.createFile(fixture.io, "repository-http/http.stderr", .{});
    errdefer stderr.close(fixture.io);
    var child = try std.process.spawn(fixture.io, .{
        .argv = &.{ python, "-B", script, "--root", root, "--port-file", port_path, "--request-log", requests },
        .environ_map = &fixture.environment,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .{ .file = stderr },
    });
    errdefer child.kill(fixture.io);
    const started = std.Io.Clock.awake.now(fixture.io);
    const port = while (started.durationTo(std.Io.Clock.awake.now(fixture.io)).toMilliseconds() < 10_000) {
        const bytes = fixture.dir.readFileAlloc(fixture.io, "repository-http/http.port", fixture.allocator, .limited(32)) catch |err| {
            if (err != error.FileNotFound) return err;
            if (childExited(child.id.?)) return error.NetworkFixtureServerStopped;
            try fixture.io.sleep(.fromMilliseconds(10), .awake);
            continue;
        };
        if (bytes.len == 0) continue;
        break std.mem.trim(u8, bytes, "\n");
    } else return error.NetworkFixtureServerTimeout;
    _ = try std.fmt.parseInt(u16, port, 10);
    return .{
        .child = child,
        .stderr = stderr,
        .url = try std.fmt.allocPrint(fixture.allocator, "http://127.0.0.1:{s}", .{port}),
        .requests = requests,
        .io = fixture.io,
    };
}

fn copyRepository(fixture: *foundation.Fixture, source: []const u8, target: []const u8, log: []const u8) !void {
    try fixture.directory(target);
    const source_contents = try std.fmt.allocPrint(fixture.allocator, "{s}/.", .{source});
    const destination = try fixture.absolute(target);
    try fixture.run(&.{ "/usr/bin/cp", "-a", source_contents, destination }, log, 60);
}

fn readLogical(fixture: *foundation.Fixture, root: []const u8, logical: []const u8, limit: usize) ![]u8 {
    if (!std.mem.startsWith(u8, logical, "/" ++ namespace) or
        std.mem.indexOf(u8, logical, "..") != null) return error.InvalidRepositoryEvidencePath;
    return support.read(fixture, try support.path(fixture.allocator, root[fixture.path.len + 1 ..], logical[1..]), limit);
}

fn unchangedEvidence(fixture: *foundation.Fixture, bytes: []const u8) !void {
    var document = try std.json.parseFromSlice(std.json.Value, fixture.allocator, bytes, .{});
    defer document.deinit();
    if (document.value != .object) return error.InvalidRepositoryUnchangedEvidence;
    const changed = document.value.object.get("changed") orelse return error.InvalidRepositoryUnchangedEvidence;
    const receipt = document.value.object.get("receipt") orelse return error.InvalidRepositoryUnchangedEvidence;
    const actions = document.value.object.get("action_count") orelse return error.InvalidRepositoryUnchangedEvidence;
    const digest = document.value.object.get("digest_sha256") orelse return error.InvalidRepositoryUnchangedEvidence;
    if (changed != .bool or changed.bool or receipt != .null or actions != .integer or actions.integer != 0 or
        digest != .string or digest.string.len != std.crypto.hash.sha2.Sha256.digest_length * 2)
        return error.InvalidRepositoryUnchangedEvidence;
    if (!document.value.object.swapRemove("digest_sha256")) return error.InvalidRepositoryUnchangedEvidence;
    const payload = try std.json.Stringify.valueAlloc(fixture.allocator, document.value, .{});
    var sha256: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &sha256, .{});
    if (!std.mem.eql(u8, digest.string, &std.fmt.bytesToHex(sha256, .lower)))
        return error.InvalidRepositoryUnchangedDigest;
}

fn scanQuerySecret(io: std.Io, dir: std.Io.Dir, path: []const u8) !void {
    const secret = "native-query-secret";
    var file = try dir.openFile(io, path, .{ .follow_symlinks = false });
    defer file.close(io);
    const before = try file.stat(io);
    if (before.kind != .file) return error.NonregularRepositoryNetworkEvidence;
    var reader = file.reader(io, &.{});
    var buffer: [64 * 1024 + secret.len - 1]u8 = undefined;
    var overlap: usize = 0;
    var scanned: u64 = 0;
    while (true) {
        const count = reader.interface.readSliceShort(buffer[overlap .. overlap + 64 * 1024]) catch return reader.err.?;
        if (count == 0) break;
        scanned = std.math.add(u64, scanned, count) catch return error.RepositoryNetworkEvidenceTooLarge;
        if (std.mem.indexOf(u8, buffer[0 .. overlap + count], secret) != null)
            return error.NetworkFixtureLeakedCredential;
        const end = overlap + count;
        const next_overlap = @min(secret.len - 1, end);
        std.mem.copyForwards(u8, buffer[0..next_overlap], buffer[end - next_overlap .. end]);
        overlap = next_overlap;
    }
    const after = try file.stat(io);
    if (scanned != before.size or before.size != after.size or before.inode != after.inode)
        return error.RepositoryNetworkEvidenceChanged;
}

fn assertNoQuerySecret(fixture: *foundation.Fixture, root: []const u8) !void {
    const relative = root[fixture.path.len + 1 ..];
    for ([_][]const u8{ "var/lib/debz", "var/cache/debz", "etc/apt" }) |name| {
        const base = try support.path(fixture.allocator, relative, name);
        defer fixture.allocator.free(base);
        var directory = fixture.dir.openDir(fixture.io, base, .{ .iterate = true, .follow_symlinks = false }) catch |err| {
            if (err == error.FileNotFound) continue;
            return err;
        };
        defer directory.close(fixture.io);
        var walker = try directory.walk(fixture.allocator);
        defer walker.deinit();
        var entries: usize = 0;
        while (try walker.next(fixture.io)) |entry| {
            entries += 1;
            if (entries > 4096) return error.RepositoryNetworkEvidenceTooLarge;
            if (entry.kind != .file) continue;
            const path = try support.path(fixture.allocator, base, entry.path);
            defer fixture.allocator.free(path);
            try scanQuerySecret(fixture.io, fixture.dir, path);
        }
    }
}

fn verifyCliScenario(
    fixture: *foundation.Fixture,
    root: []const u8,
    case: []const u8,
    results: []const api.OwnedResult,
    before_status: []const u8,
    network_requests: ?[]const u8,
) !void {
    const first = results[0].result;
    const final = results[results.len - 1].result;
    const unchanged = std.mem.eql(u8, case, "unchanged") or std.mem.eql(u8, case, "unchanged_no_refresh");
    const no_refresh = std.mem.eql(u8, case, "no_refresh") or std.mem.eql(u8, case, "unchanged_no_refresh");
    const lock = std.mem.eql(u8, case, "lock_wait") or std.mem.eql(u8, case, "lock_signal");
    const early = lock or std.mem.eql(u8, case, "unsafe_runtime");
    const deadline = std.mem.eql(u8, case, "deadline");
    const signal = std.mem.eql(u8, case, "signal");
    const failed = std.mem.eql(u8, case, "known_failure");
    const refresh_failure = std.mem.eql(u8, case, "refresh_failure");
    const relative = root[fixture.path.len + 1 ..];
    const status = try support.read(fixture, try support.path(fixture.allocator, relative, "var/lib/dpkg/status"), 64 * 1024);
    if (early or unchanged) {
        if (!std.mem.eql(u8, status, before_status)) return error.RepositoryRefusalChangedStatus;
    }
    if (early or deadline or signal) {
        for (results) |item| if (item.result.exit_status == .success)
            return error.RepositoryFailureReportedSuccess;
        if (std.mem.eql(u8, case, "lock_wait") or deadline) {
            if (first.diagnostic_count == 0 or first.diagnostics[0].id != .resource_limit_exceeded) {
                std.debug.print("repository CLI {s}: exit={s}, diagnostic={s}; expected resource limit\n", .{
                    case,
                    @tagName(first.exit_status),
                    if (first.diagnostic_count == 0) "none" else @tagName(first.diagnostics[0].id),
                });
                return error.InvalidRepositoryDeadlineDiagnostic;
            }
        }
        if (std.mem.eql(u8, case, "lock_signal") and
            (first.exit_status != .recovery or first.diagnostic_count == 0 or
                first.diagnostics[0].id != .recovery_required))
            return error.InvalidRepositoryLockSignalDiagnostic;
        if (std.mem.eql(u8, case, "unsafe_runtime") and
            (first.exit_status != .unavailable or first.diagnostic_count == 0 or
                first.diagnostics[0].id != .transaction_backend_unavailable or
                !std.mem.eql(u8, first.diagnostics[0].message, "UnsafeRuntimeDirectory")))
            return error.InvalidRepositoryUnsafeRuntimeDiagnostic;
        if (signal) {
            if (results.len != 3 or first.exit_status != .recovery or
                final.exit_status != .recovery or
                !std.mem.eql(u8, final.summary, "script_outcome_unknown"))
                return error.InvalidRepositorySignalRecovery;
            try assertText(fixture, try support.path(fixture.allocator, relative, "repository-trace"), "preinst\npostinst\n");
        }
        if (early) {
            try absent(fixture, root, namespace ++ "root-operation-v1.json");
        } else if (signal) {
            const retained = try support.read(fixture, try support.path(fixture.allocator, relative, namespace ++ "root-operation-v1.json"), 64 * 1024);
            if (retained.len == 0) return error.MissingInterruptedRepositoryCaller;
        }
    } else {
        if (results.len != 3) return error.MissingRepositoryReplay;
        if (failed) {
            for (results) |item| if (item.result.exit_status != .transaction or item.result.installed)
                return error.InvalidKnownFailureResult;
            if (first.diagnostic_count == 0 or first.diagnostics[0].id != .transaction_failed)
                return error.InvalidKnownFailureResult;
            if (std.mem.indexOf(u8, status, "Status: install ok half-configured\n") == null)
                return error.InvalidKnownFailureStatus;
        } else {
            if (results[1].result.exit_status != .success or final.exit_status != .success or
                first.exit_status != (if (refresh_failure) api.ExitStatus.post_install else .success) or
                !final.installed or final.changed or
                final.refreshed_phase != (if (no_refresh) api.PhaseState.skipped else .complete))
                return error.InvalidRepositoryCliRecovery;
            if (refresh_failure and (first.diagnostic_count == 0 or
                first.diagnostics[0].id != .refresh_failed or !first.changed))
                return error.InvalidRepositoryRefreshFailure;
        }
        try absent(fixture, root, namespace ++ "root-operation-v1.json");
        try absent(fixture, root, namespace ++ "native-execution-intent-v1.json");
        try absent(fixture, root, namespace ++ "native-recovery-v1");
        const logical = final.paths.provenance orelse return error.MissingRepositoryProvenance;
        const evidence = try readLogical(fixture, root, logical, 16 * 1024 * 1024);
        if (unchanged) {
            if (!std.mem.endsWith(u8, logical, "/native-repository-unchanged-v1.json") or
                first.changed or !first.installed)
                return error.InvalidRepositoryUnchangedEvidence;
            try unchangedEvidence(fixture, evidence);
            try absent(fixture, root, "repository-trace");
            try absent(fixture, root, namespace ++ "root-operation-completion-v2.json");
        } else {
            var proof = try @import("debz").native_provenance.decode(fixture.allocator, evidence);
            defer proof.deinit();
            if (proof.document.outcome != (if (failed) @import("debz").native_provenance.Outcome.failed else .succeeded) or
                !std.mem.eql(u8, proof.document.install_root, @import("debz").live_root.logical_root_path))
                return error.InvalidRepositoryNativeProvenance;
            var named = try @import("debz").root_fs.openAbsoluteRoot(fixture.io, root);
            defer named.close();
            try @import("debz").native_provenance.verifyEvidence(fixture.allocator, named.root, proof.document);
            try assertText(fixture, try support.path(fixture.allocator, relative, "repository-trace"), "preinst\npostinst\n");
            const completed = try support.read(fixture, try support.path(fixture.allocator, relative, namespace ++ "root-operation-completion-v2.json"), 64 * 1024);
            if (completed.len == 0) return error.MissingRepositoryCompletion;
        }
        const checkpoint = final.paths.operation_state orelse return error.MissingRepositoryCheckpoint;
        const state_bytes = try readLogical(fixture, root, checkpoint, @import("debz").repository_state.maximum_document_bytes);
        var state = try @import("debz").repository_state.decode(fixture.allocator, state_bytes, @import("debz").repository_state.maximum_document_bytes);
        defer state.deinit();
        if (state.state.phase != (if (failed) @import("debz").repository_state.Phase.failed else .complete) or
            state.state.installed == failed or
            state.state.no_refresh != no_refresh or
            state.state.diagnostic_id != (if (failed) api.DiagnosticId.transaction_failed else null) or
            !std.mem.eql(u8, state.state.root, @import("debz").live_root.logical_root_path))
            return error.InvalidRepositoryCheckpoint;
    }
    try assertEmpty(fixture, root, "run/debz/system-root");
    try absent(fixture, root, "usr/bin/dpkg");
    try absent(fixture, root, "usr/bin/dpkg-deb");
    const requests_path = network_requests orelse return;
    try assertNoQuerySecret(fixture, root);
    const requests_relative = requests_path[fixture.path.len + 1 ..];
    const requests = try support.read(fixture, requests_relative, 1024 * 1024);
    if (std.mem.indexOf(u8, requests, "native-query-secret") != null)
        return error.NetworkFixtureLeakedCredential;
    var lines = std.mem.splitScalar(u8, requests, '\n');
    var descriptor_count: usize = 0;
    var repository = false;
    var bootstrap = false;
    while (lines.next()) |line| {
        if (std.mem.eql(u8, line, "/descriptor.deb")) descriptor_count += 1;
        if (std.mem.startsWith(u8, line, "/repository/")) repository = true;
        if (std.mem.startsWith(u8, line, "/bootstrap-repository/")) bootstrap = true;
    }
    if (descriptor_count != 1 or !repository or !bootstrap) return error.IncompleteNetworkFixtureRequests;
}

fn cliScenario(
    fixture: *foundation.Fixture,
    self: []const u8,
    cli: []const u8,
    arch: []const u8,
    python: []const u8,
    reference: []const u8,
    case: []const u8,
) !void {
    const name = try std.fmt.allocPrint(fixture.allocator, "repository-cli-{s}", .{case});
    const unchanged = std.mem.eql(u8, case, "unchanged") or std.mem.eql(u8, case, "unchanged_no_refresh");
    const no_refresh = std.mem.eql(u8, case, "no_refresh") or std.mem.eql(u8, case, "unchanged_no_refresh");
    const blocked = std.mem.eql(u8, case, "refresh_failure") or
        std.mem.eql(u8, case, "signal") or std.mem.eql(u8, case, "deadline");
    const network = std.mem.eql(u8, case, "network");
    var server: ?NetworkServer = if (network) try startNetworkServer(fixture, python) else null;
    defer if (server) |*running| running.stop();
    const transport = if (server) |running| running.url else "file:///fixture";
    const root = try makeRoot(fixture, name, arch);
    defer fixture.allocator.free(root);
    const relative = root[fixture.path.len + 1 ..];
    try copyRunner(fixture, root, cli, "/fixture/debz");
    try copyRunner(fixture, root, "/bin/sh", "/bin/sh");
    try copyRunner(fixture, root, "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
    const helper_path = try support.path(fixture.allocator, relative, "usr/bin/dpkg-trigger");
    const helper_bytes = try support.read(fixture, helper_path, 8 * 1024 * 1024);
    const helper_before = try fixture.dir.statFile(fixture.io, helper_path, .{ .follow_symlinks = false });
    if (blocked) try copyRunner(fixture, root, "/bin/sleep", "/bin/sleep");
    const generated_relative = try support.path(fixture.allocator, name, "generated");
    const generated = try fixture.absolute(generated_relative);
    const generator = try std.fmt.allocPrint(fixture.allocator, "{s}/tools/generate-integration-repository.py", .{options.repository});
    const descriptor_relative = try support.path(fixture.allocator, name, "root/fixture/descriptor.deb");
    const descriptor = try fixture.absolute(descriptor_relative);
    const generator_log = try support.path(fixture.allocator, name, "generator.log");
    const repository_url = try std.fmt.allocPrint(fixture.allocator, "{s}/repository", .{transport});
    try fixture.run(&.{
        python,                                                                                               "-B", generator,             "--output", generated,                     "--suite",      "debian-stable",
        "--architecture",                                                                                     arch, "--descriptor-output", descriptor, "--descriptor-repository-url", repository_url, "--descriptor-script-case",
        if (std.mem.eql(u8, case, "known_failure")) "known_failure" else if (blocked) "blocked" else "trace",
    }, generator_log, 60);
    for ([_][]const u8{ "repository", "bootstrap-repository" }) |destination| {
        const target = try std.fmt.allocPrint(fixture.allocator, "{s}/fixture/{s}", .{ relative, destination });
        const log = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}.copy.log", .{ name, destination });
        try copyRepository(fixture, generated, target, log);
        if (network) {
            const network_target = try std.fmt.allocPrint(fixture.allocator, "repository-http/root/fixture/{s}", .{destination});
            const network_log = try std.fmt.allocPrint(fixture.allocator, "{s}/{s}.network.log", .{ name, destination });
            try copyRepository(fixture, generated, network_target, network_log);
        }
    }
    if (network) {
        const network_descriptor = try fixture.absolute("repository-http/root/fixture/descriptor.deb");
        const network_log = try support.path(fixture.allocator, name, "descriptor.network.log");
        try fixture.run(&.{ "/usr/bin/cp", descriptor, network_descriptor }, network_log, 10);
    }
    const keyring = try support.read(fixture, try support.path(fixture.allocator, name, "generated/fixture-keyring.gpg"), 1024 * 1024);
    try fixture.write(try support.path(fixture.allocator, relative, "usr/share/keyrings/bootstrap.gpg"), keyring, 0o644);
    const source = try std.fmt.allocPrint(fixture.allocator, "Types: deb\nURIs: {s}/bootstrap-repository\nSuites: debian-stable\n" ++
        "Components: main\nArchitectures: {s}\nSigned-By: /usr/share/keyrings/bootstrap.gpg\n", .{ transport, arch });
    try fixture.write(try support.path(fixture.allocator, relative, "etc/apt/sources.list.d/bootstrap.sources"), source, 0o644);
    if (unchanged) {
        const ca_archive = try std.fmt.allocPrint(fixture.allocator, "{s}/pool/main/ca-certificates_20240203_all.deb", .{generated});
        const seed_log = try support.path(fixture.allocator, name, "seed");
        try fixture.directory(seed_log);
        if (try support.reference(fixture, reference, root, .{
            .operation = "install",
            .archives = &.{ ca_archive, descriptor },
        }, seed_log) != 0) return error.ReferenceSeedFailed;
        const status_path = try support.path(fixture.allocator, relative, "var/lib/dpkg/status");
        const status = try support.read(fixture, status_path, 64 * 1024);
        const changed = try std.mem.replaceOwned(u8, fixture.allocator, status, "Package: packages-microsoft-prod\nStatus: install ok installed\n", "Package: packages-microsoft-prod\nStatus: hold ok installed\n");
        if (std.mem.eql(u8, changed, status)) return error.MissingHeldRepositoryPackage;
        try fixture.write(status_path, changed, 0o644);
        try fixture.dir.deleteFile(fixture.io, try support.path(fixture.allocator, relative, "repository-trace"));
    }
    const initial_status = try support.read(fixture, try support.path(fixture.allocator, relative, "var/lib/dpkg/status"), 64 * 1024);
    const descriptor_bytes = try support.read(fixture, descriptor_relative, 8 * 1024 * 1024);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(descriptor_bytes, &digest, .{});
    const hash = try fixture.allocator.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
    const url = try std.fmt.allocPrint(fixture.allocator, "{s}/descriptor.deb{s}", .{ transport, if (network) "?token=native-query-secret" else "" });
    var arguments: std.ArrayList([]const u8) = .empty;
    try arguments.appendSlice(fixture.allocator, &.{
        "repo",           "add",           "--url",                                                                                                      url,
        "--sha256",       hash,            "--root",                                                                                                     "/",
        "--architecture", arch,            "--transaction-backend",                                                                                      "native",
        "--json",         "--deadline-ms", if (std.mem.eql(u8, case, "lock_wait")) "75" else if (std.mem.eql(u8, case, "deadline")) "15000" else "60000",
    });
    if (no_refresh) try arguments.append(fixture.allocator, "--no-refresh");
    if (std.mem.eql(u8, case, "lock_wait") or std.mem.eql(u8, case, "deadline"))
        try arguments.appendSlice(fixture.allocator, &.{
            "--connect-timeout-ms", "50", "--read-timeout-ms", "50",
        });
    const args_path = try support.path(fixture.allocator, relative, "fixture/cli-arguments.json");
    try fixture.write(args_path, try std.json.Stringify.valueAlloc(fixture.allocator, arguments.items, .{}), 0o600);
    try fixture.write(try support.path(fixture.allocator, relative, "fixture/cli-case"), case, 0o600);
    const step_path = try support.path(fixture.allocator, relative, "fixture/cli-step");
    const calls: usize = if (std.mem.eql(u8, case, "lock_wait") or
        std.mem.eql(u8, case, "lock_signal") or
        std.mem.eql(u8, case, "unsafe_runtime") or
        std.mem.eql(u8, case, "deadline")) 1 else 3;
    for (0..calls) |step| {
        const number = try std.fmt.allocPrint(fixture.allocator, "{d}", .{step});
        try fixture.write(step_path, number, 0o600);
        const phase = try std.fmt.allocPrint(fixture.allocator, "{s}-{d}", .{ name, step });
        try projected(fixture, self, root, .cli, phase, true, null);
    }
    var results: [3]api.OwnedResult = undefined;
    var count: usize = 0;
    defer for (results[0..count]) |*value| value.deinit();
    for (0..calls) |step| {
        const path = try std.fmt.allocPrint(fixture.allocator, "fixture/cli-{d}.json", .{step});
        results[step] = try resultAt(fixture, root, path);
        count += 1;
        const elapsed_path = try std.fmt.allocPrint(fixture.allocator, "{s}/fixture/cli-{d}.elapsed", .{ relative, step });
        const elapsed_bytes = try support.read(fixture, elapsed_path, 32);
        const elapsed = try std.fmt.parseInt(u64, elapsed_bytes, 10);
        if (((std.mem.eql(u8, case, "lock_wait") or std.mem.eql(u8, case, "lock_signal")) and elapsed >= 3000) or
            (std.mem.eql(u8, case, "deadline") and elapsed >= 20000))
            return error.RepositoryCliExceededExpectedDeadline;
    }
    try verifyCliScenario(fixture, root, case, results[0..count], initial_status, if (server) |running|
        running.requests
    else
        null);
    if (calls > 1) try absent(fixture, root, "fixture/descriptor.deb");
    const helper_after = try fixture.dir.statFile(fixture.io, helper_path, .{ .follow_symlinks = false });
    const helper_final = try support.read(fixture, helper_path, 8 * 1024 * 1024);
    if (helper_before.kind != .file or helper_after.kind != .file or
        helper_before.inode != helper_after.inode or
        !std.mem.eql(u8, helper_bytes, helper_final))
        return error.RepositoryCliChangedTriggerHelper;
    std.debug.print("{s}: {d} real public CLI invocations, retained evidence and bounded supervision passed\n", .{ name, calls });
}

fn cliCase(fixture: *foundation.Fixture, self: []const u8, cli: []const u8, arch: []const u8) !void {
    const name = "repository-cli-watchdog";
    const root = try makeRoot(fixture, name, arch);
    defer fixture.allocator.free(root);
    try copyRunner(fixture, root, cli, "/fixture/debz");
    const relative = root[fixture.path.len + 1 ..];
    const args_path = try support.path(fixture.allocator, relative, "fixture/cli-arguments.json");
    const case_path = try support.path(fixture.allocator, relative, "fixture/cli-case");
    const step_path = try support.path(fixture.allocator, relative, "fixture/cli-step");
    const arguments = [_][]const u8{
        "repo",   "add",           "--url",          "file:///fixture/absent.deb", "--sha256",              "0" ** 64,
        "--root", "/",             "--architecture", arch,                         "--transaction-backend", "native",
        "--json", "--deadline-ms", "60000",
    };
    const encoded = try std.json.Stringify.valueAlloc(fixture.allocator, &arguments, .{});
    try fixture.write(args_path, encoded, 0o600);
    try fixture.write(case_path, "missing_descriptor", 0o600);
    try fixture.write(step_path, "1", 0o600);
    try projected(fixture, self, root, .cli, name, true, null);
    const output = try support.path(fixture.allocator, relative, "fixture/cli-1.json");
    _ = try support.read(fixture, output, 1024 * 1024);
    try absent(fixture, root, "fixture/cli-0.json");
    try absent(fixture, root, "fixture/cli-2.json");
    const saved = try support.path(fixture.allocator, relative, "fixture/cli-1.saved");
    try fixture.dir.rename(output, fixture.dir, saved, fixture.io);
    for ([_]struct { step: []const u8, deadline: []const u8 }{
        .{ .step = "-1", .deadline = "60000" },
        .{ .step = "3", .deadline = "60000" },
        .{ .step = "0", .deadline = "115000" },
    }) |invalid| {
        const changed = [_][]const u8{
            "repo",   "add",           "--url",          "file:///fixture/absent.deb", "--sha256",              "0" ** 64,
            "--root", "/",             "--architecture", arch,                         "--transaction-backend", "native",
            "--json", "--deadline-ms", invalid.deadline,
        };
        try fixture.write(args_path, try std.json.Stringify.valueAlloc(fixture.allocator, &changed, .{}), 0o600);
        try fixture.write(step_path, invalid.step, 0o600);
        const rejected = try std.fmt.allocPrint(fixture.allocator, "repository-cli-rejected-{s}-{s}", .{ invalid.step, invalid.deadline });
        try projected(fixture, self, root, .cli, rejected, false, if (std.mem.eql(u8, invalid.deadline, "115000")) "error: UnboundedRepositoryWatchdog" else "error: InvalidRepositoryInvocation");
        for ([_][]const u8{ "fixture/cli-0.json", "fixture/cli-1.json", "fixture/cli-2.json" }) |path|
            try absent(fixture, root, path);
    }
    try fixture.dir.rename(saved, fixture.dir, output, fixture.io);
    std.debug.print("repository CLI: real child, explicit deadline +5s watchdog, single step, and pre-spawn refusals passed\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    var iterator = init.minimal.args.iterate();
    const self = iterator.next() orelse return error.MissingRunner;
    if (iterator.next()) |first| {
        if (std.mem.eql(u8, first, "--inside")) {
            const kind = iterator.next() orelse return error.MissingProjectionMode;
            const mode = std.meta.stringToEnum(Mode, kind) orelse return error.InvalidProjectionMode;
            const root = iterator.next() orelse return error.MissingProjectionRoot;
            if (iterator.next() != null) return error.InvalidArguments;
            return inside(init, allocator, root, mode);
        }
        const cli = iterator.next() orelse return error.MissingRepositoryCli;
        const runner_path = try std.fs.path.resolve(allocator, &.{ options.repository, self });
        const native_path = try std.fs.path.resolve(allocator, &.{ options.repository, first });
        const cli_path = try std.fs.path.resolve(allocator, &.{ options.repository, cli });
        var fixture_python: []const u8 = "python3";
        var selected_cli_case: ?[]const u8 = null;
        var pinned: ?[]const u8 = null;
        var projection_only = false;
        var execution_only = false;
        var cli_only = false;
        while (iterator.next()) |argument| {
            if (std.mem.eql(u8, argument, "--reference-dpkg")) {
                if (pinned != null) return error.DuplicateReference;
                pinned = iterator.next() orelse return error.MissingReferencePath;
            } else if (std.mem.eql(u8, argument, "--projection-only")) {
                projection_only = true;
            } else if (std.mem.eql(u8, argument, "--execution-only")) {
                execution_only = true;
            } else if (std.mem.eql(u8, argument, "--cli-only")) {
                cli_only = true;
            } else if (std.mem.eql(u8, argument, "--fixture-python")) {
                fixture_python = iterator.next() orelse return error.MissingFixturePython;
            } else if (std.mem.eql(u8, argument, "--cli-scenario")) {
                if (selected_cli_case != null) return error.DuplicateRepositoryScenario;
                selected_cli_case = iterator.next() orelse return error.MissingRepositoryScenario;
            } else return error.InvalidArguments;
        }
        if (selected_cli_case) |chosen| {
            if (!std.mem.eql(u8, chosen, "missing_descriptor")) {
                var found = false;
                for (cli_cases) |case| {
                    if (std.mem.eql(u8, chosen, case)) {
                        found = true;
                        break;
                    }
                }
                if (!found) return error.InvalidRepositoryScenario;
            }
        }
        if (std.mem.indexOfScalar(u8, fixture_python, '/') != null)
            fixture_python = try std.fs.path.resolve(allocator, &.{ options.repository, fixture_python });
        const selected = try selectMode(false, projection_only, execution_only, cli_only);
        const reference = try support.prerequisites(init, allocator, pinned);
        defer allocator.free(reference.architecture);
        var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
        defer fixture.deinit();
        errdefer fixture.retain = true;
        errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch |err|
            std.debug.print("host dpkg status changed after repository failure: {s}\n", .{@errorName(err)});
        if (selected == null or selected == .projection)
            try projectionCase(&fixture, runner_path, native_path, reference.architecture);
        if (selected == null or selected == .projection or selected == .execution) {
            for ([_][]const u8{ "success", "known_failure", "interrupted", "missing_helper", "unchanged", "diagnostic", "expired" }) |case|
                try executionCase(&fixture, runner_path, native_path, reference.architecture, case, false);
            for ([_][]const u8{ "success", "known_failure", "interrupted", "unchanged" }) |case|
                try executionCase(&fixture, runner_path, native_path, reference.architecture, case, true);
            try unchangedCases(&fixture, runner_path, native_path, reference.architecture);
            try dispatchCases(&fixture, runner_path, native_path, reference.architecture);
        }
        if (selected == null or selected == .projection or selected == .execution or selected == .cli) {
            for (cli_cases) |case| {
                if (selected_cli_case) |chosen| {
                    if (!std.mem.eql(u8, chosen, case)) continue;
                }
                try cliScenario(&fixture, runner_path, cli_path, reference.architecture, fixture_python, reference.executable, case);
            }
            if (selected_cli_case == null or std.mem.eql(u8, selected_cli_case.?, "missing_descriptor"))
                try cliCase(&fixture, runner_path, cli_path, reference.architecture);
        }
        try support.assertHostUnchanged(allocator, init.io, reference.before);
    } else return error.MissingNativeDriver;
}

test "repository transport rejects host roots modes and invalid watchdog before spawning" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const io = std.testing.io;
    var fixture = try foundation.Fixture.init(a, io, options.repository);
    defer fixture.deinit();
    const root = try makeRoot(&fixture, "repository-guard", "amd64");
    defer a.free(root);
    try std.testing.expectError(error.DisposableRootAndPrivatePidNamespaceRequired, privateRoot(a, io, "/", 1, 0));
    try std.testing.expectError(error.DisposableRootAndPrivatePidNamespaceRequired, privateRoot(a, io, root, 123, 0));
    try std.testing.expectError(error.DisposableRootAndPrivatePidNamespaceRequired, privateRoot(a, io, root, 1, 1000));
    try privateRoot(a, io, root, 1, 0);
    const marker = try support.path(a, root[fixture.path.len + 1 ..], ".debz-native-projection");
    defer a.free(marker);
    try fixture.write(marker, "not a projection fixture\n", 0o600);
    try std.testing.expectError(error.DisposableRootAndPrivatePidNamespaceRequired, privateRoot(a, io, root, 1, 0));
    for ([_]struct { workflow: bool, projection: bool, execution: bool, cli: bool }{
        .{ .workflow = true, .projection = true, .execution = false, .cli = false },
        .{ .workflow = true, .projection = false, .execution = true, .cli = false },
        .{ .workflow = true, .projection = false, .execution = false, .cli = true },
        .{ .workflow = false, .projection = true, .execution = true, .cli = false },
        .{ .workflow = false, .projection = true, .execution = false, .cli = true },
        .{ .workflow = false, .projection = false, .execution = true, .cli = true },
    }) |invalid|
        try std.testing.expectError(error.ProjectionFixturesMutuallyExclusive, selectMode(invalid.workflow, invalid.projection, invalid.execution, invalid.cli));
    const sentinel = try fixture.absolute("cannot-spawn");
    try fixture.write("cannot-spawn", "#!/bin/sh\nexit 99\n", 0o755);
    for ([_]Mode{ .projection, .execution, .cli }) |mode| {
        try std.testing.expectError(error.DisposableRootAndPrivatePidNamespaceRequired, projected(&fixture, sentinel, "/", mode, "repository-host-root-refused", false, null));
        try support.absent(&fixture, "repository-host-root-refused.log");
    }
    const args = [_][]const u8{ "repo", "add", "--deadline-ms", "60000" };
    try std.testing.expectEqual(@as(u64, 65), try cliWatchdog(&args, 1, "success"));
    try std.testing.expectEqual(@as(u64, 20), try cliWatchdog(&.{ "--deadline-ms", "15000" }, 0, "deadline"));
    try std.testing.expectError(error.InvalidRepositoryInvocation, cliWatchdog(&args, -1, "success"));
    try std.testing.expectError(error.InvalidRepositoryInvocation, cliWatchdog(&args, 3, "success"));
    try std.testing.expectError(error.UnboundedRepositoryWatchdog, cliWatchdog(&.{ "--deadline-ms", "115000" }, 0, "success"));
    try support.absent(&fixture, try support.path(a, root[fixture.path.len + 1 ..], "fixture/cli-0.json"));
}

test "repository network evidence scans large files and split secrets" {
    const a = std.testing.allocator;
    var fixture = try foundation.Fixture.init(a, std.testing.io, options.repository);
    defer fixture.deinit();
    const root = try fixture.makeRoot("repository-secret-scan/root", "amd64");
    defer a.free(root);
    const path = try support.path(a, root[fixture.path.len + 1 ..], "var/lib/debz/query-artifact.bin");
    defer a.free(path);
    const secret = "native-query-secret";
    const bytes = try a.alloc(u8, 2 * 1024 * 1024 + 2 * 64 * 1024);
    defer a.free(bytes);
    @memset(bytes, 'x');
    try fixture.write(path, bytes, 0o600);
    try assertNoQuerySecret(&fixture, root);
    for ([_]usize{ 64 * 1024 - 7, 2 * 1024 * 1024 + 64 * 1024 - 7 }) |offset| {
        @memcpy(bytes[offset .. offset + secret.len], secret);
        try fixture.write(path, bytes, 0o600);
        try std.testing.expectError(error.NetworkFixtureLeakedCredential, assertNoQuerySecret(&fixture, root));
        @memset(bytes[offset .. offset + secret.len], 'x');
    }
    try fixture.write(path, bytes, 0o600);
    try assertNoQuerySecret(&fixture, root);
}
