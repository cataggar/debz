const std = @import("std");
const testing = std.testing;
const support = @import("tooling-test-support.zig");

const uri = "https://snapshot.ubuntu.com/ubuntu/20260923T000000Z";

const Scenario = struct {
    name: []const u8 = "",
    trace: bool = false,
    execve: []const u8 = "",
    injected_execve: []const u8 = "",
    no_trace: bool = false,
    execveat: bool = false,
};

var fixture_compiled = false;

const Driver = struct {
    work: support.Work,
    script: []const u8,
    keyring: []const u8,
    workspace: []const u8,
    executable: []const u8,
    arch: []const u8,

    fn init() !Driver {
        var work = try support.Work.init();
        errdefer work.deinit();
        try work.write("fixture-keyring.gpg", "offline fixture; not archive trust material");
        const executable = try work.path("fixture-cli");
        errdefer support.allocator.free(executable);
        const keyring = try work.path("fixture-keyring.gpg");
        errdefer support.allocator.free(keyring);
        const workspace = try work.path(".real-snapshot/fresh");
        errdefer support.allocator.free(workspace);
        var path_buf: [std.fs.max_path_bytes]u8 = undefined;
        const len = try std.Io.Dir.cwd().realPathFile(support.io, ".", &path_buf);
        const script = try std.fmt.allocPrint(support.allocator, "{s}/tools/real-snapshot-acceptance.sh", .{path_buf[0..len]});
        errdefer support.allocator.free(script);
        const fixture_script = try std.fmt.allocPrint(support.allocator, "#!/bin/sh\nprintf called > '{s}/called'\nexit 77\n", .{work.root});
        defer support.allocator.free(fixture_script);
        try work.write("fixture-cli", fixture_script);
        const mode = try support.run(&.{ "chmod", "0700", executable });
        defer mode.deinit();
        try mode.ok();
        return .{
            .work = work,
            .script = script,
            .keyring = keyring,
            .workspace = workspace,
            .executable = executable,
            .arch = if (@import("builtin").cpu.arch == .aarch64) "arm64" else "amd64",
        };
    }

    fn deinit(self: *Driver) void {
        support.allocator.free(self.script);
        support.allocator.free(self.keyring);
        support.allocator.free(self.workspace);
        support.allocator.free(self.executable);
        self.work.deinit();
    }

    fn run(self: *Driver, keyring: []const u8, args: []const []const u8) !support.Result {
        const variable = try std.fmt.allocPrint(support.allocator, "DEBZ_REAL_SNAPSHOT_KEYRING={s}", .{keyring});
        defer support.allocator.free(variable);
        var argv: [12][]const u8 = undefined;
        argv[0] = "env";
        argv[1] = variable;
        argv[2] = "bash";
        argv[3] = self.script;
        for (args, 0..) |arg, index| argv[4 + index] = arg;
        return support.runIn(argv[0 .. 4 + args.len], .{ .path = self.work.root });
    }

    fn validate(self: *Driver, keyring: []const u8) !support.Result {
        return self.run(keyring, &.{ "--validate", uri, "stonking", self.arch });
    }

    fn accept(self: *Driver, workspace: []const u8) !support.Result {
        return self.run(self.keyring, &.{ self.executable, uri, "stonking", self.arch, workspace });
    }

    fn initOffline() !Driver {
        var driver = try Driver.init();
        errdefer driver.deinit();
        const cwd = try std.process.currentPathAlloc(support.io, support.allocator);
        defer support.allocator.free(cwd);
        const binary = try std.fmt.allocPrint(support.allocator,
            "{s}/.zig-cache/issue-214-snapshot-fixture-{s}",
            .{ cwd, if (@import("builtin").mode == .ReleaseSafe) "ReleaseSafe" else "Debug" });
        errdefer support.allocator.free(binary);
        if (!fixture_compiled) {
            const binary_arg = try std.fmt.allocPrint(support.allocator, "-femit-bin={s}", .{binary});
            defer support.allocator.free(binary_arg);
            const compiled = try support.runWithTimeout(&.{
                "zig", "build-exe", "test/real-snapshot-fixture-cli.zig", "-O",
                if (@import("builtin").mode == .ReleaseSafe) "ReleaseSafe" else "Debug",
                binary_arg,
            }, .inherit, 120);
            defer compiled.deinit();
            try compiled.ok();
            fixture_compiled = true;
        }
        support.allocator.free(driver.executable);
        driver.executable = binary;
        try driver.work.write("strace",
            \\#!/usr/bin/env bash
            \\set -euo pipefail
            \\[[ $# -ge 8 && "$1" == -f && "$2" == -qq && "$3" == -yy &&
            \\   "$4" == -e && "$5" == trace=execve,execveat && "$6" == -o ]]
            \\output=$7
            \\shift 7
            \\traced=${SNAPSHOT_TEST_EXECVE:-$1}
            \\if [[ " $* " == *injected-invalid.lock.json* ]]; then
            \\  traced=${SNAPSHOT_TEST_INJECTED_EXECVE:-$traced}
            \\fi
            \\if [[ ${SNAPSHOT_TEST_NO_TRACE:-0} != 1 ]]; then
            \\  if [[ ${SNAPSHOT_TEST_EXECVEAT:-0} == 1 ]]; then
            \\    printf 'execveat(3<%s>, "", [], [], AT_EMPTY_PATH) = 0\n' "$traced" >"$output"
            \\  else
            \\    printf 'execve("%s", [...], [...]) = 0\n' "$traced" >"$output"
            \\  fi
            \\fi
            \\exec "$@"
            ++ "\n");
        const strace_path = try driver.work.path("strace");
        defer support.allocator.free(strace_path);
        const executable = try support.run(&.{ "chmod", "0700", strace_path });
        defer executable.deinit();
        try executable.ok();
        return driver;
    }

    fn offline(self: *Driver, config: Scenario) !support.Result {
        const key = try std.fmt.allocPrint(support.allocator, "DEBZ_REAL_SNAPSHOT_KEYRING={s}", .{self.keyring});
        defer support.allocator.free(key);
        const calls_path = try self.work.path("calls.jsonl");
        defer support.allocator.free(calls_path);
        const calls = try std.fmt.allocPrint(support.allocator, "SNAPSHOT_TEST_CALLS={s}", .{calls_path});
        defer support.allocator.free(calls);
        const name = try std.fmt.allocPrint(support.allocator, "SNAPSHOT_TEST_SCENARIO={s}", .{config.name});
        defer support.allocator.free(name);
        const execve = try std.fmt.allocPrint(support.allocator, "SNAPSHOT_TEST_EXECVE={s}", .{config.execve});
        defer support.allocator.free(execve);
        const injected = try std.fmt.allocPrint(support.allocator, "SNAPSHOT_TEST_INJECTED_EXECVE={s}", .{config.injected_execve});
        defer support.allocator.free(injected);
        const inherited = try support.run(&.{ "printenv", "PATH" });
        defer inherited.deinit();
        try inherited.ok();
        const inherited_path = std.mem.trimEnd(u8, inherited.stdout, "\n");
        if (inherited_path.len > 16 * 1024) return error.PathTooLong;
        const path = try std.fmt.allocPrint(support.allocator, "PATH={s}:{s}", .{ self.work.root, inherited_path });
        defer support.allocator.free(path);
        return support.runIn(&.{
            "env", key, calls, name, path, execve, injected,
            if (config.trace) "DEBZ_REAL_SNAPSHOT_TRACE=1" else "DEBZ_REAL_SNAPSHOT_TRACE=0",
            if (config.no_trace) "SNAPSHOT_TEST_NO_TRACE=1" else "SNAPSHOT_TEST_NO_TRACE=0",
            if (config.execveat) "SNAPSHOT_TEST_EXECVEAT=1" else "SNAPSHOT_TEST_EXECVEAT=0",
            "bash", self.script, self.executable, uri, "stonking", self.arch, self.workspace,
        }, .{ .path = self.work.root });
    }
};

test "snapshot: fixed offline inputs accept native architecture and refuse mutable URI, suite, or mismatch" {
    var f = try Driver.init();
    defer f.deinit();
    const valid = try f.run(f.keyring, &.{ "--validate-values", uri, "stonking", f.arch });
    defer valid.deinit();
    try valid.ok();
    for ([_]struct { uri_arg: []const u8, suite: []const u8, arch: []const u8 }{
        .{ .uri_arg = "https://snapshot.ubuntu.com/ubuntu/latest", .suite = "stonking", .arch = "amd64" },
        .{ .uri_arg = uri, .suite = "unreviewed", .arch = "amd64" },
        .{ .uri_arg = uri, .suite = "stonking", .arch = "i386" },
    }) |invalid| {
        const result = try f.run(f.keyring, &.{ "--validate-values", invalid.uri_arg, invalid.suite, invalid.arch });
        defer result.deinit();
        try testing.expect(result.code != 0);
    }
    const wrong_arch = if (std.mem.eql(u8, f.arch, "amd64")) "arm64" else "amd64";
    const mismatch = try f.run(f.keyring, &.{ "--validate", uri, "stonking", wrong_arch });
    defer mismatch.deinit();
    try mismatch.failsWith("native runner architecture does not match");
}

test "snapshot: explicit regular keyring rejects missing, relative, directory and symlink paths" {
    var f = try Driver.init();
    defer f.deinit();
    const good = try f.validate(f.keyring);
    defer good.deinit();
    try good.ok();
    const link = try f.work.path("linked.gpg");
    defer support.allocator.free(link);
    try f.work.directory.dir.symLink(support.io, f.keyring, "linked.gpg", .{});
    const missing = try f.work.path("missing.gpg");
    defer support.allocator.free(missing);
    for ([_][]const u8{ missing, f.work.root, link, "fixture-keyring.gpg" }) |invalid| {
        const result = try f.validate(invalid);
        defer result.deinit();
        try result.failsWith("explicit regular Ubuntu archive keyring");
    }
}

test "snapshot: existing directory and dangling symlink refuse before fixture CLI or mutation" {
    var f = try Driver.init();
    defer f.deinit();
    try f.work.directory.dir.createDirPath(support.io, ".real-snapshot/fresh");
    try f.work.write(".real-snapshot/fresh/retained", "unchanged");
    const existing = try f.accept(f.workspace);
    defer existing.deinit();
    try existing.failsWith("snapshot workspace must be new");
    const marker = try f.work.read(".real-snapshot/fresh/retained");
    defer support.allocator.free(marker);
    try testing.expectEqualStrings("unchanged", marker);
    try testing.expectError(error.FileNotFound, f.work.read("called"));
    try f.work.directory.dir.deleteTree(support.io, ".real-snapshot/fresh");
    try f.work.directory.dir.symLink(support.io, "missing", ".real-snapshot/fresh", .{});
    const dangling = try f.accept(f.workspace);
    defer dangling.deinit();
    try dangling.failsWith("snapshot workspace must be new");
    try testing.expectError(error.FileNotFound, f.work.read("called"));
    try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/missing"));
}

test "snapshot: workspace outside repository's disposable namespace refuses before CLI" {
    var f = try Driver.init();
    defer f.deinit();
    const unsafe_path = try f.work.path("outside");
    defer support.allocator.free(unsafe_path);
    const result = try f.accept(unsafe_path);
    defer result.deinit();
    try result.failsWith("unsafe workspace");
    try testing.expectError(error.FileNotFound, f.work.read("called"));
    try testing.expectError(error.FileNotFound, f.work.read("outside"));
}

test "snapshot: offline native creation and zero-action update preserve evidence, lock usage and receipt" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const result = try f.offline(.{});
    defer result.deinit();
    try result.ok();
    const provenance = try f.work.read(".real-snapshot/fresh/evidence/create-native-transaction-provenance-v2.json");
    defer support.allocator.free(provenance);
    try support.contains(provenance, "\"outcome\":\"succeeded\"");
    const update = try f.work.read(".real-snapshot/fresh/evidence/update.json");
    defer support.allocator.free(update);
    try support.contains(update, "\"changed\":false");
    const before = try f.work.read(".real-snapshot/fresh/evidence/fresh-root-before.txt");
    defer support.allocator.free(before);
    try testing.expectEqualStrings(
        "install_root_exists=true\ndpkg_database_present=false\nhelper_placeholder_present=false\npackage_state_present=false\n",
        before,
    );
    const zero = try f.work.read(".real-snapshot/fresh/evidence/update-zero-actions.txt");
    defer support.allocator.free(zero);
    try testing.expectEqualStrings("changed=false\nstatus_unchanged=true\nprovenance_unchanged=true\n", zero);
    const config = try f.work.read(".real-snapshot/fresh/ubuntu.json");
    defer support.allocator.free(config);
    try support.contains(config, "\"maximum_release_age_seconds\":2678400");
    const log = try f.work.read("calls.jsonl");
    defer support.allocator.free(log);
    try support.contains(log, "[\"transaction-result\",\"verify\"");
    try support.contains(log, "\"--transaction-backend\",\"native\"");
    try support.contains(log, "\"--lock-output\",");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, log, "[\"transaction-result\",\"verify\""));
    const install_lock = try f.work.path(".real-snapshot/fresh/evidence/ubuntu-minimal.lock.json");
    defer support.allocator.free(install_lock);
    const update_lock = try f.work.path(".real-snapshot/fresh/evidence/ubuntu-minimal.update.lock.json");
    defer support.allocator.free(update_lock);
    var lines = std.mem.splitScalar(u8, log, '\n');
    var verifications: usize = 0;
    var update_plans: usize = 0;
    var mutating: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parsed = try std.json.parseFromSlice([]const []const u8, support.allocator, line, .{});
        defer parsed.deinit();
        const args = parsed.value;
        if (std.mem.eql(u8, args[0], "transaction-result")) {
            verifications += 1;
            try testing.expect(args.len > 1 and std.mem.eql(u8, args[1], "verify"));
            try testing.expect(hasArgument(args, install_lock));
            try testing.expect(hasArgument(args, "--transaction-backend") and hasArgument(args, "native"));
        }
        if (std.mem.eql(u8, args[0], "plan") and hasArgument(args, update_lock)) {
            update_plans += 1;
            try testing.expect(!hasArgument(args, "ubuntu-minimal"));
            try testing.expect(!hasArgument(args, "--lock-input"));
        }
        if (std.mem.eql(u8, args[0], "install") or std.mem.eql(u8, args[0], "upgrade-all")) {
            mutating += 1;
            try testing.expect(hasArgument(args, "--transaction-backend") and hasArgument(args, "native"));
        }
    }
    try testing.expectEqual(@as(usize, 1), verifications);
    try testing.expectEqual(@as(usize, 1), update_plans);
    try testing.expectEqual(@as(usize, 2), mutating);
}

fn hasArgument(args: []const []const u8, value: []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, value)) return true;
    }
    return false;
}

fn expectOperations(f: *Driver, expected: []const []const u8) !void {
    const bytes = try f.work.read("calls.jsonl");
    defer support.allocator.free(bytes);
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    var index: usize = 0;
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var parsed = try std.json.parseFromSlice([]const []const u8, support.allocator, line, .{});
        defer parsed.deinit();
        if (index >= expected.len) {
            std.debug.print("unexpected operation '{s}' at index {d}\n", .{ parsed.value[0], index });
            return error.ExtraOperation;
        }
        try testing.expectEqualStrings(expected[index], parsed.value[0]);
        index += 1;
    }
    try testing.expectEqual(expected.len, index);
}

test "snapshot: unreviewed initial signer refuses before any download" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const refused = try f.offline(.{ .name = "unreviewed-signer" });
    defer refused.deinit();
    try testing.expect(refused.code != 0);
    try expectOperations(&f, &.{ "refresh", "plan" });
    try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/download.json"));
}

test "snapshot: failed receipt and unreviewed update signer refuse before update" {
    {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(.{ .name = "failed-verification" });
        defer refused.deinit();
        try testing.expect(refused.code != 0);
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/create-transaction-result.json"));
    }
    {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(.{ .name = "unreviewed-update-signer" });
        defer refused.deinit();
        try testing.expect(refused.code != 0);
        try expectOperations(&f, &.{
            "refresh", "plan", "download", "install", "transaction-result", "plan", "plan",
        });
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/update.json"));
    }
}

test "snapshot: status mutation and package-owned excluded device cannot produce zero-action evidence" {
    {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(.{ .name = "changed-status" });
        defer refused.deinit();
        try testing.expect(refused.code != 0);
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/update-zero-actions.txt"));
    }
    {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(.{ .name = "owned-excluded-device" });
        defer refused.deinit();
        try refused.failsWith("candidate package claims excluded chroot device");
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/update.json"));
    }
}

test "snapshot: bounded retry diagnostics remain evidence, unexpected stderr fails refresh" {
    {
        var f = try Driver.initOffline();
        defer f.deinit();
        const accepted = try f.offline(.{ .name = "retry-log" });
        defer accepted.deinit();
        try accepted.ok();
        for ([_][]const u8{ "refresh", "download" }) |name| {
            const path = try std.fmt.allocPrint(support.allocator, ".real-snapshot/fresh/evidence/{s}.stderr", .{name});
            defer support.allocator.free(path);
            const log = try f.work.read(path);
            defer support.allocator.free(log);
            try testing.expectEqualStrings(
                "debz acquisition retry failed_attempt=1/6 delay_ms=2000 http_status=503\n",
                log,
            );
        }
    }
    {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(.{ .name = "unexpected-stderr" });
        defer refused.deinit();
        try refused.failsWith("unexpected candidate stderr during refresh");
        try expectOperations(&f, &.{"refresh"});
    }
}

test "snapshot: failed traced refresh reports freshness while no forbidden native exec occurs" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const expired = try f.offline(.{ .name = "freshness-failure", .trace = true });
    defer expired.deinit();
    try testing.expectEqual(@as(u8, 4), expired.code);
    try expectOperations(&f, &.{"refresh"});
    const audit = try f.work.read(".real-snapshot/fresh/evidence/native-exec-audit.txt");
    defer support.allocator.free(audit);
    try testing.expectEqualStrings("operation=refresh\nexit_status=4\nforbidden_dpkg_exec=false\n", audit);
    const refresh = try f.work.read(".real-snapshot/fresh/evidence/refresh.json");
    defer support.allocator.free(refresh);
    try support.contains(refresh, "\"summary\":\"ReleaseExpired\"");
    var root = try f.work.directory.dir.openDir(support.io, ".real-snapshot/fresh/root", .{ .iterate = true });
    defer root.close(support.io);
    var iterator = root.iterate();
    try testing.expect((try iterator.next(support.io)) == null);
}

test "snapshot: trace rejects forbidden dpkg execve and descriptor execveat even on failed refresh" {
    for ([_]Scenario{
        .{ .name = "freshness-failure", .trace = true, .execve = "/usr/bin/dpkg" },
        .{ .name = "freshness-failure", .trace = true, .execve = "/usr/local/bin/dpkg-deb", .execveat = true },
    }) |scenario| {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(scenario);
        defer refused.deinit();
        try testing.expectEqual(@as(u8, 90), refused.code);
        try expectOperations(&f, &.{"refresh"});
        const audit = try f.work.read(".real-snapshot/fresh/evidence/native-exec-audit.txt");
        defer support.allocator.free(audit);
        try testing.expectEqualStrings("operation=refresh\nexit_status=4\nforbidden_dpkg_exec=true\n", audit);
    }
}

test "snapshot: missing trace refuses failed command and invalid-lock probe audits dpkg-deb" {
    {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(.{ .name = "freshness-failure", .trace = true, .no_trace = true });
        defer refused.deinit();
        try testing.expectEqual(@as(u8, 91), refused.code);
        try support.contains(refused.stderr, "candidate execution trace missing");
        try expectOperations(&f, &.{"refresh"});
    }
    {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(.{ .trace = true, .injected_execve = "/opt/pinned/bin/dpkg-deb" });
        defer refused.deinit();
        try testing.expectEqual(@as(u8, 90), refused.code);
        const audit = try f.work.read(".real-snapshot/fresh/evidence/native-exec-audit.txt");
        defer support.allocator.free(audit);
        try support.contains(audit, "operation=injected-failure\nexit_status=5\nforbidden_dpkg_exec=true\n");
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/injected-failure.txt"));
    }
}

test "snapshot: reference rejects corrupt cached archive before creating root or snapshot" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const accepted = try f.offline(.{});
    defer accepted.deinit();
    try accepted.ok();
    const lock_relative = ".real-snapshot/fresh/evidence/ubuntu-minimal.lock.json";
    const lock = try f.work.path(lock_relative);
    defer support.allocator.free(lock);
    const objects = ".real-snapshot/fresh/cache/packages-v2/objects";
    try f.work.directory.dir.createDirPath(support.io, objects);
    const zeros: [128]u8 = @splat('0');
    const archive = try std.fmt.allocPrint(support.allocator, "{s}/sha512-{s}", .{ objects, zeros });
    defer support.allocator.free(archive);
    try f.work.write(archive, "x");
    var packages: std.ArrayList(u8) = .empty;
    defer packages.deinit(support.allocator);
    for ([_][]const u8{ "libc6", "dash", "coreutils", "dpkg" }, 0..) |name, index| {
        const item = try std.fmt.allocPrint(support.allocator,
            "{{\"name\":\"{s}\",\"version\":\"1\",\"architecture\":\"{s}\",\"declared_size\":1,\"archive_identity\":{{\"primary\":\"sha512\",\"digests\":[{{\"algorithm\":\"sha512\",\"digest\":\"{s}\"}}]}}}}{s}",
            .{ name, f.arch, zeros, if (index == 3) "" else "," });
        defer support.allocator.free(item);
        try packages.appendSlice(support.allocator, item);
    }
    const lock_text = try std.fmt.allocPrint(support.allocator,
        "{{\"schema\":\"https://debz.dev/schema/exact-closure-lock-v3\",\"version\":3,\"target_architecture\":\"{s}\",\"packages\":[{s}]}}\n",
        .{ f.arch, packages.items });
    defer support.allocator.free(lock_text);
    try f.work.write(lock_relative, lock_text);
    const reference = try std.fmt.allocPrint(support.allocator, "{s}/tools/real-snapshot-reference.sh", .{
        f.script[0 .. f.script.len - "tools/real-snapshot-acceptance.sh".len],
    });
    defer support.allocator.free(reference);
    const cache = try f.work.path(".real-snapshot/fresh/cache");
    defer support.allocator.free(cache);
    const refused = try support.runIn(&.{
        "bash", reference, f.executable, lock,
        cache, f.arch, f.workspace,
    }, .{ .path = f.work.root });
    defer refused.deinit();
    try testing.expect(refused.code != 0);
    try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/reference.snapshot.json"));
    try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/reference-root"));
}

fn source(path: []const u8) ![]u8 {
    return std.Io.Dir.cwd().readFileAlloc(support.io, path, support.allocator, .limited(128 * 1024));
}

test "snapshot: manual two-architecture CI workflow retains opt-in, artifact bounds, cleanup, and comparison" {
    const workflow = try source(".github/workflows/ci.yml");
    defer support.allocator.free(workflow);
    const start = std.mem.indexOf(u8, workflow, "  ubuntu-real-snapshot:\n") orelse return error.MissingSnapshotJob;
    const job = workflow[start..];
    for ([_][]const u8{
        "if: github.event_name == 'workflow_dispatch' && inputs.run_native_real_snapshot",
        "timeout-minutes: 90",
        "- architecture: amd64",
        "- architecture: arm64",
        "real-snapshot-acceptance.sh --validate",
        "real-snapshot-acceptance.sh \"$PWD/zig-out/bin/debz\"",
        "real-snapshot-reference.sh \"$REFERENCE_DPKG\"",
        "real-snapshot-comparator compare",
        "comparison-unavailable.txt",
        "if [ -f \"$evidence/reference.snapshot.json\" ]",
        "[ -f \"$evidence/native.snapshot.json\" ]; then",
        "one evidence member exceeds 128 MiB",
        "artifact-summary.txt",
        "sudo rm -rf \"$work/root\" \"$work/cache\"",
        "sudo rm -rf \"$work/reference-root\"",
        "name: ubuntu-real-snapshot-${{ matrix.architecture }}",
        "path: .real-snapshot/${{ matrix.architecture }}/evidence/",
    }) |required| try support.contains(job, required);
    try testing.expect(std.mem.indexOf(u8, workflow[0..start], "schedule:\n") != null);
}

test "snapshot: runner bounds and native backend safety checks remain explicit" {
    const runner = try source("tools/real-snapshot-acceptance.sh");
    defer support.allocator.free(runner);
    for ([_][]const u8{
        "max_download_bytes=$((1536 * 1024 * 1024))",
        "max_package_bytes=$((512 * 1024 * 1024))",
        "max_cache_bytes=$((2 * 1024 * 1024 * 1024))",
        "maximum_release_age_seconds=$((31 * 24 * 60 * 60))",
        "DEBZ_REAL_SNAPSHOT_KEYRING",
        "trace=execve,execveat",
        "candidate execution trace missing",
        "forbidden_dpkg_exec=true",
        "unexpected candidate stderr during",
        "candidate package claims excluded chroot device",
        "update-zero-actions.txt",
    }) |required| try support.contains(runner, required);
}
