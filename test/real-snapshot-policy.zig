const std = @import("std");
const testing = std.testing;
const support = @import("tooling-test-support.zig");

const uri = "https://snapshot.ubuntu.com/ubuntu/20261001T000000Z";
const audit_no_calls = "allowed_script_dpkg_exec=0\nallowed_script_dpkg_divert_exec=0\nallowed_script_dpkg_statoverride_exec=0\n";

const Scenario = struct {
    name: []const u8 = "",
    trace: bool = false,
    execve: []const u8 = "",
    injected_execve: []const u8 = "",
    no_trace: bool = false,
    execveat: bool = false,
    script_dpkg: bool = false,
    script_tools: bool = false,
    progress_limit_seconds: []const u8 = "",
    ceiling_seconds: []const u8 = "",
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
        const source_script = try std.fmt.allocPrint(support.allocator, "{s}/tools/real-snapshot-acceptance.sh", .{path_buf[0..len]});
        defer support.allocator.free(source_script);
        const script_bytes = try std.Io.Dir.cwd().readFileAlloc(support.io, source_script, support.allocator, .limited(support.maximum_file_bytes));
        defer support.allocator.free(script_bytes);
        try work.write("tools/real-snapshot-acceptance.sh", script_bytes);
        const reference_bytes = try std.Io.Dir.cwd().readFileAlloc(support.io, "tools/real-snapshot-reference.sh", support.allocator, .limited(support.maximum_file_bytes));
        defer support.allocator.free(reference_bytes);
        try work.write("tools/real-snapshot-reference.sh", reference_bytes);
        // Offline sequencing fixture only; production trust refusals and
        // descriptor checks are exercised by the protected-CI Python tests.
        try work.write("tools/real-snapshot-reference-protected-ci.sh",
            \\#!/usr/bin/env bash
            \\[[ $# == 2 && $1 == --check-keyring && -f $2 && ! -L $2 ]] || exit 2
        ++ "\n");
        try work.write("tools/real_snapshot_reference_paths.py",
            \\def protected(path, directory=False):
            \\    if not path.is_absolute():
            \\        raise ValueError(f"reference path is not absolute: {path}")
            \\    return path.stat()
        ++ "\n");
        try work.directory.dir.createDirPath(support.io, ".real-snapshot");
        const script = try work.path("tools/real-snapshot-acceptance.sh");
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
        return self.run(keyring, &.{ "--validate", uri, "resolute", self.arch });
    }

    fn accept(self: *Driver, workspace: []const u8) !support.Result {
        return self.run(self.keyring, &.{ self.executable, uri, "resolute", self.arch, workspace });
    }

    fn initOffline() !Driver {
        var driver = try Driver.init();
        errdefer driver.deinit();
        const cwd = try std.process.currentPathAlloc(support.io, support.allocator);
        defer support.allocator.free(cwd);
        const binary = try std.fmt.allocPrint(support.allocator, "{s}/.zig-cache/issue-214-snapshot-fixture-{s}", .{ cwd, if (@import("builtin").mode == .ReleaseSafe) "ReleaseSafe" else "Debug" });
        errdefer support.allocator.free(binary);
        if (!fixture_compiled) {
            const binary_arg = try std.fmt.allocPrint(support.allocator, "-femit-bin={s}", .{binary});
            defer support.allocator.free(binary_arg);
            const compiled = try support.runWithTimeout(&.{
                "zig",                                                                   "build-exe", "test/real-snapshot-fixture-cli.zig", "-O",
                if (@import("builtin").mode == .ReleaseSafe) "ReleaseSafe" else "Debug", binary_arg,
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
            \\reviewed=(-f --seccomp-bpf -qq -yy -s 4096 --pidns-translation -e signal=none
            \\  -e trace=execve,execveat,fork,vfork,clone,clone3 -o)
            \\(( $# > ${#reviewed[@]} + 1 )) && [[ "${*:1:${#reviewed[@]}}" == "${reviewed[*]}" ]]
            \\shift ${#reviewed[@]}
            \\output=$1
            \\shift
            \\traced=${SNAPSHOT_TEST_EXECVE:-$1}
            \\if [[ " $* " == *injected-invalid.lock.json* ]]; then
            \\  traced=${SNAPSHOT_TEST_INJECTED_EXECVE:-$traced}
            \\fi
            \\if [[ ${SNAPSHOT_TEST_NO_TRACE:-0} != 1 ]]; then
            \\  if [[ ${SNAPSHOT_TEST_EXECVEAT:-0} == 1 ]]; then
            \\    printf '%s execveat(3<%s>, "", ["dpkg-deb"], 0x1 /* 1 var */, AT_EMPTY_PATH) = 0\n' \
            \\      "$$" "$traced" >"$output"
            \\  else
            \\    printf '%s execve("%s", ["%s", "--print-architecture"], 0x1 /* 1 var */) = 0\n' \
            \\      "$$" "$traced" "${traced##*/}" >"$output"
            \\  fi
            \\  if [[ ${SNAPSHOT_TEST_SCRIPT_DPKG:-0} == 1 ]]; then
            \\    script=/var/lib/debz-lifecycle-scripts/tzdata.postinst
            \\    printf '%s\n' "$$ clone(child_stack=NULL, flags=SIGCHLD) = 9001" \
            \\      "9001 execve(\"$script\", [\"$script\", \"configure\"], 0x1 /* 1 var */) = 0" \
            \\      '9001 vfork() = 9002' \
            \\      '9002 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0' >>"$output"
            \\  fi
            \\  if [[ ${SNAPSHOT_TEST_SCRIPT_TOOLS:-0} == 1 ]]; then
            \\    script=/var/lib/debz-lifecycle-scripts/chrony.postinst
            \\    printf '%s\n' "$$ clone(child_stack=NULL, flags=SIGCHLD) = 9011" \
            \\      "9011 execve(\"$script\", [\"$script\", \"configure\", \"\"], 0x1 /* 1 var */) = 0" \
            \\      '9011 vfork() = 9012' \
            \\      '9012 execve("/usr/bin/dpkg-divert", ["dpkg-divert", "--truename", "/bin/ping"], 0x1 /* 1 var */) = 0' \
            \\      '9011 vfork() = 9013' \
            \\      '9013 execve("/usr/bin/dpkg-statoverride", ["dpkg-statoverride", "--list", "/var/lib/chrony"], 0x1 /* 1 var */) = 0' >>"$output"
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
        const progress_limit = try std.fmt.allocPrint(support.allocator, "DEBZ_REAL_SNAPSHOT_INSTALL_PROGRESS_LIMIT_SECONDS={s}", .{config.progress_limit_seconds});
        defer support.allocator.free(progress_limit);
        const ceiling = try std.fmt.allocPrint(support.allocator, "DEBZ_REAL_SNAPSHOT_INSTALL_CEILING_SECONDS={s}", .{config.ceiling_seconds});
        defer support.allocator.free(ceiling);
        const inherited = try support.run(&.{ "printenv", "PATH" });
        defer inherited.deinit();
        try inherited.ok();
        const inherited_path = std.mem.trimEnd(u8, inherited.stdout, "\n");
        if (inherited_path.len > 16 * 1024) return error.PathTooLong;
        const path = try std.fmt.allocPrint(support.allocator, "PATH={s}:{s}", .{ self.work.root, inherited_path });
        defer support.allocator.free(path);
        return support.runIn(&.{
            "env",                                                                            key,                                                                             calls,                                                                           name,                                                                                     path,                                                                                        execve, injected,    progress_limit,  ceiling,
            if (config.trace) "DEBZ_REAL_SNAPSHOT_TRACE=1" else "DEBZ_REAL_SNAPSHOT_TRACE=0", if (config.no_trace) "SNAPSHOT_TEST_NO_TRACE=1" else "SNAPSHOT_TEST_NO_TRACE=0", if (config.execveat) "SNAPSHOT_TEST_EXECVEAT=1" else "SNAPSHOT_TEST_EXECVEAT=0", if (config.script_dpkg) "SNAPSHOT_TEST_SCRIPT_DPKG=1" else "SNAPSHOT_TEST_SCRIPT_DPKG=0", if (config.script_tools) "SNAPSHOT_TEST_SCRIPT_TOOLS=1" else "SNAPSHOT_TEST_SCRIPT_TOOLS=0", "bash", self.script, self.executable, uri,
            "resolute",                                                                       self.arch,                                                                       self.workspace,
        }, .{ .path = self.work.root });
    }
};

test "snapshot: fixed offline inputs accept native architecture and refuse mutable URI, suite, or mismatch" {
    var f = try Driver.init();
    defer f.deinit();
    const valid = try f.run(f.keyring, &.{ "--validate-values", uri, "resolute", f.arch });
    defer valid.deinit();
    try valid.ok();
    for ([_]struct { uri_arg: []const u8, suite: []const u8, arch: []const u8 }{
        .{ .uri_arg = "https://snapshot.ubuntu.com/ubuntu/latest", .suite = "resolute", .arch = "amd64" },
        .{ .uri_arg = uri, .suite = "unreviewed", .arch = "amd64" },
        .{ .uri_arg = uri, .suite = "resolute", .arch = "i386" },
    }) |invalid| {
        const result = try f.run(f.keyring, &.{ "--validate-values", invalid.uri_arg, invalid.suite, invalid.arch });
        defer result.deinit();
        try testing.expect(result.code != 0);
    }
    const wrong_arch = if (std.mem.eql(u8, f.arch, "amd64")) "arm64" else "amd64";
    const mismatch = try f.run(f.keyring, &.{ "--validate", uri, "resolute", wrong_arch });
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

test "snapshot: production acceptance refuses the unprotected offline trust fixture" {
    var f = try Driver.init();
    defer f.deinit();
    const key = try std.fmt.allocPrint(support.allocator, "DEBZ_REAL_SNAPSHOT_KEYRING={s}", .{f.keyring});
    defer support.allocator.free(key);
    const result = try support.run(&.{
        "env", key, "bash", "tools/real-snapshot-acceptance.sh", "--validate", uri, "resolute", f.arch,
    });
    defer result.deinit();
    try result.failsWith("writable or non-root ancestor");
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
    const frozen_config = try f.work.read(".real-snapshot/fresh/config/resolute.json");
    defer support.allocator.free(frozen_config);
    try support.contains(frozen_config, "\"mode\":\"frozen_release_with_witnesses\"");
    try support.contains(frozen_config, "\"witness_suites\":[\"resolute-updates\",\"resolute-security\"]");
    const updates_config = try f.work.read(".real-snapshot/fresh/config/resolute-updates.json");
    defer support.allocator.free(updates_config);
    try support.contains(updates_config, "\"maximum_release_age_seconds\":2678400");
    const security_config = try f.work.read(".real-snapshot/fresh/config/resolute-security.json");
    defer support.allocator.free(security_config);
    try support.contains(security_config, "\"maximum_release_age_seconds\":2678400");
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
            const root = try f.work.path(".real-snapshot/fresh/root");
            defer support.allocator.free(root);
            try expectArguments(args, &.{
                "transaction-result", "verify", "--transaction-backend", "native",
                "--install-root",     root,     "--lock-input",          install_lock,
                "--architecture",     f.arch,   "--json",
            });
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

test "snapshot: relative native caller uses absolute protected source paths before create" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const relative_script = try support.allocator.dupe(u8, "tools/real-snapshot-acceptance.sh");
    support.allocator.free(f.script);
    f.script = relative_script;
    const result = try f.offline(.{});
    defer result.deinit();
    try result.ok();
    const continuation = try f.work.read(".real-snapshot/fresh/evidence/update-zero-actions.txt");
    defer support.allocator.free(continuation);
    try testing.expectEqualStrings("changed=false\nstatus_unchanged=true\nprovenance_unchanged=true\n", continuation);
}

fn expectArguments(actual: []const []const u8, expected: []const []const u8) !void {
    try testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got| try testing.expectEqualStrings(want, got);
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

test "snapshot: native verification refusal preserves installed evidence and stops before update" {
    for ([_]struct { scenario: []const u8, exit_code: u8 }{
        .{ .scenario = "failed-verification", .exit_code = 7 },
        .{ .scenario = "failed-outcome", .exit_code = 1 },
    }) |scenario| {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(.{ .name = scenario.scenario });
        defer refused.deinit();
        try testing.expectEqual(scenario.exit_code, refused.code);
        try support.contains(refused.stderr, "native create transaction-result verification");
        try expectOperations(&f, &.{ "refresh", "plan", "download", "install", "transaction-result" });
        const provenance = try f.work.read(".real-snapshot/fresh/root/var/lib/debz/native-transaction-provenance-v2.json");
        defer support.allocator.free(provenance);
        try support.contains(provenance, "\"outcome\":\"succeeded\"");
        const status = try f.work.read(".real-snapshot/fresh/root/var/lib/dpkg/status");
        defer support.allocator.free(status);
        try support.contains(status, "Status: install ok installed");
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/update.json"));
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/update-zero-actions.txt"));
    }
}

test "snapshot: legacy verification requires state path, native rejects it" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const accepted = try f.offline(.{});
    defer accepted.deinit();
    try accepted.ok();
    const calls = try f.work.path("calls.jsonl");
    defer support.allocator.free(calls);
    const env_calls = try std.fmt.allocPrint(support.allocator, "SNAPSHOT_TEST_CALLS={s}", .{calls});
    defer support.allocator.free(env_calls);
    const lock = try f.work.path(".real-snapshot/fresh/evidence/ubuntu-minimal.lock.json");
    defer support.allocator.free(lock);
    const update_lock = try f.work.path(".real-snapshot/fresh/evidence/ubuntu-minimal.update.lock.json");
    defer support.allocator.free(update_lock);
    const root = try f.work.path(".real-snapshot/fresh/root");
    defer support.allocator.free(root);
    const state = try f.work.path(".real-snapshot/fresh/state");
    defer support.allocator.free(state);
    const legacy = try support.run(&.{
        "env",          env_calls, f.executable,   "transaction-result", "verify",
        "--state-path", state,     "--lock-input", update_lock,          "--architecture",
        f.arch,         "--json",
    });
    defer legacy.deinit();
    try legacy.ok();
    const legacy_without_state = try support.run(&.{
        "env",          env_calls,   f.executable,     "transaction-result", "verify",
        "--lock-input", update_lock, "--architecture", f.arch,               "--json",
    });
    defer legacy_without_state.deinit();
    try testing.expect(legacy_without_state.code != 0);
    try support.contains(legacy_without_state.stderr, "MissingState");
    const native_with_state = try support.run(&.{
        "env",                   env_calls,      f.executable,     "transaction-result", "verify",
        "--transaction-backend", "native",       "--install-root", root,                 "--state-path",
        state,                   "--lock-input", lock,             "--architecture",     f.arch,
        "--json",
    });
    defer native_with_state.deinit();
    try testing.expect(native_with_state.code != 0);
    try support.contains(native_with_state.stderr, "NativeVerificationDoesNotUseStatePath");
}

test "snapshot: install verdict bounds time without durable progress by a fixed ceiling" {
    var f = try Driver.init();
    defer f.deinit();
    for ([_]struct { elapsed: []const u8, progressed: []const u8, limit: []const u8, ceiling: []const u8, verdict: []const u8 }{
        .{ .elapsed = "0", .progressed = "0", .limit = "1200", .ceiling = "10800", .verdict = "running\n" },
        .{ .elapsed = "1199", .progressed = "0", .limit = "1200", .ceiling = "10800", .verdict = "running\n" },
        .{ .elapsed = "1200", .progressed = "0", .limit = "1200", .ceiling = "10800", .verdict = "stalled\n" },
        .{ .elapsed = "6199", .progressed = "5000", .limit = "1200", .ceiling = "10800", .verdict = "running\n" },
        .{ .elapsed = "6200", .progressed = "5000", .limit = "1200", .ceiling = "10800", .verdict = "stalled\n" },
        .{ .elapsed = "10799", .progressed = "10799", .limit = "1200", .ceiling = "10800", .verdict = "running\n" },
        .{ .elapsed = "10800", .progressed = "10800", .limit = "1200", .ceiling = "10800", .verdict = "ceiling\n" },
        .{ .elapsed = "10800", .progressed = "0", .limit = "1200", .ceiling = "10800", .verdict = "ceiling\n" },
        .{ .elapsed = "3", .progressed = "0", .limit = "3", .ceiling = "3", .verdict = "ceiling\n" },
    }) |case| {
        const result = try f.run(f.keyring, &.{ "--progress-verdict", case.elapsed, case.progressed, case.limit, case.ceiling });
        defer result.deinit();
        try result.ok();
        try testing.expectEqualStrings(case.verdict, result.stdout);
    }
    for ([_][4][]const u8{
        .{ "5", "6", "1", "10" },
        .{ "5", "0", "0", "10" },
        .{ "5", "0", "11", "10" },
        .{ "05", "0", "1", "10" },
        .{ "-1", "0", "1", "10" },
        .{ "5", "0", "one", "10" },
        .{ "5", "0", "1", "1000000" },
    }) |invalid| {
        const result = try f.run(f.keyring, &.{ "--progress-verdict", invalid[0], invalid[1], invalid[2], invalid[3] });
        defer result.deinit();
        try testing.expectEqual(@as(u8, 2), result.code);
        try support.contains(result.stderr, "invalid progress verdict input");
    }
}

test "snapshot: reviewed install bounds are recorded and overrides may only tighten them" {
    {
        var f = try Driver.initOffline();
        defer f.deinit();
        const accepted = try f.offline(.{});
        defer accepted.deinit();
        try accepted.ok();
        const identity = try f.work.read(".real-snapshot/fresh/evidence/invocation-identity.txt");
        defer support.allocator.free(identity);
        try support.contains(identity, "operation_limit=30m\nverification_limit=10m\n" ++
            "install_progress_limit_seconds=1200\ninstall_ceiling_seconds=10800\n");
        const progress = try f.work.read(".real-snapshot/fresh/evidence/create-progress.txt");
        defer support.allocator.free(progress);
        try support.contains(progress, "progress_limit_seconds=1200\nceiling_seconds=10800\nsample_seconds=60\n");
        try support.contains(progress, "\nsha_instructions=");
        try support.contains(progress, "\nverdict=completed\nexit_status=0\n");
        try support.contains(progress, "status_entries=1 installed=1 unpacked=0 other=0 ledger_bytes=0\n");
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/create-watchdog.txt"));
    }
    for ([_]struct { limit: []const u8 = "", ceiling: []const u8 = "", message: []const u8 }{
        .{ .limit = "1201", .message = "install progress bounds may only tighten the reviewed limits" },
        .{ .ceiling = "10801", .message = "install progress bounds may only tighten the reviewed limits" },
        .{ .limit = "0", .message = "install progress bounds may only tighten the reviewed limits" },
        .{ .ceiling = "90m", .message = "install progress bounds may only tighten the reviewed limits" },
        .{ .limit = "30", .ceiling = "20", .message = "install progress limit exceeds its ceiling" },
    }) |invalid| {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(.{ .progress_limit_seconds = invalid.limit, .ceiling_seconds = invalid.ceiling });
        defer refused.deinit();
        try testing.expectEqual(@as(u8, 2), refused.code);
        try support.contains(refused.stderr, invalid.message);
        try testing.expectError(error.FileNotFound, f.work.read("calls.jsonl"));
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh"));
    }
}

fn progressField(progress: []const u8, comptime field: []const u8) !u64 {
    const marker = "\n" ++ field ++ "=";
    const start = (std.mem.lastIndexOf(u8, progress, marker) orelse return error.MissingProgressField) + marker.len;
    const end = std.mem.indexOfScalarPos(u8, progress, start, '\n') orelse return error.MissingProgressField;
    return std.fmt.parseInt(u64, progress[start..end], 10);
}

test "snapshot: slowly progressing install continues beyond its progress limit" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const accepted = try f.offline(.{ .name = "slow-progress", .progress_limit_seconds = "3", .ceiling_seconds = "20" });
    defer accepted.deinit();
    try accepted.ok();
    const progress = try f.work.read(".real-snapshot/fresh/evidence/create-progress.txt");
    defer support.allocator.free(progress);
    try support.contains(progress, "\nverdict=completed\nexit_status=0\n");
    try testing.expect(try progressField(progress, "elapsed_seconds") > 3);
    try testing.expect(try progressField(progress, "longest_progress_gap_seconds") < 3);
    try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/create-watchdog.txt"));
    try expectOperations(&f, &.{
        "refresh", "plan", "download",    "install", "transaction-result",
        "plan",    "plan", "upgrade-all", "plan",
    });
}

test "snapshot: stalled install stops at its progress limit before verification" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const refused = try f.offline(.{ .name = "stalled-install", .trace = true, .progress_limit_seconds = "2", .ceiling_seconds = "20" });
    defer refused.deinit();
    try testing.expectEqual(@as(u8, 124), refused.code);
    try support.contains(refused.stderr, "native create stalled after");
    try expectOperations(&f, &.{ "refresh", "plan", "download", "install" });
    const progress = try f.work.read(".real-snapshot/fresh/evidence/create-progress.txt");
    defer support.allocator.free(progress);
    try support.contains(progress, "\nverdict=stalled\nexit_status=124\n");
    try support.contains(progress, "status_entries=1 installed=0 unpacked=1 other=0");
    try testing.expect(try progressField(progress, "elapsed_seconds") < 20);
    const watchdog = try f.work.read(".real-snapshot/fresh/evidence/create-watchdog.txt");
    defer support.allocator.free(watchdog);
    try support.contains(watchdog, "verdict=stalled\n");
    try support.contains(watchdog, "\nloadavg=");
    try support.contains(watchdog, " install --install-root ");
    const audit = try f.work.read(".real-snapshot/fresh/evidence/native-exec-audit.txt");
    defer support.allocator.free(audit);
    try support.contains(audit, "operation=create\nexit_status=124\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=false\n");
    try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/create-summary.json"));
}

test "snapshot: continuously progressing install stops at its fixed ceiling" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const refused = try f.offline(.{ .name = "endless-progress", .progress_limit_seconds = "3", .ceiling_seconds = "4" });
    defer refused.deinit();
    try testing.expectEqual(@as(u8, 124), refused.code);
    try support.contains(refused.stderr, "native create ceiling after");
    try expectOperations(&f, &.{ "refresh", "plan", "download", "install" });
    const progress = try f.work.read(".real-snapshot/fresh/evidence/create-progress.txt");
    defer support.allocator.free(progress);
    try support.contains(progress, "\nverdict=ceiling\nexit_status=124\n");
    // Whole-second polling can observe 250 ms progress up to 2 s apart.
    try testing.expect(try progressField(progress, "longest_progress_gap_seconds") < 3);
    try testing.expect(try progressField(progress, "elapsed_seconds") < 20);
    const watchdog = try f.work.read(".real-snapshot/fresh/evidence/create-watchdog.txt");
    defer support.allocator.free(watchdog);
    try support.contains(watchdog, "verdict=ceiling\n");
    try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/create-summary.json"));
}

test "snapshot: unreviewed update signer refuses before update" {
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
    try testing.expectEqualStrings("operation=refresh\nexit_status=4\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=false\n", audit);
    const summary = try f.work.read(".real-snapshot/fresh/evidence/exec-audit-summary.txt");
    defer support.allocator.free(summary);
    try testing.expectEqualStrings("audited_operations=1\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=false\n", summary);
    const refresh = try f.work.read(".real-snapshot/fresh/evidence/refresh.json");
    defer support.allocator.free(refresh);
    try support.contains(refresh, "\"summary\":\"ReleaseExpired\"");
    var root = try f.work.directory.dir.openDir(support.io, ".real-snapshot/fresh/root", .{ .iterate = true });
    defer root.close(support.io);
    var iterator = root.iterate();
    try testing.expect((try iterator.next(support.io)) == null);
}

test "snapshot: trace rejects forbidden dpkg execve and descriptor execveat even on failed refresh" {
    for ([_]struct { scenario: Scenario, record: []const u8 }{
        .{
            .scenario = .{ .name = "freshness-failure", .trace = true, .execve = "/usr/bin/dpkg" },
            .record = "forbidden_exec reason=not-script-descended line=1 ",
        },
        .{
            .scenario = .{ .name = "freshness-failure", .trace = true, .execve = "/usr/local/bin/dpkg-deb", .execveat = true },
            .record = "forbidden_exec reason=execveat line=1 ",
        },
    }) |case| {
        var f = try Driver.initOffline();
        defer f.deinit();
        const refused = try f.offline(case.scenario);
        defer refused.deinit();
        try testing.expectEqual(@as(u8, 90), refused.code);
        try support.contains(refused.stderr, "outside the reviewed script exception during refresh");
        try expectOperations(&f, &.{"refresh"});
        const audit = try f.work.read(".real-snapshot/fresh/evidence/native-exec-audit.txt");
        defer support.allocator.free(audit);
        try testing.expect(std.mem.startsWith(u8, audit, "operation=refresh\nexit_status=4\n"));
        try support.contains(audit, case.record);
        try testing.expect(std.mem.endsWith(u8, audit, "\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=true\n"));
        const summary = try f.work.read(".real-snapshot/fresh/evidence/exec-audit-summary.txt");
        defer support.allocator.free(summary);
        try testing.expectEqualStrings("audited_operations=1\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=true\n", summary);
    }
}

test "snapshot: wrapper binds script dpkg calls to the reviewed root identity" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const refused = try f.offline(.{ .name = "freshness-failure", .trace = true, .script_dpkg = true });
    defer refused.deinit();
    try testing.expectEqual(@as(u8, 90), refused.code);
    try expectOperations(&f, &.{"refresh"});
    const audit = try f.work.read(".real-snapshot/fresh/evidence/native-exec-audit.txt");
    defer support.allocator.free(audit);
    // The fixture root has no reviewed /usr/bin/dpkg, so the otherwise
    // reviewed script-descended query is refused rather than counted.
    try support.contains(audit, "forbidden_exec reason=dpkg-identity:");
    try support.contains(audit, " pid=9002 path=\"/usr/bin/dpkg\" script=/var/lib/debz-lifecycle-scripts/tzdata.postinst script_pid=9001 lineage=");
    try support.contains(audit, ">9001>9002 argv=[\"dpkg\",\"-s\",\"tzdata\"]\n");
    try testing.expect(std.mem.indexOf(u8, audit, "script_dpkg_exec ") == null);
    try testing.expect(std.mem.endsWith(u8, audit, "\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=true\n"));
}

test "snapshot: wrapper binds script dpkg-divert and dpkg-statoverride calls to their reviewed root identities" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const refused = try f.offline(.{ .name = "freshness-failure", .trace = true, .script_tools = true });
    defer refused.deinit();
    try testing.expectEqual(@as(u8, 90), refused.code);
    try support.contains(refused.stderr, "invoked a dpkg tool outside the reviewed script exception");
    try expectOperations(&f, &.{"refresh"});
    const audit = try f.work.read(".real-snapshot/fresh/evidence/native-exec-audit.txt");
    defer support.allocator.free(audit);
    try support.contains(audit, "forbidden_exec reason=dpkg-divert-identity:");
    try support.contains(audit, " pid=9012 path=\"/usr/bin/dpkg-divert\" script=/var/lib/debz-lifecycle-scripts/chrony.postinst script_pid=9011 lineage=");
    try support.contains(audit, ">9011>9012 argv=[\"dpkg-divert\",\"--truename\",\"/bin/ping\"]\n");
    try support.contains(audit, "forbidden_exec reason=dpkg-statoverride-identity:");
    try support.contains(audit, " pid=9013 path=\"/usr/bin/dpkg-statoverride\" script=/var/lib/debz-lifecycle-scripts/chrony.postinst script_pid=9011 lineage=");
    try support.contains(audit, ">9011>9013 argv=[\"dpkg-statoverride\",\"--list\",\"/var/lib/chrony\"]\n");
    try testing.expect(std.mem.indexOf(u8, audit, "\nscript_") == null);
    try testing.expect(std.mem.endsWith(u8, audit, "\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=true\n"));
    const summary = try f.work.read(".real-snapshot/fresh/evidence/exec-audit-summary.txt");
    defer support.allocator.free(summary);
    try testing.expectEqualStrings("audited_operations=1\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=true\n", summary);
}

test "snapshot: traced acceptance without dpkg execs records a passing exec audit summary" {
    var f = try Driver.initOffline();
    defer f.deinit();
    const accepted = try f.offline(.{ .trace = true });
    defer accepted.deinit();
    try accepted.ok();
    const summary = try f.work.read(".real-snapshot/fresh/evidence/exec-audit-summary.txt");
    defer support.allocator.free(summary);
    try support.contains(summary, "\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=false\n");
    try testing.expect(std.mem.startsWith(u8, summary, "audited_operations="));
    try testing.expect(try numberBetween(summary, "audited_operations=", "\n") >= 8);
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
        try support.contains(audit, "operation=injected-failure\nexit_status=5\nforbidden_exec reason=path line=1 ");
        try support.contains(audit, " path=\"/opt/pinned/bin/dpkg-deb\" ");
        try testing.expect(std.mem.endsWith(u8, audit, "\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=true\n"));
        try testing.expectError(error.FileNotFound, f.work.read(".real-snapshot/fresh/evidence/injected-failure.txt"));
    }
}

const audit_debz = "/opt/debz/bin/debz";
const audit_dpkg = "reviewed fixture dpkg\n";
const audit_dpkg_size = std.fmt.comptimePrint("{d}", .{audit_dpkg.len});
const audit_version = "1.23.7ubuntu2";
const audit_script = "/var/lib/debz-lifecycle-scripts/tzdata.postinst";
const audit_lineage = " script=" ++ audit_script ++ " script_pid=702 lineage=700>701>702>703 argv=";

/// The fixture root's script-callable tools; each has its own identity.
const audit_tools = [_]struct { name: []const u8, bytes: []const u8 }{
    .{ .name = "dpkg", .bytes = audit_dpkg },
    .{ .name = "dpkg-divert", .bytes = "reviewed fixture dpkg-divert\n" },
    .{ .name = "dpkg-statoverride", .bytes = "reviewed fixture dpkg-statoverride\n" },
};

fn auditToolBytes(tool: []const u8) []const u8 {
    for (audit_tools) |entry| {
        if (std.mem.eql(u8, entry.name, tool)) return entry.bytes;
    }
    unreachable;
}

fn auditHex(bytes: []const u8) [2 * std.crypto.hash.sha2.Sha256.digest_length]u8 {
    var hashed: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &hashed, .{});
    return std.fmt.bytesToHex(hashed, .lower);
}

/// The fixture identities as "TOOL=DIGEST:SIZE ..." words, with TOOL's
/// identity replaced by OVERRIDE.
fn auditIdentities(tool: []const u8, override: []const u8) ![]u8 {
    var parts: [audit_tools.len][]u8 = undefined;
    var made: usize = 0;
    defer for (parts[0..made]) |part| support.allocator.free(part);
    for (audit_tools) |entry| {
        const digest = auditHex(entry.bytes);
        parts[made] = if (std.mem.eql(u8, entry.name, tool))
            try std.fmt.allocPrint(support.allocator, "{s}={s}", .{ entry.name, override })
        else
            try std.fmt.allocPrint(support.allocator, "{s}={s}:{d}", .{ entry.name, &digest, entry.bytes.len });
        made += 1;
    }
    return std.fmt.allocPrint(support.allocator, "{s} {s} {s}", .{ parts[0], parts[1], parts[2] });
}

fn writeAuditRoot(f: *Driver, version: []const u8, status_architecture: []const u8) !void {
    for (audit_tools) |entry| {
        const relative = try std.fmt.allocPrint(support.allocator, "audit-root/usr/bin/{s}", .{entry.name});
        defer support.allocator.free(relative);
        try f.work.write(relative, entry.bytes);
    }
    try f.work.directory.dir.createDirPath(support.io, "audit-root/usr/sbin");
    try f.work.directory.dir.createDirPath(support.io, "audit-root/usr/local/bin");
    const status = try std.fmt.allocPrint(support.allocator, "Package: dpkg-dev\nStatus: install ok installed\nVersion: {s}\nArchitecture: all\n\n" ++
        "Package: dpkg\nStatus: install ok installed\nVersion: {s}\nArchitecture: {s}\n" ++
        "Description: fixture\n Version: 0\n\n", .{ audit_version, version, status_architecture });
    defer support.allocator.free(status);
    try f.work.write("audit-root/var/lib/dpkg/status", status);
}

fn auditLink(f: *Driver, target: []const u8, relative: []const u8) !void {
    const link = try f.work.path(relative);
    defer support.allocator.free(link);
    const linked = try support.run(&.{ "ln", "-s", target, link });
    defer linked.deinit();
    try linked.ok();
}

fn auditWith(f: *Driver, mode: []const u8, trace: []const u8, identities: []const u8) !support.Result {
    try f.work.write("audit.trace", trace);
    const trace_path = try f.work.path("audit.trace");
    defer support.allocator.free(trace_path);
    const root = try f.work.path("audit-root");
    defer support.allocator.free(root);
    if (std.mem.eql(u8, mode, "--audit-exec-trace"))
        return f.run(f.keyring, &.{ mode, trace_path, root, f.arch, audit_debz });
    return f.run(f.keyring, &.{ mode, trace_path, root, f.arch, audit_debz, audit_version, identities });
}

fn auditFixture(f: *Driver, trace: []const u8) !support.Result {
    const identities = try auditIdentities("", "");
    defer support.allocator.free(identities);
    return auditWith(f, "--audit-exec-trace-fixture", trace, identities);
}

/// A debz thread forks a lifecycle script, which vforks CALL(ARGS); strace
/// prints the child's exec before the vfork returns.
fn scriptTrace(script: []const u8, call: []const u8, args: []const u8, result: []const u8) ![]u8 {
    return std.fmt.allocPrint(support.allocator,
        \\700 execve("/opt/debz/bin/debz", ["debz", "install"], 0x7ffd0 /* 4 vars */) = 0
        \\700 clone3({{flags=CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_SETTLS|CLONE_PARENT_SETTID|CLONE_CHILD_CLEARTID, child_tid=0x1, parent_tid=0x2, exit_signal=0, stack=0x3, stack_size=0x4, tls=0x5}} => {{parent_tid=[701]}}, 88) = 701
        \\701 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x6) = 702
        \\702 execve("{s}", ["{s}", "configure", ""], 0x7ffd1 /* 1 var */) = 0
        \\702 vfork( <unfinished ...>
        \\703 {s}({s} <unfinished ...>
        \\702 <... vfork resumed>)              = 703
        \\703 <... {s} resumed>) = {s}
        \\
    , .{ script, script, call, args, call, result });
}

fn dpkgArgs(path: []const u8, argv: []const u8) ![]u8 {
    return std.fmt.allocPrint(support.allocator, "\"{s}\", [{s}], 0x7ffd2 /* 2 vars */", .{ path, argv });
}

fn scriptTool(tool: []const u8, argv: []const u8) ![]u8 {
    const path = try std.fmt.allocPrint(support.allocator, "/usr/bin/{s}", .{tool});
    defer support.allocator.free(path);
    const args = try dpkgArgs(path, argv);
    defer support.allocator.free(args);
    return scriptTrace(audit_script, "execve", args, "0");
}

fn scriptDpkg(argv: []const u8) ![]u8 {
    return scriptTool("dpkg", argv);
}

fn expectRefused(result: support.Result, reason: []const u8) !void {
    const record = try std.fmt.allocPrint(support.allocator, "forbidden_exec reason={s} ", .{reason});
    defer support.allocator.free(record);
    errdefer std.debug.print("expected refusal {s}, got {d}:\n{s}{s}\n", .{ reason, result.code, result.stdout, result.stderr });
    try testing.expectEqual(@as(u8, 90), result.code);
    try testing.expect(std.mem.startsWith(u8, result.stdout, record));
    try testing.expect(std.mem.indexOf(u8, result.stdout, "\nscript_") == null);
    try testing.expect(std.mem.endsWith(u8, result.stdout, "\n" ++ audit_no_calls ++ "forbidden_dpkg_exec=true\n"));
}

fn expectAllowed(result: support.Result, record: []const u8) !void {
    return expectAllowedTool(result, "dpkg", record);
}

/// Expects exactly one allowed call, of TOOL, printed as RECORD, with TOOL's
/// fixture identity recorded.
fn expectAllowedTool(result: support.Result, tool: []const u8, record: []const u8) !void {
    errdefer std.debug.print("expected allowed {s}, got {d}:\n{s}{s}\n", .{ record, result.code, result.stdout, result.stderr });
    try result.ok();
    try testing.expect(std.mem.startsWith(u8, result.stdout, record));
    try testing.expect(std.mem.indexOf(u8, result.stdout, "forbidden_exec") == null);
    const name = try std.mem.replaceOwned(u8, support.allocator, tool, "-", "_");
    defer support.allocator.free(name);
    const bytes = auditToolBytes(tool);
    const digest = auditHex(bytes);
    const identity = try std.fmt.allocPrint(support.allocator, "\nscript_{s}_identity version=" ++ audit_version ++ " architecture=", .{name});
    defer support.allocator.free(identity);
    try support.contains(result.stdout, identity);
    const pinned = try std.fmt.allocPrint(support.allocator, " size={d} digest={s}\n", .{ bytes.len, &digest });
    defer support.allocator.free(pinned);
    try support.contains(result.stdout, pinned);
    const counts = try std.fmt.allocPrint(support.allocator, "\nallowed_script_dpkg_exec={d}\nallowed_script_dpkg_divert_exec={d}\n" ++
        "allowed_script_dpkg_statoverride_exec={d}\nforbidden_dpkg_exec=false\n", .{
        @intFromBool(std.mem.eql(u8, tool, "dpkg")),
        @intFromBool(std.mem.eql(u8, tool, "dpkg-divert")),
        @intFromBool(std.mem.eql(u8, tool, "dpkg-statoverride")),
    });
    defer support.allocator.free(counts);
    try testing.expect(std.mem.endsWith(u8, result.stdout, counts));
}

test "snapshot: exec audit allows each reviewed read-only dpkg action and argv[0] label from a debz-started script" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    for ([_][]const u8{
        "\"dpkg\", \"--compare-versions\", \"--\", \"1.0\", \"lt\", \"2.0\"",
        "\"dpkg\", \"--compare-versions\", \"1.0\", \"lt-nl\", \"\"",
        "\"dpkg\", \"--validate-version\", \"--\", \"1:2.0-1\"",
        "\"dpkg\", \"--print-architecture\"",
        "\"dpkg\", \"-s\", \"tzdata\"",
        "\"dpkg\", \"-L\", \"python3-yaml\"",
        "\"dpkg\", \"-l\", \"libc6\"",
        "\"/usr/bin/dpkg\", \"-L\", \"python3-minimal:amd64\"",
        "\"/usr/bin/dpkg\", \"--compare-versions\", \"3.14\", \"ge\", \"3.13\"",
    }) |argv| {
        const trace = try scriptDpkg(argv);
        defer support.allocator.free(trace);
        const result = try auditFixture(&f, trace);
        defer result.deinit();
        const compact = try std.mem.replaceOwned(u8, support.allocator, argv, "\", \"", "\",\"");
        defer support.allocator.free(compact);
        const record = try std.fmt.allocPrint(support.allocator, "script_dpkg_exec line=6 pid=703" ++ audit_lineage ++ "[{s}]\n", .{compact});
        defer support.allocator.free(record);
        try expectAllowed(result, record);
        const digest = auditHex(audit_dpkg);
        const identity = try std.fmt.allocPrint(support.allocator, "\nscript_dpkg_identity version={s} architecture={s} size={s} digest={s}\n", .{
            audit_version, f.arch, audit_dpkg_size, &digest,
        });
        defer support.allocator.free(identity);
        try support.contains(result.stdout, identity);
    }
}

test "snapshot: exec audit follows pid namespace, fork and debconf re-exec lineage" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    for ([_]struct { trace: []const u8, record: []const u8 }{
        .{
            .trace =
            \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
            \\700 clone(child_stack=NULL, flags=CLONE_NEWNS|CLONE_NEWPID|SIGCHLD) = 801
            \\801 execve("/var/lib/debz-lifecycle-scripts/dash.postinst", ["/var/lib/debz-lifecycle-scripts/dash.postinst", "configure"], 0x1 /* 1 var */) = 0
            \\801 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x1) = 2 /* 802 in strace's PID NS */
            \\802 execve("/usr/bin/dpkg", ["dpkg", "--print-architecture"], 0x1 /* 1 var */) = 0
            \\
            ,
            .record = "script_dpkg_exec line=5 pid=802 script=/var/lib/debz-lifecycle-scripts/dash.postinst script_pid=801 lineage=700>801>802 argv=[\"dpkg\",\"--print-architecture\"]\n",
        },
        .{
            .trace =
            \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
            \\700 fork() = 702
            \\702 execve("/var/lib/dpkg/info/libc6:amd64.postinst", ["/var/lib/dpkg/info/libc6:amd64.postinst", "configure"], 0x1 /* 1 var */) = 0
            \\702 execve("/usr/share/debconf/frontend", ["/usr/share/debconf/frontend", "/var/lib/dpkg/info/libc6:amd64.postinst", "configure"], 0x1 /* 2 vars */) = 0
            \\702 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0x1) = 703
            \\703 execve("/var/lib/dpkg/info/libc6:amd64.postinst", ["/var/lib/dpkg/info/libc6:amd64.postinst", "configure"], 0x1 /* 3 vars */) = 0
            \\703 vfork() = 704
            \\704 execve("/usr/bin/dpkg", ["dpkg", "--compare-versions", "--", "2.41", "lt", "2.42"], 0x1 /* 3 vars */) = 0
            \\
            ,
            .record = "script_dpkg_exec line=8 pid=704 script=/var/lib/dpkg/info/libc6:amd64.postinst script_pid=702 lineage=700>702>703>704 argv=[\"dpkg\",\"--compare-versions\",\"--\",\"2.41\",\"lt\",\"2.42\"]\n",
        },
    }) |case| {
        const result = try auditFixture(&f, case.trace);
        defer result.deinit();
        try expectAllowed(result, case.record);
    }
}

test "snapshot: exec audit refuses dpkg outside a debz-started script or with unreviewed arguments" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    for ([_]struct { argv: []const u8, reason: []const u8 }{
        .{ .argv = "\"dpkg\", \"--configure\", \"tzdata\"", .reason = "action" },
        .{ .argv = "\"dpkg\", \"-i\", \"/tmp/x.deb\"", .reason = "action" },
        .{ .argv = "\"dpkg\", \"--unpack\", \"/tmp/x.deb\"", .reason = "action" },
        .{ .argv = "\"dpkg\", \"--set-selections\"", .reason = "action" },
        .{ .argv = "\"dpkg\"", .reason = "action" },
        .{ .argv = "\"dpkg\", \"--root=/target\", \"-s\", \"tzdata\"", .reason = "action" },
        .{ .argv = "\"dpkg\", \"--admindir\", \"/x\", \"-s\", \"tzdata\"", .reason = "action" },
        .{ .argv = "\"dpkg\", \"--force-all\", \"-L\", \"tzdata\"", .reason = "action" },
        .{ .argv = "\"dpkg\", \"--instdir=/x\", \"-l\"", .reason = "action" },
        .{ .argv = "\"dpkg\", \"--no-pager\", \"-l\", \"tzdata\"", .reason = "action" },
        .{ .argv = "\"dpkg\", \"-s\", \"--admindir=/x\", \"tzdata\"", .reason = "option" },
        .{ .argv = "\"dpkg\", \"--print-architecture\", \"--force-all\"", .reason = "option" },
        .{ .argv = "\"dpkg\", \"-L\", \"--instdir\", \"/x\", \"tzdata\"", .reason = "option" },
        .{ .argv = "\"dpkg\", \"-s\", \"-l\", \"tzdata\"", .reason = "option" },
        .{ .argv = "\"dpkg\", \"--compare-versions\", \"--\", \"1\", \"lt\", \"--root=/\"", .reason = "option" },
        .{ .argv = "\"./dpkg\", \"-L\", \"python3\"", .reason = "argv0" },
        .{ .argv = "\"/bin/dpkg\", \"-L\", \"python3\"", .reason = "argv0" },
        .{ .argv = "\"/usr/local/bin/dpkg\", \"-L\", \"python3\"", .reason = "argv0" },
        .{ .argv = "\"/usr/bin//dpkg\", \"-L\", \"python3\"", .reason = "argv0" },
        .{ .argv = "\"/usr/bin/../bin/dpkg\", \"-L\", \"python3\"", .reason = "argv0" },
        .{ .argv = "\"usr/bin/dpkg\", \"-L\", \"python3\"", .reason = "argv0" },
        .{ .argv = "\"dpkg-query\", \"-L\", \"python3\"", .reason = "argv0" },
        .{ .argv = "\"\", \"-L\", \"python3\"", .reason = "argv0" },
        .{ .argv = "", .reason = "argv0" },
        .{ .argv = "\"dpkg\", \"-s\", \"tzdata\"...", .reason = "truncated" },
    }) |case| {
        const trace = try scriptDpkg(case.argv);
        defer support.allocator.free(trace);
        const result = try auditFixture(&f, trace);
        defer result.deinit();
        try expectRefused(result, case.reason);
    }
    for ([_][]const u8{ "/tmp/dpkg", "/usr/local/bin/dpkg", "/usr/sbin/dpkg", "/bin/dpkg", "dpkg", "./dpkg", "/usr/bin//dpkg", "/usr/bin/../bin/dpkg" }) |path| {
        for ([_][]const u8{ "\"dpkg\", \"-s\", \"tzdata\"", "\"/usr/bin/dpkg\", \"-s\", \"tzdata\"" }) |argv| {
            const args = try dpkgArgs(path, argv);
            defer support.allocator.free(args);
            const trace = try scriptTrace(audit_script, "execve", args, "0");
            defer support.allocator.free(trace);
            const result = try auditFixture(&f, trace);
            defer result.deinit();
            try expectRefused(result, "path");
        }
    }
    {
        const args = try dpkgArgs("/usr/bin/dpkg-deb", "\"dpkg-deb\", \"--info\", \"/tmp/x.deb\"");
        defer support.allocator.free(args);
        const trace = try scriptTrace(audit_script, "execve", args, "0");
        defer support.allocator.free(trace);
        const result = try auditFixture(&f, trace);
        defer result.deinit();
        try expectRefused(result, "path");
    }
    for ([_]struct { call: []const u8, args: []const u8, result: []const u8, reason: []const u8 }{
        .{ .call = "execveat", .args = "AT_FDCWD, \"/usr/bin/dpkg\", [\"dpkg\", \"-s\", \"tzdata\"], 0x1 /* 1 var */, 0", .result = "0", .reason = "execveat" },
        .{ .call = "execveat", .args = "3</usr/bin/dpkg>, \"\", [\"dpkg\", \"-s\", \"tzdata\"], 0x1 /* 1 var */, AT_EMPTY_PATH", .result = "0", .reason = "execveat" },
        .{ .call = "execve", .args = "\"/usr/bin/dpkg\", [\"dpkg\", \"-s\", \"tzdata\"], 0x1 /* 1 var */", .result = "-1 ENOENT (No such file or directory)", .reason = "exec-result" },
    }) |case| {
        const trace = try scriptTrace(audit_script, case.call, case.args, case.result);
        defer support.allocator.free(trace);
        const result = try auditFixture(&f, trace);
        defer result.deinit();
        try expectRefused(result, case.reason);
    }
    for ([_]struct { trace: []const u8, reason: []const u8 }{
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/usr/bin/perl", ["perl", "-e", "exec @ARGV"], 0x1 /* 1 var */) = 0
        \\702 clone(child_stack=NULL, flags=SIGCHLD) = 703
        \\703 execve("/var/lib/debz-lifecycle-scripts/tzdata.postinst", ["/var/lib/debz-lifecycle-scripts/tzdata.postinst"], 0x1 /* 1 var */) = 0
        \\703 vfork() = 704
        \\704 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/usr/bin/env", ["env", "/opt/debz/bin/debz"], 0x1 /* 1 var */) = 0
        \\700 execve("/opt/debz/bin/debz", ["/opt/debz/bin/debz"], 0x1 /* 1 var */) = -1 EACCES (Permission denied)
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/tzdata.postinst", ["/var/lib/debz-lifecycle-scripts/tzdata.postinst"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\900 execve("/var/lib/dpkg/info/tzdata.postinst", ["/var/lib/dpkg/info/tzdata.postinst", "configure"], 0x1 /* 1 var */) = 0
        \\900 vfork() = 901
        \\901 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\900 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\900 execve("/var/lib/dpkg/info/tzdata.postinst", ["/var/lib/dpkg/info/tzdata.postinst", "configure"], 0x1 /* 1 var */) = 0
        \\900 vfork() = 901
        \\901 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\900 execve("/var/lib/dpkg/info/tzdata.postinst", ["/var/lib/dpkg/info/tzdata.postinst", "configure"], 0x1 /* 1 var */) = 0
        \\900 vfork() = 901
        \\901 execve("/usr/bin/dpkg", ["/usr/bin/dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/bin/sh", ["sh", "-c", "/var/lib/dpkg/info/tzdata.postinst configure"], 0x1 /* 1 var */) = 0
        \\702 execve("/var/lib/dpkg/info/tzdata.postinst", ["/var/lib/dpkg/info/tzdata.postinst", "configure"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/tzdata.config", ["/var/lib/debz-lifecycle-scripts/tzdata.config"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "exec-result", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/tzdata.postinst", ["/var/lib/debz-lifecycle-scripts/tzdata.postinst"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */ <unfinished ...>
        \\
        },
        .{ .reason = "ambiguous-lineage", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 703
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/tzdata.postinst", ["/var/lib/debz-lifecycle-scripts/tzdata.postinst"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "unparsed", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/tzdata.postinst", ["/var/lib/debz-lifecycle-scripts/tzdata.postinst"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg", ["dpkg", "-s", "tzdata"], ["PATH=/usr/bin"]) = 0
        \\
        },
    }) |case| {
        const result = try auditFixture(&f, case.trace);
        defer result.deinit();
        try expectRefused(result, case.reason);
    }
}

test "snapshot: exec audit refuses script dpkg calls unless the root dpkg has the reviewed identity" {
    for ([_][]const u8{ "dpkg", "/usr/bin/dpkg" }) |argv0| try expectIdentityBound("dpkg", argv0, "\"-s\", \"tzdata\"");
}

test "snapshot: exec audit refuses script dpkg-divert and dpkg-statoverride calls unless each root tool has its reviewed identity" {
    for ([_][]const u8{ "dpkg-divert", "/usr/bin/dpkg-divert" }) |argv0|
        try expectIdentityBound("dpkg-divert", argv0, "\"--truename\", \"/bin/ping\"");
    for ([_][]const u8{ "dpkg-statoverride", "/usr/bin/dpkg-statoverride" }) |argv0|
        try expectIdentityBound("dpkg-statoverride", argv0, "\"--list\", \"/var/lib/chrony\"");
}

fn expectIdentityBound(tool: []const u8, argv0: []const u8, arguments: []const u8) !void {
    const argv = try std.fmt.allocPrint(support.allocator, "\"{s}\", {s}", .{ argv0, arguments });
    defer support.allocator.free(argv);
    const allowed = try scriptTool(tool, argv);
    defer support.allocator.free(allowed);
    const compact = try std.mem.replaceOwned(u8, support.allocator, argv, "\", \"", "\",\"");
    defer support.allocator.free(compact);
    const recorded = try std.fmt.allocPrint(support.allocator, audit_lineage ++ "[{s}]\n", .{compact});
    defer support.allocator.free(recorded);
    const name = try std.mem.replaceOwned(u8, support.allocator, tool, "-", "_");
    defer support.allocator.free(name);
    const allowed_record = try std.fmt.allocPrint(support.allocator, "script_{s}_exec line=6 pid=703{s}", .{ name, recorded });
    defer support.allocator.free(allowed_record);
    const bytes = auditToolBytes(tool);
    const other_tool = if (std.mem.eql(u8, tool, "dpkg")) "dpkg-divert" else "dpkg";
    const Change = enum { none, merged_sbin, digest, size, other_tool_pin, other_tool_bytes, reviewed_pins, usr_sbin, dangling_local, absolute_sbin, symlinked_tool, symlinked_bin_dir, version, status_architecture, no_root };
    for ([_]struct { change: Change, reason: ?[]const u8 }{
        .{ .change = .none, .reason = null },
        .{ .change = .merged_sbin, .reason = null },
        .{ .change = .digest, .reason = "digest" },
        .{ .change = .size, .reason = "digest" },
        .{ .change = .other_tool_pin, .reason = "digest" },
        .{ .change = .other_tool_bytes, .reason = "digest" },
        .{ .change = .reviewed_pins, .reason = "digest" },
        .{ .change = .usr_sbin, .reason = "shadow:/usr/sbin/" },
        .{ .change = .dangling_local, .reason = "shadow:/usr/local/bin/" },
        .{ .change = .absolute_sbin, .reason = "shadow:/sbin/" },
        .{ .change = .symlinked_tool, .reason = "not-regular" },
        .{ .change = .symlinked_bin_dir, .reason = "not-regular" },
        .{ .change = .version, .reason = "version" },
        .{ .change = .status_architecture, .reason = "version" },
        .{ .change = .no_root, .reason = "unreadable" },
    }) |case| {
        var f = try Driver.init();
        defer f.deinit();
        const wrong_arch = if (std.mem.eql(u8, f.arch, "amd64")) "arm64" else "amd64";
        if (case.change != .no_root)
            try writeAuditRoot(&f, if (case.change == .version) "1.23.7ubuntu1" else audit_version, if (case.change == .status_architecture) wrong_arch else f.arch);
        const in_bin = try std.fmt.allocPrint(support.allocator, "audit-root/usr/bin/{s}", .{tool});
        defer support.allocator.free(in_bin);
        switch (case.change) {
            .merged_sbin => try auditLink(&f, "usr/sbin", "audit-root/sbin"),
            .other_tool_bytes => try f.work.write(in_bin, auditToolBytes(other_tool)),
            .usr_sbin => {
                const shadow = try std.fmt.allocPrint(support.allocator, "audit-root/usr/sbin/{s}", .{tool});
                defer support.allocator.free(shadow);
                try f.work.write(shadow, bytes);
            },
            .dangling_local => {
                const shadow = try std.fmt.allocPrint(support.allocator, "audit-root/usr/local/bin/{s}", .{tool});
                defer support.allocator.free(shadow);
                try auditLink(&f, "/nonexistent/tool", shadow);
            },
            .absolute_sbin => {
                const alternate = try std.fmt.allocPrint(support.allocator, "audit-root/opt/alternate/{s}", .{tool});
                defer support.allocator.free(alternate);
                try f.work.write(alternate, bytes);
                try auditLink(&f, "/opt/alternate", "audit-root/sbin");
            },
            .symlinked_tool => {
                const moved = try std.fmt.allocPrint(support.allocator, "audit-root/usr/lib/dpkg/{s}", .{tool});
                defer support.allocator.free(moved);
                try f.work.write(moved, bytes);
                try f.work.directory.dir.deleteFile(support.io, in_bin);
                const target = try std.fmt.allocPrint(support.allocator, "../lib/dpkg/{s}", .{tool});
                defer support.allocator.free(target);
                try auditLink(&f, target, in_bin);
            },
            .symlinked_bin_dir => {
                const bin = try f.work.path("audit-root/usr/bin");
                defer support.allocator.free(bin);
                const moved_to = try f.work.path("audit-root/usr/alt-bin");
                defer support.allocator.free(moved_to);
                const moved = try support.run(&.{ "mv", bin, moved_to });
                defer moved.deinit();
                try moved.ok();
                try auditLink(&f, "alt-bin", "audit-root/usr/bin");
            },
            else => {},
        }
        const reviewed = auditHex(bytes);
        const other = auditHex("unreviewed tool\n");
        const other_bytes = auditToolBytes(other_tool);
        const other_digest = auditHex(other_bytes);
        const override = switch (case.change) {
            .digest => try std.fmt.allocPrint(support.allocator, "{s}:{d}", .{ &other, bytes.len }),
            .size => try std.fmt.allocPrint(support.allocator, "{s}:23", .{&reviewed}),
            .other_tool_pin => try std.fmt.allocPrint(support.allocator, "{s}:{d}", .{ &other_digest, other_bytes.len }),
            else => try std.fmt.allocPrint(support.allocator, "{s}:{d}", .{ &reviewed, bytes.len }),
        };
        defer support.allocator.free(override);
        const identities = try auditIdentities(tool, override);
        defer support.allocator.free(identities);
        const result = if (case.change == .reviewed_pins)
            try auditWith(&f, "--audit-exec-trace", allowed, "")
        else
            try auditWith(&f, "--audit-exec-trace-fixture", allowed, identities);
        defer result.deinit();
        if (case.reason) |reason| {
            const full = try std.fmt.allocPrint(support.allocator, "{s}-identity:{s}{s}", .{
                tool, reason, if (std.mem.startsWith(u8, reason, "shadow:")) tool else "",
            });
            defer support.allocator.free(full);
            try expectRefused(result, full);
            try support.contains(result.stdout, recorded);
        } else {
            try expectAllowedTool(result, tool, allowed_record);
        }
    }
}

test "snapshot: exec audit accepts only the /usr/bin/dpkg filename even when /bin is the usrmerge link" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    try auditLink(&f, "usr/bin", "audit-root/bin");
    for ([_]struct { path: []const u8, argv0: []const u8, reason: ?[]const u8 }{
        .{ .path = "/usr/bin/dpkg", .argv0 = "dpkg", .reason = null },
        .{ .path = "/usr/bin/dpkg", .argv0 = "/usr/bin/dpkg", .reason = null },
        .{ .path = "/bin/dpkg", .argv0 = "dpkg", .reason = "path" },
        .{ .path = "/bin/dpkg", .argv0 = "/bin/dpkg", .reason = "path" },
        .{ .path = "/bin/dpkg", .argv0 = "/usr/bin/dpkg", .reason = "path" },
        .{ .path = "/usr/bin/dpkg", .argv0 = "/bin/dpkg", .reason = "argv0" },
    }) |case| {
        const argv = try std.fmt.allocPrint(support.allocator, "\"{s}\", \"-L\", \"python3\"", .{case.argv0});
        defer support.allocator.free(argv);
        const args = try dpkgArgs(case.path, argv);
        defer support.allocator.free(args);
        const trace = try scriptTrace(audit_script, "execve", args, "0");
        defer support.allocator.free(trace);
        const result = try auditFixture(&f, trace);
        defer result.deinit();
        if (case.reason) |reason| {
            try expectRefused(result, reason);
            const path = try std.fmt.allocPrint(support.allocator, " path=\"{s}\" ", .{case.path});
            defer support.allocator.free(path);
            try support.contains(result.stdout, path);
        } else {
            const record = try std.fmt.allocPrint(support.allocator, "script_dpkg_exec line=6 pid=703" ++ audit_lineage ++ "[\"{s}\",\"-L\",\"python3\"]\n", .{case.argv0});
            defer support.allocator.free(record);
            try expectAllowed(result, record);
        }
    }
}

test "snapshot: exec audit allows each dpkg-divert and dpkg-statoverride shape that the closure's scripts use" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    for ([_]struct { tool: []const u8, argv: []const u8 }{
        // base-files preinst and postinst
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--quiet\", \"--package\", \"base-files\", \"--add\", \"--no-rename\", \"--divert\", \"/.lib32.usr-is-merged\", \"/lib32\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--quiet\", \"--package\", \"base-files\", \"--remove\", \"--no-rename\", \"--divert\", \"/.lib64.usr-is-merged\", \"/lib64\"" },
        // libc6 preinst (amd64 and arm64)
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--truename\", \"/lib64\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--quiet\", \"--package\", \"base-files\", \"--remove\", \"--no-rename\", \"--divert\", \"/lib64.usr-is-merged\", \"/lib64\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--quiet\", \"--add\", \"--no-rename\", \"--package\", \"base-files\", \"--divert\", \"/.lib64.usr-is-merged\", \"/lib64\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--quiet\", \"--add\", \"--no-rename\", \"--divert\", \"/lib64/ld-linux-x86-64.so.2.usr-is-merged\", \"/lib64/ld-linux-x86-64.so.2\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--quiet\", \"--add\", \"--no-rename\", \"--divert\", \"/lib/ld-linux-aarch64.so.1.usr-is-merged\", \"/lib/ld-linux-aarch64.so.1\"" },
        // libext2fs2t64 and libreadline8t64, then libtirpc3t64's implicit --add
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--package\", \"libext2fs2t64\", \"--no-rename\", \"--divert\", \"/lib/x86_64-linux-gnu/libe2p.so.2.usr-is-merged\", \"--add\", \"/lib/x86_64-linux-gnu/libe2p.so.2\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--package\", \"libreadline8t64\", \"--no-rename\", \"--divert\", \"/lib/aarch64-linux-gnu/libreadline.so.8.usr-is-merged\", \"--add\", \"/lib/aarch64-linux-gnu/libreadline.so.8\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--package\", \"libtirpc3t64\", \"--no-rename\", \"--divert\", \"/lib/x86_64-linux-gnu/libtirpc.so.3.usr-is-merged\", \"/lib/x86_64-linux-gnu/libtirpc.so.3\"" },
        // netplan-generator preinst and postinst
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--no-rename\", \"--divert\", \"/lib/systemd/system-generators/netplan.usr-is-merged\", \"--add\", \"/lib/systemd/system-generators/netplan\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--no-rename\", \"--divert\", \"/lib/systemd/system-generators/netplan.usr-is-merged\", \"--remove\", \"/lib/systemd/system-generators/netplan\"" },
        // coreutils-from-gnu preinst
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--package\", \"coreutils-switch\", \"--divert\", \"/usr/bin/[.remove-bak\", \"--no-rename\", \"--remove\", \"/usr/bin/[\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--package\", \"coreutils-switch\", \"--divert\", \"/usr/share/man/man8/chroot.8.gz.remove-bak\", \"--no-rename\", \"--remove\", \"/usr/share/man/man8/chroot.8.gz\"" },
        // iputils-ping postinst, dash postinst and gzip preinst queries
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--truename\", \"/bin/ping\"" },
        .{ .tool = "dpkg-divert", .argv = "\"dpkg-divert\", \"--listpackage\", \"/bin/sh\"" },
        .{ .tool = "dpkg-divert", .argv = "\"/usr/bin/dpkg-divert\", \"--truename\", \"/usr/share/man/man1/sh.1.gz\"" },
        // sudo-rs and chrony postinst
        .{ .tool = "dpkg-statoverride", .argv = "\"dpkg-statoverride\", \"--list\", \"/usr/lib/cargo/bin/sudo\"" },
        .{ .tool = "dpkg-statoverride", .argv = "\"dpkg-statoverride\", \"--update\", \"--add\", \"root\", \"_chrony\", \"0640\", \"/etc/chrony/chrony.keys\"" },
        .{ .tool = "dpkg-statoverride", .argv = "\"dpkg-statoverride\", \"--update\", \"--add\", \"_chrony\", \"_chrony\", \"0750\", \"/var/lib/chrony\"" },
        .{ .tool = "dpkg-statoverride", .argv = "\"/usr/bin/dpkg-statoverride\", \"--list\", \"/var/log/chrony\"" },
    }) |case| {
        const trace = try scriptTool(case.tool, case.argv);
        defer support.allocator.free(trace);
        const result = try auditFixture(&f, trace);
        defer result.deinit();
        const compact = try std.mem.replaceOwned(u8, support.allocator, case.argv, "\", \"", "\",\"");
        defer support.allocator.free(compact);
        const name = try std.mem.replaceOwned(u8, support.allocator, case.tool, "-", "_");
        defer support.allocator.free(name);
        const record = try std.fmt.allocPrint(support.allocator, "script_{s}_exec line=6 pid=703" ++ audit_lineage ++ "[{s}]\n", .{ name, compact });
        defer support.allocator.free(record);
        try expectAllowedTool(result, case.tool, record);
    }
}

test "snapshot: exec audit follows the traced debconf re-exec lineage of libc6's preinst dpkg-divert" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    // From the local arm64 20261001T000000Z trace, with the candidate path shortened.
    const trace =
        \\30634 execve("/opt/debz/bin/debz", ["/opt/debz/bin/debz", "install"], 0x2f827ed0 /* 11 vars */) = 0
        \\30634 clone(child_stack=NULL, flags=SIGCHLD) = 29901
        \\29901 execve("/var/lib/debz-lifecycle-scripts/libc6.preinst", ["/var/lib/debz-lifecycle-scripts/libc6.preinst", "install"], 0x2d882060 /* 11 vars */) = 0
        \\29901 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xf79f9a8b80b0) = 29902
        \\29902 execve("/usr/bin/perl", ["perl", "-e", ""], 0xc97f61450098 /* 12 vars */) = 0
        \\29901 execve("/usr/share/debconf/frontend", ["/usr/share/debconf/frontend", "/var/lib/debz-lifecycle-scripts/libc6.preinst", "install"], 0xc97f61452810 /* 13 vars */) = 0
        \\29901 clone(child_stack=NULL, flags=CLONE_CHILD_CLEARTID|CLONE_CHILD_SETTID|SIGCHLD, child_tidptr=0xe09c8c2500f0) = 29904
        \\29904 execve("/var/lib/debz-lifecycle-scripts/libc6.preinst", ["/var/lib/debz-lifecycle-scripts/libc6.preinst", "install"], 0xb82fe8096db0 /* 14 vars */) = 0
        \\29904 clone(child_stack=0xffffe3b8e010, flags=CLONE_VM|CLONE_VFORK|SIGCHLD <unfinished ...>
        \\29923 execve("/usr/bin/dpkg-divert", ["dpkg-divert", "--quiet", "--add", "--no-rename", "--divert", "/lib/ld-linux-aarch64.so.1.usr-is-merged", "/lib/ld-linux-aarch64.so.1"], 0xbb789ce99bd8 /* 16 vars */ <unfinished ...>
        \\29904 <... clone resumed>)              = 29923
        \\29923 <... execve resumed>)             = 0
        \\
    ;
    const result = try auditFixture(&f, trace);
    defer result.deinit();
    try expectAllowedTool(result, "dpkg-divert", "script_dpkg_divert_exec line=10 pid=29923 script=/var/lib/debz-lifecycle-scripts/libc6.preinst " ++
        "script_pid=29901 lineage=30634>29901>29904>29923 argv=[\"dpkg-divert\",\"--quiet\",\"--add\",\"--no-rename\",\"--divert\"," ++
        "\"/lib/ld-linux-aarch64.so.1.usr-is-merged\",\"/lib/ld-linux-aarch64.so.1\"]\n");
}

test "snapshot: exec audit refuses dpkg-divert and dpkg-statoverride outside the reviewed shapes" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    for ([_]struct { tool: []const u8, argv: []const u8, reason: []const u8 }{
        // Shapes the closure uses only on upgrade or removal, or not at all.
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--rename\", \"--package\", \"zutils\", \"--divert\", \"/usr/bin/zcat.usr-is-merged\", \"--remove\", \"/usr/bin/zcat\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--package\", \"dash\", \"--rename\", \"--remove\", \"/bin/sh\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--package\", \"coreutils-switch\", \"--divert\", \"/usr/bin/cat.remove-bak\", \"--rename\", \"--remove\", \"/usr/bin/cat\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--package\", \"dash\", \"--no-rename\", \"--remove\", \"/bin/sh\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--quiet\", \"--local\", \"--remove\", \"--no-rename\", \"/etc/os-release\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--list\", \"/etc/os-release\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--add\", \"/usr/bin/sudo\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--test\", \"--quiet\", \"--add\", \"--no-rename\", \"--divert\", \"/lib64/x.usr-is-merged\", \"/lib64/x\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--add\", \"--quiet\", \"--no-rename\", \"--divert\", \"/lib64/x.usr-is-merged\", \"/lib64/x\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--quiet\", \"--add\", \"--no-rename\", \"--divert\", \"/lib64/x.usr-is-merged\", \"/lib64/x\", \"/lib64/y\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--truename\"" },
        // Diversion targets other than the DEP17 or coreutils-switch name of the same path.
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--quiet\", \"--add\", \"--no-rename\", \"--divert\", \"/usr/bin/sudo.real\", \"/usr/bin/sudo\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--quiet\", \"--add\", \"--no-rename\", \"--divert\", \"/tmp/sudo.usr-is-merged\", \"/usr/bin/sudo\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--quiet\", \"--add\", \"--no-rename\", \"--divert\", \"/.usr/bin.usr-is-merged\", \"/usr/bin\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--package\", \"coreutils-switch\", \"--divert\", \"/usr/bin/cat.remove-bak\", \"--no-rename\", \"--add\", \"/usr/bin/cat\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--package\", \"coreutils-switch\", \"--divert\", \"/usr/bin/cat.usr-is-merged\", \"--no-rename\", \"--remove\", \"/usr/bin/cat\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--package\", \"coreutils-switch\", \"--divert\", \"/usr/bin/sudo.remove-bak\", \"--no-rename\", \"--remove\", \"/usr/bin/cat\"" },
        // Operands outside the reviewed grammar.
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--quiet\", \"--package\", \"Base-Files\", \"--add\", \"--no-rename\", \"--divert\", \"/.lib32.usr-is-merged\", \"/lib32\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--truename\", \"bin/ping\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--truename\", \"/bin/../etc/shadow\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--truename\", \"/bin/./ping\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--truename\", \"/bin//ping\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--truename\", \"/bin/ping\\n\"" },
        .{ .tool = "dpkg-divert", .reason = "shape", .argv = "\"dpkg-divert\", \"--truename\", \"/bin/p ing\"" },
        .{ .tool = "dpkg-divert", .reason = "option", .argv = "\"dpkg-divert\", \"--admindir\", \"/x\", \"--truename\", \"/bin/ping\"" },
        .{ .tool = "dpkg-divert", .reason = "option", .argv = "\"dpkg-divert\", \"--root=/x\", \"--truename\", \"/bin/ping\"" },
        .{ .tool = "dpkg-divert", .reason = "option", .argv = "\"dpkg-divert\", \"--instdir\", \"/x\", \"--truename\", \"/bin/ping\"" },
        .{ .tool = "dpkg-divert", .reason = "option", .argv = "\"dpkg-divert\", \"--quiet\", \"--add\", \"--no-rename\", \"--divert\", \"/lib64/x.usr-is-merged\", \"--force-all\", \"/lib64/x\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--remove\", \"/var/lib/chrony\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--list\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--list\", \"/etc/a\", \"/etc/b\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--quiet\", \"--list\", \"/var/lib/chrony\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--add\", \"root\", \"_chrony\", \"0640\", \"/etc/chrony/chrony.keys\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--add\", \"--update\", \"root\", \"_chrony\", \"0640\", \"/etc/chrony/chrony.keys\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--update\", \"--add\", \"root\", \"root\", \"4755\", \"/usr/bin/sudo\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--update\", \"--add\", \"root\", \"root\", \"2755\", \"/usr/bin/x\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--update\", \"--add\", \"root\", \"root\", \"755\", \"/usr/bin/x\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--update\", \"--add\", \"#0\", \"root\", \"0640\", \"/etc/x\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--update\", \"--add\", \"root\", \"_chrony\", \"0640\", \"etc/chrony/chrony.keys\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\", \"--update\", \"--add\", \"root\", \"_chrony\", \"0640\", \"/etc/../etc/shadow\"" },
        .{ .tool = "dpkg-statoverride", .reason = "shape", .argv = "\"dpkg-statoverride\"" },
        .{ .tool = "dpkg-statoverride", .reason = "option", .argv = "\"dpkg-statoverride\", \"--force-statoverride-add\", \"--update\", \"--add\", \"root\", \"_chrony\", \"0640\", \"/etc/chrony/chrony.keys\"" },
        .{ .tool = "dpkg-statoverride", .reason = "option", .argv = "\"dpkg-statoverride\", \"--admindir=/x\", \"--list\", \"/var/lib/chrony\"" },
        .{ .tool = "dpkg-statoverride", .reason = "option", .argv = "\"dpkg-statoverride\", \"--root\", \"/x\", \"--list\", \"/var/lib/chrony\"" },
        .{ .tool = "dpkg-statoverride", .reason = "option", .argv = "\"dpkg-statoverride\", \"--list\", \"/var/lib/chrony\", \"--instdir=/x\"" },
        // argv[0] must name the same tool as the filename.
        .{ .tool = "dpkg-divert", .reason = "argv0", .argv = "\"dpkg\", \"--truename\", \"/bin/ping\"" },
        .{ .tool = "dpkg-divert", .reason = "argv0", .argv = "\"dpkg-statoverride\", \"--list\", \"/bin/ping\"" },
        .{ .tool = "dpkg-divert", .reason = "argv0", .argv = "\"/bin/dpkg-divert\", \"--truename\", \"/bin/ping\"" },
        .{ .tool = "dpkg-divert", .reason = "argv0", .argv = "\"./dpkg-divert\", \"--truename\", \"/bin/ping\"" },
        .{ .tool = "dpkg-divert", .reason = "argv0", .argv = "\"/usr/sbin/dpkg-divert\", \"--truename\", \"/bin/ping\"" },
        .{ .tool = "dpkg-statoverride", .reason = "argv0", .argv = "\"/usr/bin/dpkg-divert\", \"--list\", \"/var/lib/chrony\"" },
        .{ .tool = "dpkg-statoverride", .reason = "argv0", .argv = "\"/bin/dpkg-statoverride\", \"--list\", \"/var/lib/chrony\"" },
        .{ .tool = "dpkg-statoverride", .reason = "argv0", .argv = "" },
        .{ .tool = "dpkg-statoverride", .reason = "truncated", .argv = "\"dpkg-statoverride\", \"--list\", \"/var/lib/chrony\"..." },
    }) |case| {
        const trace = try scriptTool(case.tool, case.argv);
        defer support.allocator.free(trace);
        const result = try auditFixture(&f, trace);
        defer result.deinit();
        try expectRefused(result, case.reason);
    }
    for ([_][]const u8{ "dpkg-divert", "dpkg-statoverride" }) |tool| {
        const arguments = if (std.mem.eql(u8, tool, "dpkg-divert")) "\"--truename\", \"/bin/ping\"" else "\"--list\", \"/var/lib/chrony\"";
        for ([_][]const u8{ "/bin/{s}", "/usr/sbin/{s}", "/sbin/{s}", "/usr/local/bin/{s}", "/tmp/{s}", "{s}", "./{s}", "/usr/bin//{s}", "/usr/bin/../bin/{s}" }) |pattern| {
            const path = try std.mem.replaceOwned(u8, support.allocator, pattern, "{s}", tool);
            defer support.allocator.free(path);
            for ([_][]const u8{ "{s}", "/usr/bin/{s}" }) |label| {
                const argv0 = try std.mem.replaceOwned(u8, support.allocator, label, "{s}", tool);
                defer support.allocator.free(argv0);
                const argv = try std.fmt.allocPrint(support.allocator, "\"{s}\", {s}", .{ argv0, arguments });
                defer support.allocator.free(argv);
                const args = try dpkgArgs(path, argv);
                defer support.allocator.free(args);
                const trace = try scriptTrace(audit_script, "execve", args, "0");
                defer support.allocator.free(trace);
                const result = try auditFixture(&f, trace);
                defer result.deinit();
                try expectRefused(result, "path");
            }
        }
        const path = try std.fmt.allocPrint(support.allocator, "/usr/bin/{s}", .{tool});
        defer support.allocator.free(path);
        const at = try std.fmt.allocPrint(support.allocator, "AT_FDCWD, \"{s}\", [\"{s}\", {s}], 0x1 /* 1 var */, 0", .{ path, tool, arguments });
        defer support.allocator.free(at);
        const descriptor = try std.fmt.allocPrint(support.allocator, "3<{s}>, \"\", [\"{s}\", {s}], 0x1 /* 1 var */, AT_EMPTY_PATH", .{ path, tool, arguments });
        defer support.allocator.free(descriptor);
        const failed = try std.fmt.allocPrint(support.allocator, "\"{s}\", [\"{s}\", {s}], 0x1 /* 1 var */", .{ path, tool, arguments });
        defer support.allocator.free(failed);
        for ([_]struct { call: []const u8, args: []const u8, result: []const u8, reason: []const u8 }{
            .{ .call = "execveat", .args = at, .result = "0", .reason = "execveat" },
            .{ .call = "execveat", .args = descriptor, .result = "0", .reason = "execveat" },
            .{ .call = "execve", .args = failed, .result = "-1 ENOENT (No such file or directory)", .reason = "exec-result" },
        }) |case| {
            const trace = try scriptTrace(audit_script, case.call, case.args, case.result);
            defer support.allocator.free(trace);
            const result = try auditFixture(&f, trace);
            defer result.deinit();
            try expectRefused(result, case.reason);
        }
    }
}

test "snapshot: exec audit refuses dpkg-divert and dpkg-statoverride outside a debz-started script" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    for ([_]struct { trace: []const u8, reason: []const u8 }{
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/usr/bin/dpkg-divert", ["dpkg-divert", "--truename", "/bin/ping"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/usr/bin/dpkg-statoverride", ["dpkg-statoverride", "--update", "--add", "root", "_chrony", "0640", "/etc/chrony/chrony.keys"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\900 execve("/var/lib/dpkg/info/chrony.postinst", ["/var/lib/dpkg/info/chrony.postinst", "configure"], 0x1 /* 1 var */) = 0
        \\900 vfork() = 901
        \\901 execve("/usr/bin/dpkg-statoverride", ["dpkg-statoverride", "--list", "/var/lib/chrony"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\900 execve("/var/lib/dpkg/info/libc6.preinst", ["/var/lib/dpkg/info/libc6.preinst", "install"], 0x1 /* 1 var */) = 0
        \\900 vfork() = 901
        \\901 execve("/usr/bin/dpkg-divert", ["dpkg-divert", "--truename", "/lib64"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/bin/sh", ["sh", "-c", "/var/lib/dpkg/info/libc6.preinst install"], 0x1 /* 1 var */) = 0
        \\702 execve("/var/lib/dpkg/info/libc6.preinst", ["/var/lib/dpkg/info/libc6.preinst", "install"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg-divert", ["dpkg-divert", "--truename", "/lib64"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "not-script-descended", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/chrony.config", ["/var/lib/debz-lifecycle-scripts/chrony.config"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg-statoverride", ["dpkg-statoverride", "--list", "/var/lib/chrony"], 0x1 /* 1 var */) = 0
        \\
        },
        .{ .reason = "ambiguous-lineage", .trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 703
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/libc6.preinst", ["/var/lib/debz-lifecycle-scripts/libc6.preinst", "install"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg-divert", ["dpkg-divert", "--truename", "/lib64"], 0x1 /* 1 var */) = 0
        \\
        },
    }) |case| {
        const result = try auditFixture(&f, case.trace);
        defer result.deinit();
        try expectRefused(result, case.reason);
    }
}

test "snapshot: exec audit checks each script tool's identity separately and records every allowed call" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    const trace =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/chrony.postinst", ["/var/lib/debz-lifecycle-scripts/chrony.postinst", "configure", ""], 0x1 /* 1 var */) = 0
        \\702 vfork() = 703
        \\703 execve("/usr/bin/dpkg", ["dpkg", "--compare-versions", "", "lt", "4.8"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 704
        \\704 execve("/usr/bin/dpkg-statoverride", ["dpkg-statoverride", "--list", "/var/lib/chrony"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 705
        \\705 execve("/usr/bin/dpkg-statoverride", ["dpkg-statoverride", "--update", "--add", "_chrony", "_chrony", "0750", "/var/lib/chrony"], 0x1 /* 1 var */) = 0
        \\702 vfork() = 706
        \\706 execve("/usr/bin/dpkg-divert", ["dpkg-divert", "--truename", "/bin/ping"], 0x1 /* 1 var */) = 0
        \\
    ;
    const lineage = " script=/var/lib/debz-lifecycle-scripts/chrony.postinst script_pid=702 lineage=700>702>";
    {
        const result = try auditFixture(&f, trace);
        defer result.deinit();
        try result.ok();
        const reviewed = [_][]const u8{ "dpkg", "dpkg-divert", "dpkg-statoverride" };
        var identities: [reviewed.len][]u8 = undefined;
        var made: usize = 0;
        defer for (identities[0..made]) |identity| support.allocator.free(identity);
        for (reviewed) |tool| {
            const name = try std.mem.replaceOwned(u8, support.allocator, tool, "-", "_");
            defer support.allocator.free(name);
            const digest = auditHex(auditToolBytes(tool));
            identities[made] = try std.fmt.allocPrint(support.allocator, "script_{s}_identity version={s} architecture={s} size={d} digest={s}\n", .{
                name, audit_version, f.arch, auditToolBytes(tool).len, &digest,
            });
            made += 1;
        }
        const expected = try std.fmt.allocPrint(support.allocator, "script_dpkg_exec line=5 pid=703" ++ lineage ++ "703 argv=[\"dpkg\",\"--compare-versions\",\"\",\"lt\",\"4.8\"]\n" ++
            "script_dpkg_statoverride_exec line=7 pid=704" ++ lineage ++ "704 argv=[\"dpkg-statoverride\",\"--list\",\"/var/lib/chrony\"]\n" ++
            "script_dpkg_statoverride_exec line=9 pid=705" ++ lineage ++ "705 argv=[\"dpkg-statoverride\",\"--update\",\"--add\",\"_chrony\",\"_chrony\",\"0750\",\"/var/lib/chrony\"]\n" ++
            "script_dpkg_divert_exec line=11 pid=706" ++ lineage ++ "706 argv=[\"dpkg-divert\",\"--truename\",\"/bin/ping\"]\n" ++
            "{s}{s}{s}allowed_script_dpkg_exec=1\nallowed_script_dpkg_divert_exec=1\nallowed_script_dpkg_statoverride_exec=2\nforbidden_dpkg_exec=false\n", .{
            identities[0], identities[1], identities[2],
        });
        defer support.allocator.free(expected);
        try testing.expectEqualStrings(expected, result.stdout);
    }
    {
        // Only dpkg-statoverride's root identity is wrong: its two calls are
        // refused, while the other tools' calls stay recorded as allowed.
        try f.work.write("audit-root/usr/bin/dpkg-statoverride", auditToolBytes("dpkg"));
        const result = try auditFixture(&f, trace);
        defer result.deinit();
        try testing.expectEqual(@as(u8, 90), result.code);
        try testing.expect(std.mem.startsWith(u8, result.stdout, "script_dpkg_exec line=5 pid=703 " ++
            "script=/var/lib/debz-lifecycle-scripts/chrony.postinst script_pid=702 lineage=700>702>703 argv=["));
        try support.contains(result.stdout, "\nscript_dpkg_divert_exec line=11 pid=706 ");
        try support.contains(result.stdout, "\nforbidden_exec reason=dpkg-statoverride-identity:digest line=7 pid=704 path=\"/usr/bin/dpkg-statoverride\" ");
        try support.contains(result.stdout, "\nforbidden_exec reason=dpkg-statoverride-identity:digest line=9 pid=705 path=\"/usr/bin/dpkg-statoverride\" ");
        try testing.expect(std.mem.indexOf(u8, result.stdout, "\nscript_dpkg_statoverride_") == null);
        try testing.expect(std.mem.endsWith(u8, result.stdout, "\nallowed_script_dpkg_exec=1\nallowed_script_dpkg_divert_exec=1\nallowed_script_dpkg_statoverride_exec=0\nforbidden_dpkg_exec=true\n"));
    }
}

test "snapshot: exec audit refuses /bin dpkg-divert and dpkg-statoverride filenames even when /bin is the usrmerge link" {
    var f = try Driver.init();
    defer f.deinit();
    try writeAuditRoot(&f, audit_version, f.arch);
    try auditLink(&f, "usr/bin", "audit-root/bin");
    for ([_][]const u8{ "dpkg-divert", "dpkg-statoverride" }) |tool| {
        const arguments = if (std.mem.eql(u8, tool, "dpkg-divert")) "\"--truename\", \"/bin/ping\"" else "\"--list\", \"/var/lib/chrony\"";
        for ([_]struct { path: []const u8, argv0: []const u8, reason: ?[]const u8 }{
            .{ .path = "/usr/bin/", .argv0 = "", .reason = null },
            .{ .path = "/usr/bin/", .argv0 = "/usr/bin/", .reason = null },
            .{ .path = "/bin/", .argv0 = "", .reason = "path" },
            .{ .path = "/bin/", .argv0 = "/bin/", .reason = "path" },
            .{ .path = "/bin/", .argv0 = "/usr/bin/", .reason = "path" },
            .{ .path = "/usr/bin/", .argv0 = "/bin/", .reason = "argv0" },
        }) |case| {
            const path = try std.fmt.allocPrint(support.allocator, "{s}{s}", .{ case.path, tool });
            defer support.allocator.free(path);
            const argv = try std.fmt.allocPrint(support.allocator, "\"{s}{s}\", {s}", .{ case.argv0, tool, arguments });
            defer support.allocator.free(argv);
            const args = try dpkgArgs(path, argv);
            defer support.allocator.free(args);
            const trace = try scriptTrace(audit_script, "execve", args, "0");
            defer support.allocator.free(trace);
            const result = try auditFixture(&f, trace);
            defer result.deinit();
            if (case.reason) |reason| {
                try expectRefused(result, reason);
            } else {
                const compact = try std.mem.replaceOwned(u8, support.allocator, argv, "\", \"", "\",\"");
                defer support.allocator.free(compact);
                const name = try std.mem.replaceOwned(u8, support.allocator, tool, "-", "_");
                defer support.allocator.free(name);
                const record = try std.fmt.allocPrint(support.allocator, "script_{s}_exec line=6 pid=703" ++ audit_lineage ++ "[{s}]\n", .{ name, compact });
                defer support.allocator.free(record);
                try expectAllowedTool(result, tool, record);
            }
        }
    }
}

test "snapshot: exec audit without dpkg needs no root and unauditable input fails closed" {
    var f = try Driver.init();
    defer f.deinit();
    const quiet =
        \\700 execve("/opt/debz/bin/debz", ["debz"], 0x1 /* 1 var */) = 0
        \\700 clone(child_stack=NULL, flags=SIGCHLD) = 702
        \\702 execve("/var/lib/debz-lifecycle-scripts/tzdata.postinst", ["/var/lib/debz-lifecycle-scripts/tzdata.postinst"], 0x1 /* 1 var */) = 0
        \\702 execve("/usr/bin/dpkg-split-helper", ["dpkg-split-helper"], 0x1 /* 1 var */) = 0
        \\
    ;
    const identities = try auditIdentities("", "");
    defer support.allocator.free(identities);
    for ([_][]const u8{ "--audit-exec-trace", "--audit-exec-trace-fixture" }) |mode| {
        const passed = try auditWith(&f, mode, quiet, identities);
        defer passed.deinit();
        try passed.ok();
        try testing.expectEqualStrings(audit_no_calls ++ "forbidden_dpkg_exec=false\n", passed.stdout);
    }
    const digest = auditHex(audit_dpkg);
    const dpkg_only = try std.fmt.allocPrint(support.allocator, "dpkg={s}:{s}", .{ &digest, audit_dpkg_size });
    defer support.allocator.free(dpkg_only);
    const duplicated = try std.fmt.allocPrint(support.allocator, "{s} {s} {s}", .{ dpkg_only, dpkg_only, dpkg_only });
    defer support.allocator.free(duplicated);
    const unsized = try auditIdentities("dpkg-statoverride", "00:x");
    defer support.allocator.free(unsized);
    for ([_][]const u8{ dpkg_only, duplicated, unsized, "" }) |incomplete| {
        const refused = try auditWith(&f, "--audit-exec-trace-fixture", quiet, incomplete);
        defer refused.deinit();
        try testing.expectEqual(@as(u8, 91), refused.code);
        try testing.expectEqualStrings("", refused.stdout);
    }
    const missing_trace = try f.run(f.keyring, &.{ "--audit-exec-trace", "/nonexistent/trace", "/nonexistent/root", f.arch, audit_debz });
    defer missing_trace.deinit();
    try testing.expectEqual(@as(u8, 91), missing_trace.code);
    try support.contains(missing_trace.stderr, "exec trace unreadable");
    const unreviewed = try f.run(f.keyring, &.{ "--audit-exec-trace", "/nonexistent/trace", "/nonexistent/root", "i386", audit_debz });
    defer unreviewed.deinit();
    try testing.expectEqual(@as(u8, 91), unreviewed.code);
    try support.contains(unreviewed.stderr, "no reviewed script dpkg identity for i386");
    const usage = try f.run(f.keyring, &.{ "--audit-exec-trace", "/nonexistent/trace" });
    defer usage.deinit();
    try testing.expectEqual(@as(u8, 2), usage.code);
}

test "snapshot: script dpkg pins are per architecture and bound to the pinned snapshot" {
    const runner = try source("tools/real-snapshot-acceptance.sh");
    defer support.allocator.free(runner);
    for ([_][]const u8{
        "readonly pinned_uri=https://snapshot.ubuntu.com/ubuntu/20261001T000000Z\n",
        "readonly script_dpkg_snapshot=20261001T000000Z\n",
        "readonly script_dpkg_version=1.23.7ubuntu1\n",
        "readonly script_dpkg_amd64='972003a11f3ae0f5b2556dce1d2c2721fb5119818b9bbef1124293024fdb6517 322728'\n",
        "readonly script_dpkg_arm64='6c03c9fa2053b5a4e899438c1318ed460f62f01812da7f91f6c35a7e0957692f 330816'\n",
        "readonly script_dpkg_divert_amd64='e975eecfbceda235ecedc2e35addf5cc5abe05de355202780cf8e47b2f6745eb 125768'\n",
        "readonly script_dpkg_divert_arm64='50fd191a3a97a17ff0de4bb921ded2d877e5648e197712e8025631c09d456798 133872'\n",
        "readonly script_dpkg_statoverride_amd64='f8496aa47ff782a4881ebdf9e0a4e4615e81f8c56bc004af51f49954e315ff8c 55936'\n",
        "readonly script_dpkg_statoverride_arm64='b9c47a676498db293c4f674d63af54656d274e68b7598e235ec50f2380dba0f6 68184'\n",
        "[[ \"$pinned_uri\" == */\"$script_dpkg_snapshot\" ]]",
        "    amd64:dpkg) echo \"$script_dpkg_amd64\" ;;\n",
        "    arm64:dpkg) echo \"$script_dpkg_arm64\" ;;\n",
        "    amd64:dpkg-divert) echo \"$script_dpkg_divert_amd64\" ;;\n",
        "    arm64:dpkg-divert) echo \"$script_dpkg_divert_arm64\" ;;\n",
        "    amd64:dpkg-statoverride) echo \"$script_dpkg_statoverride_amd64\" ;;\n",
        "    arm64:dpkg-statoverride) echo \"$script_dpkg_statoverride_arm64\" ;;\n",
        "  for tool in dpkg dpkg-divert dpkg-statoverride; do\n",
        "TOOLS = (\"dpkg\", \"dpkg-divert\", \"dpkg-statoverride\")\n",
        "ACTIONS = (\"--compare-versions\", \"--validate-version\", \"--print-architecture\", \"-s\", \"-L\", \"-l\")\n",
        "REFUSED_OPTIONS = (\"--root\", \"--admindir\", \"--instdir\", \"--force\")\n",
        "tool = path[len(\"/usr/bin/\"):] if path.startswith(\"/usr/bin/\") else None\n",
        "elif tool not in TOOLS:",
        "elif not argv or argv[0] not in (tool, path):",
        "native-exec-audit.txt",
        "exec-audit-summary.txt",
    }) |required| try support.contains(runner, required);
    const workflow = try source(".github/workflows/ci.yml");
    defer support.allocator.free(workflow);
    const start = std.mem.indexOf(u8, workflow, "  ubuntu-real-snapshot:\n") orelse return error.MissingSnapshotJob;
    const job = workflow[start..];
    const collector = try source("tools/real-snapshot-protected-native-ci.sh");
    defer support.allocator.free(collector);
    try support.contains(collector, "bash tools/real-snapshot-acceptance.sh --audit-exec-trace \\\n");
    try support.contains(collector, "\"$checkout/zig-out/bin/debz\"");
    try support.contains(collector, ">\"$evidence/forbidden-exec.txt\"");
    try support.contains(job, ">>\"$GITHUB_STEP_SUMMARY\"");
    try testing.expect(std.mem.indexOf(u8, workflow, "--audit-exec-trace-fixture") == null);
    try testing.expect(std.mem.indexOf(u8, workflow, "execveat\\(") == null);
    for ([_][]const u8{ "dpkg", "dpkg_divert", "dpkg_statoverride" }) |tool| {
        const counted = try std.fmt.allocPrint(support.allocator, "sed -n 's/^allowed_script_{s}_exec=", .{tool});
        defer support.allocator.free(counted);
        try support.contains(collector, counted);
    }
    // No identity is shared across architectures or tools.
    var seen: [6][]const u8 = undefined;
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, runner, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, "readonly script_dpkg_") or std.mem.indexOfScalar(u8, line, '\'') == null) continue;
        const value = line[std.mem.indexOfScalar(u8, line, '\'').? + 1 ..];
        for (seen[0..count]) |other| try testing.expect(!std.mem.eql(u8, other[0..16], value[0..16]));
        seen[count] = value;
        count += 1;
    }
    try testing.expectEqual(@as(usize, 6), count);
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
        const item = try std.fmt.allocPrint(support.allocator, "{{\"name\":\"{s}\",\"version\":\"1\",\"architecture\":\"{s}\",\"declared_size\":1,\"archive_identity\":{{\"primary\":\"sha512\",\"digests\":[{{\"algorithm\":\"sha512\",\"digest\":\"{s}\"}}]}}}}{s}", .{ name, f.arch, zeros, if (index == 3) "" else "," });
        defer support.allocator.free(item);
        try packages.appendSlice(support.allocator, item);
    }
    const lock_text = try std.fmt.allocPrint(support.allocator, "{{\"schema\":\"https://debz.dev/schema/exact-closure-lock-v3\",\"version\":3,\"target_architecture\":\"{s}\",\"packages\":[{s}]}}\n", .{ f.arch, packages.items });
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
        cache,  f.arch,    f.workspace,
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
        "- architecture: amd64",
        "- architecture: arm64",
        "real-snapshot-acceptance.sh --validate",
        "real-snapshot-reference-protected-ci.sh\" --stage-native",
        "native \"$PROTECTED_TREE\" \"$ARCHITECTURE\" \"$GITHUB_SHA\"",
        "reference \"$PROTECTED_TREE\" \"$ARCHITECTURE\" \"$GITHUB_SHA\"",
        "rm -rf --one-file-system -- \"$tree\"",
        "name: ubuntu-real-snapshot-${{ matrix.architecture }}",
        "path: .real-snapshot/${{ matrix.architecture }}/evidence/",
    }) |required| try support.contains(job, required);
    const collector = try source("tools/real-snapshot-protected-native-ci.sh");
    defer support.allocator.free(collector);
    for ([_][]const u8{
        "exec bash \"$checkout/tools/real-snapshot-acceptance.sh\" \"$checkout/zig-out/bin/debz\"",
        "real-snapshot-reference.sh \"$REFERENCE_DPKG\"",
        "real-snapshot-comparator compare",
        "comparison-unavailable.txt",
        "[[ -f \"$evidence/reference.snapshot.json\" && -f \"$evidence/native.snapshot.json\" ]]",
        "128 * 1024 * 1024",
        "512 * 1024 * 1024",
        "artifact-summary.txt",
    }) |required| try support.contains(collector, required);
    try testing.expect(std.mem.indexOf(u8, workflow[0..start], "schedule:\n") != null);
}

fn minutesAfter(text: []const u8, marker: []const u8) !u64 {
    return numberBetween(text, marker, "\n");
}

fn numberBetween(text: []const u8, marker: []const u8, terminator: []const u8) !u64 {
    const start = (std.mem.indexOf(u8, text, marker) orelse return error.MissingTimeBudget) + marker.len;
    const end = std.mem.indexOfPos(u8, text, start, terminator) orelse return error.MissingTimeBudget;
    return std.fmt.parseInt(u64, text[start..end], 10);
}

test "snapshot: manual job budgets cover the reviewed install ceiling and the pinned reference" {
    const workflow = try source(".github/workflows/ci.yml");
    defer support.allocator.free(workflow);
    const start = std.mem.indexOf(u8, workflow, "  ubuntu-real-snapshot:\n") orelse return error.MissingSnapshotJob;
    const job = workflow[start..];
    const job_minutes = try minutesAfter(job, "\n    timeout-minutes: ");
    const native_minutes = try minutesAfter(job, "- name: Create and replay exact native Ubuntu root\n        timeout-minutes: ");
    const reference_minutes = try minutesAfter(job, "- name: Install exact closure with pinned dpkg reference\n        timeout-minutes: ");
    const staging_minutes = try minutesAfter(job, "- name: Stage protected native checkout, toolchain, dpkg and trust root\n        timeout-minutes: ");
    const diagnostics_minutes = try minutesAfter(job, "- name: Collect bounded protected native diagnostics\n        if: always()\n        timeout-minutes: ");
    const runner = try source("tools/real-snapshot-acceptance.sh");
    defer support.allocator.free(runner);
    const ceiling_minutes = try numberBetween(runner, "readonly maximum_install_ceiling_seconds=$((", " * 60))\n");
    try testing.expectEqual(@as(u64, 320), job_minutes);
    try testing.expectEqual(@as(u64, 20), staging_minutes);
    try testing.expectEqual(@as(u64, 220), native_minutes);
    try testing.expectEqual(@as(u64, 50), reference_minutes);
    try testing.expectEqual(@as(u64, 15), diagnostics_minutes);
    // Refresh, planning, download, verification and the zero-action update
    // need their own budget beyond the install ceiling; the reference keeps
    // its 40-minute pinned-dpkg limit; protected setup and export are separate.
    try testing.expect(native_minutes >= ceiling_minutes + 30);
    try testing.expect(reference_minutes >= 45);
    try testing.expect(job_minutes >= staging_minutes + native_minutes + reference_minutes + diagnostics_minutes + 15);
    const reference = try source("tools/real-snapshot-reference.sh");
    defer support.allocator.free(reference);
    try support.contains(reference, "timeout --signal=TERM --kill-after=30s 40m");
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
        "strace -f --seccomp-bpf -qq -yy -s 4096 --pidns-translation -e signal=none\n      -e trace=execve,execveat,fork,vfork,clone,clone3 -o \"$evidence/$name.execve\"",
        "readonly operation_limit=30m",
        "readonly verification_limit=10m",
        "readonly maximum_install_progress_limit_seconds=$((20 * 60))",
        "readonly maximum_install_ceiling_seconds=$((180 * 60))",
        "install progress bounds may only tighten the reviewed limits",
        "kill -ALRM \"$pid\"",
        "--kill-after=30s \"$((install_ceiling_seconds + 30))s\"",
        "candidate execution trace missing",
        "outside the reviewed script exception during",
        "unexpected candidate stderr during",
        "candidate package claims excluded chroot device",
        "update-zero-actions.txt",
    }) |required| try support.contains(runner, required);
}

test "snapshot: every in-tree real-snapshot pin is a reviewed repin manifest identity" {
    const tool = "tools/real-snapshot-repin.py";
    const passed = try support.runWithTimeout(&.{ "python3", tool, "check" }, .inherit, 120);
    defer passed.deinit();
    try passed.ok();
    try support.contains(passed.stdout, "check passed: ");

    const manifest = try source("tools/fixtures/real-snapshot/pin-v1.json");
    defer support.allocator.free(manifest);
    const identities = std.mem.indexOf(u8, manifest, "\"identities\": [") orelse return error.MissingIdentities;
    const marker = "\"digest\": \"sha256:";
    const at = (std.mem.indexOfPos(u8, manifest, identities, marker) orelse return error.MissingIdentityDigest) + marker.len;
    manifest[at] = if (manifest[at] == '0') '1' else '0';
    var work = try support.Work.init();
    defer work.deinit();
    try work.write("pin.json", manifest);
    const path = try work.path("pin.json");
    defer support.allocator.free(path);
    const failed = try support.runWithTimeout(&.{ "python3", tool, "check", "--manifest", path }, .inherit, 120);
    defer failed.deinit();
    try testing.expectEqual(@as(u8, 1), failed.code);
    try failed.failsWith("does not pin sha256:");
    try failed.failsWith("is absent from the manifest");
}
