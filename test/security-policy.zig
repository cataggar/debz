const std = @import("std");
const testing = std.testing;
const support = @import("tooling-test-support.zig");

const Fixture = struct {
    work: support.Work,
    arena: std.heap.ArenaAllocator,

    fn init() !Fixture {
        return .{ .work = try support.Work.init(), .arena = std.heap.ArenaAllocator.init(support.allocator) };
    }

    fn deinit(self: *Fixture) void {
        self.work.deinit();
        self.arena.deinit();
    }

    fn path(self: *Fixture, relative: []const u8) ![]const u8 {
        return std.fmt.allocPrint(self.arena.allocator(), "{s}/{s}", .{ self.work.root, relative });
    }

    fn source(self: *Fixture, relative: []const u8) ![]const u8 {
        return std.Io.Dir.cwd().readFileAlloc(support.io, relative, self.arena.allocator(), .limited(8 * 1024 * 1024));
    }

    fn replace(self: *Fixture, text: []const u8, original: []const u8, new: []const u8) ![]const u8 {
        const index = std.mem.indexOf(u8, text, original) orelse {
            std.debug.print("missing mutation target '{s}'\n", .{original});
            return error.MissingMutationTarget;
        };
        return std.fmt.allocPrint(self.arena.allocator(), "{s}{s}{s}", .{ text[0..index], new, text[index + original.len ..] });
    }

    fn check(self: *Fixture, kind: []const u8, text: []const u8) !support.Result {
        try self.work.write("check-input", text);
        return support.runWithTimeout(
            &.{ "python3", "tools/security-audit.py", "check", kind, try self.path("check-input") },
            .inherit,
            if (std.mem.startsWith(u8, kind, "digest-")) 120 else 30,
        );
    }
};

fn nativeCheck(f: *Fixture, kind: []const u8, path: []const u8, text: ?[]const u8) !support.Result {
    const input = try std.json.Stringify.valueAlloc(f.arena.allocator(), .{ .path = path, .text = text }, .{});
    return f.check(kind, input);
}

fn nativeMutations(f: *Fixture, kind: []const u8, path: []const u8, tokens: []const []const u8) !void {
    const source = try f.source(path);
    const valid = try nativeCheck(f, kind, path, source);
    defer valid.deinit();
    try valid.ok();
    for (tokens) |token| {
        const changed = try f.replace(source, token, "");
        const refused = try nativeCheck(f, kind, path, changed);
        defer refused.deinit();
        if (refused.code == 0) std.debug.print("unchecked {s} mutation in {s}: {s}\n", .{ kind, path, token });
        try testing.expectEqual(@as(u8, 1), refused.code);
        try refused.failsWith("security-audit:");
    }
}

fn nativeMutationsIn(
    f: *Fixture,
    kind: []const u8,
    path: []const u8,
    start: []const u8,
    end: []const u8,
    tokens: []const []const u8,
) !void {
    const source = try f.source(path);
    const first = std.mem.indexOf(u8, source, start) orelse return error.MissingMutationScope;
    const last = std.mem.indexOfPos(u8, source, first + start.len, end) orelse return error.MissingMutationScope;
    const body = source[first..last];
    const valid = try nativeCheck(f, kind, path, source);
    defer valid.deinit();
    try valid.ok();
    for (tokens) |token| {
        const changed = try f.replace(source, body, try f.replace(body, token, ""));
        const refused = try nativeCheck(f, kind, path, changed);
        defer refused.deinit();
        if (refused.code == 0) std.debug.print("unchecked {s} mutation in {s}: {s}\n", .{ kind, path, token });
        try testing.expectEqual(@as(u8, 1), refused.code);
        try refused.failsWith("security-audit:");
    }
}

test "security: commit-pinned composite actions reject floating refs" {
    var f = try Fixture.init();
    defer f.deinit();
    const good = try f.check("action-pin", "uses: actions/cache/restore@5a3ec84eff668545956fd18022155c47e93e2684\n");
    defer good.deinit();
    try good.ok();
    const bad = try f.check("action-pin", "uses: actions/cache/restore@v4\n");
    defer bad.deinit();
    try bad.failsWith("action.yml: actions/cache/restore is not commit-pinned");
}

test "security: Zig installer must remain exact and setup-zig or cache substitutions refuse" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_]struct { file: []const u8, kind: []const u8 }{
        .{ .file = ".github/workflows/ci.yml", .kind = "ghr-ci" },
        .{ .file = ".github/workflows/release.yml", .kind = "ghr-release" },
    }) |workflow| {
        const source = try f.source(workflow.file);
        const valid = try f.check(workflow.kind, source);
        defer valid.deinit();
        try valid.ok();
        const old = try f.replace(source, "ghr-version: v0.8.1", "ghr-version: v0.8.0");
        const invalid = try f.check(workflow.kind, old);
        defer invalid.deinit();
        try invalid.failsWith("exact verified ghr Zig install blocks");
        const obsolete = try std.fmt.allocPrint(f.arena.allocator(), "{s}\nuses: mlugg/setup-zig@deadbeef\n", .{source});
        const replaced = try f.check(workflow.kind, obsolete);
        defer replaced.deinit();
        try replaced.failsWith("obsolete setup-zig installation");
    }
}

test "security: workflow expected failures require bound outcomes, no hidden failures" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const valid = try f.check("workflow-failure", workflow);
    defer valid.deinit();
    try valid.ok();
    for ([_]struct { token: []const u8, diagnostic: []const u8 }{
        .{ .token = "test \"$OUTCOME\" = failure", .diagnostic = "expected-failure action coverage lacks outcome assertions" },
        .{ .token = "NATIVE_OUTCOME: ${{ steps.native-foreign-lock.outcome }}", .diagnostic = "native backend refusal coverage lacks bound outcome assertions" },
        .{ .token = "LEGACY_PATH: ${{ steps.legacy-foreign-lock.outputs.cache-path }}", .diagnostic = "native backend refusal coverage lacks bound outcome assertions" },
    }) |mutation| {
        const changed = try std.mem.replaceOwned(u8, f.arena.allocator(), workflow, mutation.token, "");
        const rejected = try f.check("workflow-failure", changed);
        defer rejected.deinit();
        try rejected.failsWith(mutation.diagnostic);
    }
    const hidden = try f.replace(workflow, "Refuse legacy lock in native action", "Ignore arbitrary failure");
    const rejected = try f.check("workflow-failure", hidden);
    defer rejected.deinit();
    try rejected.failsWith("workflow hides a failing command");
    for ([_]struct { id: []const u8, prefix: []const u8 }{
        .{ .id = "native-foreign-lock", .prefix = "NATIVE" },
        .{ .id = "legacy-foreign-lock", .prefix = "LEGACY" },
    }) |negative| {
        const id = try std.fmt.allocPrint(f.arena.allocator(), "id: {s}", .{negative.id});
        const outcome = try std.fmt.allocPrint(f.arena.allocator(), "{s}_OUTCOME: ${{{{ steps.{s}.outcome }}}}", .{ negative.prefix, negative.id });
        const path = try std.fmt.allocPrint(f.arena.allocator(), "{s}_PATH: ${{{{ steps.{s}.outputs.cache-path }}}}", .{ negative.prefix, negative.id });
        const assert_outcome = try std.fmt.allocPrint(f.arena.allocator(), "test \"${s}_OUTCOME\" = failure", .{negative.prefix});
        const assert_path = try std.fmt.allocPrint(f.arena.allocator(), "test -z \"${s}_PATH\"", .{negative.prefix});
        for ([_][]const u8{ id, outcome, path, assert_outcome, assert_path }) |token| {
            const mutated = try f.replace(workflow, token, "");
            const failure = try f.check("workflow-failure", mutated);
            defer failure.deinit();
            try failure.failsWith("native backend refusal coverage lacks bound outcome assertions");
        }
    }
}

test "security: required CI modes, architecture and aggregate failure propagation refuse mutations" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const valid = try f.check("ci-recovery", workflow);
    defer valid.deinit();
    try valid.ok();
    for ([_]struct { original: []const u8, changed: []const u8, message: []const u8 }{
        .{ .original = "optimize: [Debug, ReleaseSafe]", .changed = "optimize: [Debug]", .message = "both optimization modes" },
        .{ .original = "name: [linux-x64, linux-arm64]", .changed = "name: [linux-x64]", .message = "both optimization modes" },
        .{ .original = "needs: [build-and-test-workload, native-recovery-zig-workflows, native-recovery-zig-family, native-recovery-zig-scenarios]", .changed = "needs: [build-and-test-workload]", .message = "existing required build checks" },
        .{ .original = "zig build test-release -j2 --summary all", .changed = "echo skip release", .message = "Test release packaging must remain required" },
    }) |mutation| {
        const changed = try f.replace(workflow, mutation.original, mutation.changed);
        const rejected = try f.check("ci-recovery", changed);
        defer rejected.deinit();
        try rejected.failsWith(mutation.message);
    }
}

test "security: all required CI workloads and optimized-mode selections fail closed under mutation" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const workload = try job(workflow, "build-and-test-workload", "\n  native-recovery-zig-workflows:\n");
    for ([_]struct { before: []const u8, after: []const u8 }{
        .{ .before = "    timeout-minutes: 90", .after = "    timeout-minutes: 180" },
        .{ .before = "name: [linux-x64, linux-arm64]", .after = "name: [linux-x64]" },
        .{ .before = "optimize: [Debug, ReleaseSafe]", .after = "optimize: [Debug]" },
        .{ .before = "optimize: [Debug, ReleaseSafe]", .after = "optimize: [ReleaseSafe]" },
        .{ .before = "      OPTIMIZE: ${{ matrix.optimize }}", .after = "      OPTIMIZE: Debug" },
        .{ .before = "        include:", .after = "        exclude:" },
        .{ .before = "          zig build test -Doptimize=\"$OPTIMIZE\" -j2 --summary all", .after = "" },
        .{ .before = "          zig build fuzz -Doptimize=\"$OPTIMIZE\" -j2 --summary all", .after = "" },
        .{ .before = "      - name: Build and test\n", .after = "      - name: Build and test\n        if: false\n" },
        .{ .before = "-Doptimize=\"$OPTIMIZE\"", .after = "-Doptimize=Debug" },
        .{ .before = "test-native-materialization test-native-conffiles", .after = "test-native-materialization" },
        .{ .before = "test-native-differential", .after = "" },
        .{ .before = "test-native-lifecycle-zig test-native-triggers-zig test-native-diversion-settlement-zig", .after = "test-native-lifecycle-zig test-native-triggers-zig" },
        .{ .before = "test-native-lifecycle-zig-oracle test-native-triggers-zig-oracle test-native-triggers-zig-settlement-reference", .after = "test-native-lifecycle-zig-oracle test-native-triggers-zig-oracle" },
        .{ .before = "test-native-diversion-settlement-zig \\\n            -Dnative-reference-dpkg=\"$reference_dpkg\"", .after = "test-native-diversion-settlement-zig \\\n            -Dnative-reference-dpkg=\"$untrusted_dpkg\"" },
        .{ .before = "      - name: Exercise standalone Zig workspace selectors and fail-closed combinations\n", .after = "      - name: Exercise standalone Zig workspace selectors and fail-closed combinations\n        if: false\n" },
        .{ .before = "          zig build build-native-acceptance-zig -Doptimize=\"$OPTIMIZE\" -j2 --summary all", .after = "" },
        .{ .before = "            zig-out/bin/native-lifecycle-zig-acceptance --oracle-only --diversions-only \\", .after = "" },
        .{ .before = "            zig-out/bin/native-trigger-zig-acceptance --oracle-only --diversion-settlement-reference-only \\", .after = "" },
        .{ .before = "          grep -Fxq 'error: InvalidSettlementSelection' \"$PWD/.tmp/zig-invalid-selector.log\"", .after = "" },
        .{ .before = "          grep -Fxq 'error: PathAlreadyExists' \"$PWD/.tmp/zig-existing-workspace.log\"", .after = "" },
        .{ .before = "reference_dpkg=\"$(python3 tools/prepare-native-dpkg.py)\"", .after = "reference_dpkg=/usr/bin/dpkg" },
        .{ .before = "-Dnative-reference-dpkg=\"$reference_dpkg\"", .after = "" },
        .{ .before = "test-native-helper-namespace", .after = "test" },
        .{ .before = "        run: zig build test-release -j2 --summary all", .after = "" },
        .{ .before = "        run: zig build -Doptimize=ReleaseSafe -j2 run -- --help", .after = "" },
        .{ .before = "            \"$(command -v zig)\" build test-apt-system-acceptance \\", .after = "" },
        .{ .before = "              -Doptimize=\"$OPTIMIZE\" -j2 --summary all", .after = "" },
        .{ .before = "              -Drequire-privileged-orchestration-tests=true \\", .after = "" },
        .{ .before = "          python3 tools/generate-integration-repository.py \\", .after = "" },
        .{ .before = "        uses: ./actions/download", .after = "" },
        .{ .before = "          test \"$DOWNLOADED\" -gt 0", .after = "" },
    }) |mutation| {
        const changed_workload = try f.replace(workload, mutation.before, mutation.after);
        const changed = try f.replace(workflow, workload, changed_workload);
        const rejected = try f.check("ci-recovery", changed);
        defer rejected.deinit();
        if (rejected.code == 0) std.debug.print("CI mutation missed workload: {s}\n", .{mutation.before});
        try rejected.failsWith("ci.yml:");
    }
    const recovery = [_][]const u8{
        "    needs: [build-and-test-workload, native-recovery-zig-workflows, native-recovery-zig-family, native-recovery-zig-scenarios]",
        "    if: ${{ always() }}",
        "          BUILD_RESULT: ${{ needs.build-and-test-workload.result }}",
        "          RECOVERY_WORKFLOWS_RESULT: ${{ needs.native-recovery-zig-workflows.result }}",
        "          RECOVERY_FAMILY_RESULT: ${{ needs.native-recovery-zig-family.result }}",
        "          RECOVERY_SCENARIOS_RESULT: ${{ needs.native-recovery-zig-scenarios.result }}",
        "          test \"$BUILD_RESULT\" = success",
        "          test \"$RECOVERY_WORKFLOWS_RESULT\" = success",
        "          test \"$RECOVERY_FAMILY_RESULT\" = success",
        "          test \"$RECOVERY_SCENARIOS_RESULT\" = success",
        "          zig build test-native-recovery-zig-unit -j2 --summary all",
        "          zig build test-native-recovery-zig-unit -Doptimize=ReleaseSafe -j2 --summary all",
        "          - os: ubuntu-24.04-arm",
    };
    for (recovery) |token| {
        const changed = try f.replace(workflow, token, "");
        const rejected = try f.check("ci-recovery", changed);
        defer rejected.deinit();
        if (rejected.code == 0) std.debug.print("CI mutation missed recovery: {s}\n", .{token});
        try rejected.failsWith("ci.yml:");
    }
    for ([_][]const u8{
        "Test release packaging",                            "Check ReleaseSafe CLI help",
        "Run required privileged orchestration crash suite", "Prepare native download action fixture",
        "Prepare native exact-lock package closure",         "Validate native download action outputs",
    }) |name| {
        const selected = try step(workload, name);
        const if_start = std.mem.indexOf(u8, selected, "        if: ${{ matrix.optimize ==") orelse return error.MissingOptimizationCondition;
        const if_end = std.mem.indexOfPos(u8, selected, if_start, "\n") orelse return error.MissingOptimizationCondition;
        const disabled = try f.replace(selected, selected[if_start..if_end], "        if: false");
        const altered = try f.replace(workflow, selected, disabled);
        const refused = try f.check("ci-recovery", altered);
        defer refused.deinit();
        const diagnostic = try std.fmt.allocPrint(f.arena.allocator(), "ci.yml: {s} must remain required", .{name});
        try refused.failsWith(diagnostic);
    }
    for ([_][]const u8{
        "Build and test",
        "Run required real apt facade acceptance",
        "Compare native materialization, conffiles, differential, lifecycle, and triggers with dpkg",
        "Require private native helper namespaces",
    }) |name| {
        const shared = try step(workload, name);
        const altered = try f.replace(workflow, shared, try std.fmt.allocPrint(f.arena.allocator(), "{s}        if: false\n", .{shared}));
        const refused = try f.check("ci-recovery", altered);
        defer refused.deinit();
        try refused.failsWith("ci.yml:");
    }
    const apt_acceptance = try step(workload, "Run required real apt facade acceptance");
    for ([_][]const u8{
        "          sudo env \\",
        "            TMPDIR=\"$PWD/.zig-cache\" \\",
        "            PYTHONPYCACHEPREFIX=\"$PWD/.zig-cache/pycache\" \\",
        "            ZIG_GLOBAL_CACHE_DIR=\"$PWD/.zig-cache/apt-system-acceptance-global\" \\",
        "            ZIG_LOCAL_CACHE_DIR=\"$PWD/.zig-cache/apt-system-acceptance-local\" \\",
    }) |token| {
        const changed = try f.replace(workflow, apt_acceptance, try f.replace(apt_acceptance, token, ""));
        const refused = try f.check("ci-recovery", changed);
        defer refused.deinit();
        try refused.failsWith("ci.yml:");
    }
    const normalization = try step(workload, "Normalize apt facade acceptance diagnostics");
    const disabled = try f.replace(workflow, normalization, try f.replace(normalization, "        if: ${{ always() }}", "        if: false"));
    const refused = try f.check("ci-recovery", disabled);
    defer refused.deinit();
    try refused.failsWith("ci.yml: apt acceptance caches must be normalized for both modes");
}

fn job(workflow: []const u8, name: []const u8, next: []const u8) ![]const u8 {
    const marker = try std.fmt.allocPrint(support.allocator, "  {s}:\n", .{name});
    defer support.allocator.free(marker);
    const start = std.mem.indexOf(u8, workflow, marker) orelse return error.MissingJob;
    const end = std.mem.indexOfPos(u8, workflow, start + marker.len, next) orelse return error.MissingNextJob;
    return workflow[start..end];
}

fn step(body: []const u8, name: []const u8) ![]const u8 {
    const marker = try std.fmt.allocPrint(support.allocator, "      - name: {s}\n", .{name});
    defer support.allocator.free(marker);
    const start = std.mem.indexOf(u8, body, marker) orelse return error.MissingStep;
    const end = std.mem.indexOfPos(u8, body, start + marker.len, "\n      - ") orelse body.len;
    return body[start..end];
}

fn script(step_text: []const u8) ![]const u8 {
    const marker = "        run: |\n";
    const index = std.mem.indexOf(u8, step_text, marker) orelse return error.MissingScript;
    return step_text[index + marker.len ..];
}

test "security: required recovery shards keep every mode, selector, setup and aggregate binding" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const gate = try job(workflow, "build-and-test", "\n  security-audit:\n");
    for ([_][]const u8{
        "    needs: [build-and-test-workload, native-recovery-zig-workflows, native-recovery-zig-family, native-recovery-zig-scenarios]",
        "    if: ${{ always() }}",
        "        name: [linux-x64, linux-arm64]",
        "          BUILD_RESULT: ${{ needs.build-and-test-workload.result }}",
        "          RECOVERY_WORKFLOWS_RESULT: ${{ needs.native-recovery-zig-workflows.result }}",
        "          RECOVERY_FAMILY_RESULT: ${{ needs.native-recovery-zig-family.result }}",
        "          RECOVERY_SCENARIOS_RESULT: ${{ needs.native-recovery-zig-scenarios.result }}",
        "          test \"$BUILD_RESULT\" = success",
        "          test \"$RECOVERY_WORKFLOWS_RESULT\" = success",
        "          test \"$RECOVERY_FAMILY_RESULT\" = success",
        "          test \"$RECOVERY_SCENARIOS_RESULT\" = success",
    }) |token| {
        const changed = try f.replace(workflow, gate, try f.replace(gate, token, ""));
        const rejected = try f.check("ci-recovery", changed);
        defer rejected.deinit();
        try rejected.failsWith("ci.yml:");
    }
    const shards = [_]struct { name: []const u8, next: []const u8, targets: []const []const u8 }{
        .{ .name = "native-recovery-zig-workflows", .next = "\n  native-recovery-zig-family:\n", .targets = &.{
            "test-native-recovery-zig",        "test-native-recovery-zig-repository",
            "test-native-recovery-helper-zig", "test-native-recovery-zig-bootstrap",
            "test-native-recovery-zig-parity", "test-native-recovery-zig-rollback-clock",
        } },
        .{ .name = "native-recovery-zig-family", .next = "\n  native-recovery-zig-scenarios:\n", .targets = &.{"test-native-recovery-zig-family"} },
        .{ .name = "native-recovery-zig-scenarios", .next = "\n  arm64-dpkg-oracles:\n", .targets = &.{
            "test-native-recovery-zig-scriptless", "test-native-recovery-zig-statoverride",
            "test-native-recovery-zig-literal",    "test-native-recovery-zig-metadata",
            "test-native-recovery-zig-conffile",   "test-native-recovery-zig-final-gaps",
            "test-native-recovery-zig-diversions",
        } },
    };
    for (shards) |shard| {
        const body = try job(workflow, shard.name, shard.next);
        const timeout_minutes: u8 = if (std.mem.eql(u8, shard.name, "native-recovery-zig-scenarios")) 75 else 35;
        const timeout = try std.fmt.allocPrint(f.arena.allocator(), "    timeout-minutes: {d}", .{timeout_minutes});
        const wrong_timeout: []const u8 = if (timeout_minutes == 75) "    timeout-minutes: 35" else "    timeout-minutes: 75";
        for ([_][]const u8{
            timeout,                                   "      fail-fast: false",
            "          - os: ubuntu-24.04",            "          - os: ubuntu-24.04-arm",
            "      - name: Install Zig via ghr\n",     "      - name: Install metadata decompression and signed fixture dependencies\n",
            "python3-cryptography python3-jsonschema", "reference_dpkg=\"$(python3 tools/prepare-native-dpkg.py)\"",
        }) |token| {
            const changed = try f.replace(workflow, body, try f.replace(body, token, ""));
            const rejected = try f.check("ci-recovery", changed);
            defer rejected.deinit();
            try rejected.failsWith("ci.yml:");
        }
        const wrong_budget = try f.replace(workflow, body, try f.replace(body, timeout, wrong_timeout));
        const changed_budget = try f.check("ci-recovery", wrong_budget);
        defer changed_budget.deinit();
        try changed_budget.failsWith("ci.yml:");
        for ([_][]const u8{ timeout, wrong_timeout }) |extra_timeout| {
            const repeated_budget = try f.replace(workflow, body, try f.replace(body, timeout, try std.fmt.allocPrint(f.arena.allocator(), "{s}\n{s}", .{ timeout, extra_timeout })));
            const duplicate_budget = try f.check("ci-recovery", repeated_budget);
            defer duplicate_budget.deinit();
            try duplicate_budget.failsWith("ci.yml:");
        }
        if (std.mem.eql(u8, shard.name, "native-recovery-zig-workflows") or
            std.mem.eql(u8, shard.name, "native-recovery-zig-family"))
        {
            const changed = try f.replace(workflow, body, try f.replace(body, "          mkdir -p .tmp", ""));
            const rejected = try f.check("ci-recovery", changed);
            defer rejected.deinit();
            try rejected.failsWith("ci.yml:");
        }
        if (std.mem.eql(u8, shard.name, "native-recovery-zig-workflows")) {
            for ([_][]const u8{
                "          zig build test-native-recovery-zig-unit -j2 --summary all", "          zig build test-native-recovery-zig-unit -Doptimize=ReleaseSafe -j2 --summary all",
            }) |token| {
                const changed = try f.replace(workflow, body, try f.replace(body, token, ""));
                const rejected = try f.check("ci-recovery", changed);
                defer rejected.deinit();
                try rejected.failsWith("ci.yml:");
            }
            for ([_][]const u8{
                "          zig build test-native-recovery-zig-unit -j2 --summary all",
                "          zig build test-native-recovery-zig-unit -Doptimize=ReleaseSafe -j2 --summary all",
            }) |command| {
                const duplicate = try f.replace(workflow, body, try f.replace(body, command, try std.fmt.allocPrint(f.arena.allocator(), "{s}\n{s}", .{ command, command })));
                const repeated = try f.check("ci-recovery", duplicate);
                defer repeated.deinit();
                try repeated.failsWith("ci.yml:");
            }
        }
        for (shard.targets) |target| {
            for ([_][]const u8{ "", " -Doptimize=ReleaseSafe" }) |mode| {
                const command = try std.fmt.allocPrint(f.arena.allocator(), "          zig build {s} -Dnative-reference-dpkg=\"$reference_dpkg\"{s} -j2 --summary all", .{ target, mode });
                try testing.expectEqual(@as(usize, 1), std.mem.count(u8, body, command));
                const absent = try f.replace(workflow, body, try f.replace(body, command, ""));
                const removed = try f.check("ci-recovery", absent);
                defer removed.deinit();
                try removed.failsWith("ci.yml:");
                const duplicate = try f.replace(workflow, body, try f.replace(body, command, try std.fmt.allocPrint(f.arena.allocator(), "{s}\n{s}", .{ command, command })));
                const repeated = try f.check("ci-recovery", duplicate);
                defer repeated.deinit();
                try repeated.failsWith("ci.yml:");
            }
        }
        const exercises: []const []const u8 = if (std.mem.eql(u8, shard.name, "native-recovery-zig-workflows"))
            &.{ "Exercise Zig recovery units in both modes", "Exercise Zig core, repository, and helper recovery" }
        else if (std.mem.eql(u8, shard.name, "native-recovery-zig-family"))
            &.{"Exercise Zig signed FAMILY recovery"}
        else
            &.{"Exercise Zig recovery scenario and diversion matrices"};
        for (exercises) |exercise| {
            const selected = try step(body, exercise);
            const skipped = try f.replace(workflow, selected, try f.replace(selected, try std.fmt.allocPrint(f.arena.allocator(), "      - name: {s}\n", .{exercise}), try std.fmt.allocPrint(f.arena.allocator(), "      - name: {s}\n        if: false\n", .{exercise})));
            const rejected = try f.check("ci-recovery", skipped);
            defer rejected.deinit();
            try rejected.failsWith("ci.yml:");
        }
    }
    try testing.expect(std.mem.indexOf(u8, workflow, "\n  native-recovery:\n") == null);
    const legacy = try f.replace(workflow, "  native-recovery-zig-workflows:\n", "      - name: Duplicate complete recovery suite\n        run: |\n          zig build test-native-recovery -j2 --summary all\n\n  native-recovery-zig-workflows:\n");
    const repeated_legacy = try f.check("ci-recovery", legacy);
    defer repeated_legacy.deinit();
    try repeated_legacy.failsWith("retired recovery job or duplicate complete aggregate");
    const duplicate = try std.fmt.allocPrint(f.arena.allocator(), "{s}\n  duplicate-recovery:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Duplicate signed FAMILY recovery\n        run: |\n          zig build test-native-recovery-zig-family -Dnative-reference-dpkg=\"$reference_dpkg\" -j2 --summary all\n", .{workflow});
    const extra = try f.check("ci-recovery", duplicate);
    defer extra.deinit();
    try extra.failsWith("ci.yml: recovery targets must execute only in the three required Zig shards");
}

test "security: aggregate gate rejects failure, cancellation, skip and unknown job results" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const gate = try job(workflow, "build-and-test", "\n  security-audit:\n");
    const commands = try script(try step(gate, "Require every build and native recovery shard"));
    const states = [_][]const u8{ "success", "failure", "cancelled", "skipped", "unknown" };
    for (states) |build| {
        for (states) |workflows| {
            for (states) |family| {
                for (states) |scenarios| {
                    const build_var = try std.fmt.allocPrint(f.arena.allocator(), "BUILD_RESULT={s}", .{build});
                    const workflows_var = try std.fmt.allocPrint(f.arena.allocator(), "RECOVERY_WORKFLOWS_RESULT={s}", .{workflows});
                    const family_var = try std.fmt.allocPrint(f.arena.allocator(), "RECOVERY_FAMILY_RESULT={s}", .{family});
                    const scenarios_var = try std.fmt.allocPrint(f.arena.allocator(), "RECOVERY_SCENARIOS_RESULT={s}", .{scenarios});
                    const result = try support.run(&.{ "env", build_var, workflows_var, family_var, scenarios_var, "bash", "-e", "-c", commands });
                    defer result.deinit();
                    try testing.expectEqual(
                        std.mem.eql(u8, build, "success") and std.mem.eql(u8, workflows, "success") and
                            std.mem.eql(u8, family, "success") and
                            std.mem.eql(u8, scenarios, "success"),
                        result.code == 0,
                    );
                }
            }
        }
    }
}

test "security: Debug and ReleaseSafe build workloads execute all commands and propagate failures" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const workload = try job(workflow, "build-and-test-workload", "\n  native-recovery-zig-workflows:\n");
    const commands = try script(try step(workload, "Build and test"));
    for ([_][]const u8{ "Debug", "ReleaseSafe" }) |mode| {
        const optimize = try std.fmt.allocPrint(f.arena.allocator(), "OPTIMIZE={s}", .{mode});
        const printed = try std.fmt.allocPrint(f.arena.allocator(), "build -Doptimize={s} -j2 --summary all\nbuild test -Doptimize={s} -j2 --summary all\nbuild fuzz -Doptimize={s} -j2 --summary all\n", .{ mode, mode, mode });
        const stdout_script = try std.fmt.allocPrint(f.arena.allocator(), "zig() {{ printf '%s\\n' \"$*\"; }}\n{s}", .{commands});
        const valid = try support.run(&.{ "env", optimize, "bash", "-e", "-c", stdout_script });
        defer valid.deinit();
        try valid.ok();
        try testing.expectEqualStrings(printed, valid.stdout);
        const fail_script = try std.fmt.allocPrint(f.arena.allocator(), "zig() {{ test \"$*\" != \"$FAIL_COMMAND\"; }}\n{s}", .{commands});
        var lines = std.mem.splitScalar(u8, printed, '\n');
        while (lines.next()) |line| {
            if (line.len == 0) continue;
            const failing = try std.fmt.allocPrint(f.arena.allocator(), "FAIL_COMMAND={s}", .{line});
            const rejected = try support.run(&.{ "env", optimize, failing, "bash", "-e", "-c", fail_script });
            defer rejected.deinit();
            try testing.expect(rejected.code != 0);
        }
    }
}

test "security: dependency linkage and release-only static runtime metadata fail closed" {
    var f = try Fixture.init();
    defer f.deinit();
    const build = try f.source("build.zig");
    const current_options = try f.check("dependency-zstd", build);
    defer current_options.deinit();
    try current_options.ok();
    const missing_static = try f.replace(build, ".shared = false,", ".shared = true,");
    const rejected = try f.check("dependency-zstd", missing_static);
    defer rejected.deinit();
    try rejected.failsWith("zstd: build option .shared must be false");
    const install = try f.check("release-install-metadata", build);
    defer install.deinit();
    try install.ok();
    const ordinary = try f.replace(
        build,
        ".{ .source = \"THIRD_PARTY_NOTICES\", .destination = \"share/doc/debz/THIRD_PARTY_NOTICES\" },",
        ".{ .source = \"THIRD_PARTY_NOTICES\", .destination = \"share/doc/debz/THIRD_PARTY_NOTICES\" },\n" ++
            "        .{ .source = \"security/runtime-dependencies.json\", .destination = \"share/debz/runtime-dependencies.json\" },",
    );
    const misplaced = try f.check("release-install-metadata", ordinary);
    defer misplaced.deinit();
    try misplaced.failsWith("ordinary install graph contains static-musl runtime metadata");
    const runtime = try f.source("security/runtime-dependencies.json");
    const valid_runtime = try f.check("runtime-metadata", runtime);
    defer valid_runtime.deinit();
    try valid_runtime.ok();
    const dynamic = try f.replace(runtime, "\"fully_static\": true", "\"fully_static\": false");
    const invalid_runtime = try f.check("runtime-metadata", dynamic);
    defer invalid_runtime.deinit();
    try testing.expect(invalid_runtime.code != 0);
    try support.contains(invalid_runtime.stderr, "runtime");
}

test "security: new raw package authority, schema digest field and fixed cache layout are rejected" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_]struct { path: []const u8, text: []const u8, diagnostic: []const u8 }{
        .{
            .path = "src/new_package_authority.zig",
            .text = "pub const Package = struct {\n    package_sha256: [32]u8,\n};\n",
            .diagnostic = "raw 32 byte field",
        },
        .{
            .path = "src/new_control.zig",
            .text = "const Control = struct {\n    policy_sha256: [32]u8,\n};\n",
            .diagnostic = "raw 32 byte field",
        },
        .{
            .path = "schema/example-v3.json",
            .text = "{\"$id\":\"https://debz.dev/schema/example-v3\",\"type\":\"object\",\"properties\":{\"package_digest\":{\"$ref\":\"#/$defs/sha256\"}},\"$defs\":{\"sha256\":{\"type\":\"string\",\"pattern\":\"^[0-9a-f]" ++ "{" ++ "64}$\"}}}",
            .diagnostic = "schema sha256 field",
        },
        .{
            .path = "src/new_cache.zig",
            .text = "const object_path = \"objects/" ++ "{sha256}\";\n",
            .diagnostic = "fixed sha256 cas",
        },
    }) |mutation| {
        const fixture = try std.json.Stringify.valueAlloc(f.arena.allocator(), .{ .path = mutation.path, .text = mutation.text }, .{});
        const rejected = try f.check("digest-semantic", fixture);
        defer rejected.deinit();
        try rejected.failsWith(mutation.diagnostic);
    }
    const positive = try f.check("digest-semantic", "{\"path\":\"src/typed_authority.zig\",\"text\":\"pub const Identity = struct {};\"}");
    defer positive.deinit();
    try positive.ok();
}

test "security: frozen digest inventory, typed authority, and narrow reviewed compatibility" {
    var f = try Fixture.init();
    defer f.deinit();
    const inventory = try std.json.Stringify.valueAlloc(f.arena.allocator(), .{
        .path = "src/content_digest.zig",
        .append = "",
    }, .{});
    const valid = try f.check("digest-inventory", inventory);
    defer valid.deinit();
    try valid.ok();
    const drift = try std.json.Stringify.valueAlloc(f.arena.allocator(), .{
        .path = "src/content_digest.zig",
        .append = "\n// sha256 inventory drift canary\n",
    }, .{});
    const rejected = try f.check("digest-inventory", drift);
    defer rejected.deinit();
    try rejected.failsWith("digest policy finding inventory changed");
    const policy = try f.source("security/digest-cutover-policy.json");
    const baseline = try f.check("digest-allowlist", policy);
    defer baseline.deinit();
    try baseline.ok();
    const overbroad = try f.replace(policy, "\"src/content_digest.zig\"\n      ],", "\"src/*\"\n      ],");
    const widened = try f.check("digest-allowlist", overbroad);
    defer widened.deinit();
    try widened.failsWith("digest semantic allowlist contains an invalid or overbroad entry");
    try support.contains(policy, "\"historical_versioned_compatibility\"");
    try support.contains(try f.source("src/content_digest.zig"), "pub const Identity = struct");
}

test "security: digest audit includes nonignored untracked files and reviewed policy" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.work.write("src/sha512_transaction_e2e_test.zig", "pub const typed = true;\n");
    try f.work.write("src/ignored.ignore", "generated");
    try f.work.write(".gitignore", "*.ignore\n");
    try f.work.write("security/digest-cutover-policy.json", "{}\n");
    const created = try support.run(&.{ "git", "init", "-q", f.work.root });
    defer created.deinit();
    try created.ok();
    const fixture = try std.json.Stringify.valueAlloc(f.arena.allocator(), .{ .root = f.work.root }, .{});
    const discovered = try f.check("digest-untracked", fixture);
    defer discovered.deinit();
    try discovered.ok();
    try support.contains(discovered.stdout, "src/sha512_transaction_e2e_test.zig\n");
    try support.contains(discovered.stdout, "security/digest-cutover-policy.json\n");
    try testing.expect(std.mem.indexOf(u8, discovered.stdout, "ignored.ignore") == null);
}

test "security: docs gate ignores disposable snapshot payloads but rejects stale repository links" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.work.write("doc/local.md", "[missing](missing.md)\n");
    try f.work.write(".real-snapshot/root/usr/share/doc/vendor.md", "[missing](missing.md)\n");
    const root_fixture = try std.json.Stringify.valueAlloc(f.arena.allocator(), .{ .root = f.work.root }, .{});
    const rejected = try f.check("docs-links", root_fixture);
    defer rejected.deinit();
    try rejected.failsWith("doc/local.md: stale local link: missing.md");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, rejected.stderr, "stale local link"));
    try f.work.write("doc/missing.md", "existing\n");
    const allowed = try f.check("docs-links", root_fixture);
    defer allowed.deinit();
    try allowed.ok();
    try f.work.directory.dir.symLink(support.io, "missing.md", "doc/linked.md", .{});
    const symlink = try f.check("docs-links", root_fixture);
    defer symlink.deinit();
    try symlink.failsWith("docs fixture contains a symlink");
}

test "security: reviewed musl toolchain, static runtime, and vulnerability dispositions are pinned" {
    var f = try Fixture.init();
    defer f.deinit();
    const policy = try f.source("security/dependency-policy.json");
    var parsed = try std.json.parseFromSlice(std.json.Value, f.arena.allocator(), policy, .{});
    defer parsed.deinit();
    const dependencies = parsed.value.object.get("production_dependencies").?.array.items;
    var count: usize = 0;
    for (dependencies) |dependency| {
        if (!std.mem.eql(u8, dependency.object.get("name").?.string, "musl")) continue;
        count += 1;
        try testing.expectEqualStrings("1.2.5", dependency.object.get("upstream_version").?.string);
        try testing.expectEqualStrings("0.16.0", dependency.object.get("toolchain_version").?.string);
        try testing.expectEqualStrings("24fdd5b7a4c1c8b5deb5b56756b9dbc8e08c86a8", dependency.object.get("toolchain_commit").?.string);
        try testing.expectEqualStrings("MIT", dependency.object.get("license").?.string);
        try testing.expectEqualStrings("static_libc_in_debz", dependency.object.get("runtime_linkage").?.string);
        const exceptions = dependency.object.get("reviewed_exceptions").?.array.items;
        try testing.expectEqual(@as(usize, 3), exceptions.len);
        for ([_]struct { id: []const u8, disposition: []const u8 }{
            .{ .id = "CVE-2025-26519", .disposition = "patched_in_toolchain" },
            .{ .id = "CVE-2026-40200", .disposition = "not_affected" },
            .{ .id = "CVE-2026-6042", .disposition = "not_linked" },
        }) |reviewed| {
            var found = false;
            for (exceptions) |exception| {
                if (std.mem.eql(u8, exception.object.get("id").?.string, reviewed.id)) {
                    try testing.expectEqualStrings(reviewed.disposition, exception.object.get("disposition").?.string);
                    found = true;
                }
            }
            try testing.expect(found);
        }
    }
    try testing.expectEqual(@as(usize, 1), count);
    const runtime = try f.source("security/runtime-dependencies.json");
    const audited = try f.check("runtime-metadata", runtime);
    defer audited.deinit();
    try audited.ok();
}

test "security: apt import and native child-process owners retain explicit boundaries" {
    var f = try Fixture.init();
    defer f.deinit();
    const apt = try f.source("src/target_apt_config.zig");
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, apt, "std.process.run("));
    for ([_][]const u8{
        ".environ_map = &environ",
        "const sources_list_path = \"/etc/apt/sources.list\";",
        "const global_keyring_directory_path = \"/etc/apt/trusted.gpg.d\";",
    }) |marker| try support.contains(apt, marker);
    const owners = [_][]const u8{
        "apt_system_command.zig", "apt_system_orchestrator.zig", "live_root.zig",
        "maintainer_script.zig",  "native_unpack.zig",           "production_backend.zig",
    };
    var directory = try std.Io.Dir.cwd().openDir(support.io, "src", .{ .iterate = true });
    defer directory.close(support.io);
    var files = directory.iterate();
    var scanned: usize = 0;
    var found: usize = 0;
    while (try files.next(support.io)) |entry| {
        scanned += 1;
        if (scanned > 256) return error.TooManySourceFiles;
        if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
        try testing.expect(entry.kind == .file);
        const source = try directory.readFileAlloc(support.io, entry.name, f.arena.allocator(), .limited(8 * 1024 * 1024));
        const owns_child = std.mem.indexOf(u8, source, "linux.fork(") != null or
            std.mem.indexOf(u8, source, "linux.execve(") != null or
            std.mem.indexOf(u8, source, "linux.chroot(") != null;
        var expected_owner = false;
        for (owners) |owner| {
            if (std.mem.eql(u8, owner, entry.name)) expected_owner = true;
        }
        try testing.expectEqual(expected_owner, owns_child);
        if (owns_child) found += 1;
        if (!std.mem.eql(u8, entry.name, "apt_system_orchestrator.zig")) {
            const owns_namespace = std.mem.indexOf(u8, source, "linux.unshare(") != null or
                std.mem.indexOf(u8, source, "linux.setns(") != null or
                std.mem.indexOf(u8, source, "linux.mount(") != null or
                std.mem.indexOf(u8, source, "linux.move_mount(") != null or
                std.mem.indexOf(u8, source, "linux.umount2(") != null;
            try testing.expectEqual(std.mem.eql(u8, entry.name, "live_root.zig") or
                std.mem.eql(u8, entry.name, "maintainer_script.zig"), owns_namespace);
        }
    }
    try testing.expectEqual(owners.len, found);
    for ([_][]const u8{ "apt_system_command.zig", "native_unpack.zig", "production_backend.zig" }) |name| {
        const path = try std.fmt.allocPrint(f.arena.allocator(), "src/{s}", .{name});
        const text = try f.source(path);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, text, "linux.fork()"));
        try testing.expect((std.mem.indexOf(u8, text, "linux.fork()") orelse return error.MissingFork) >
            (std.mem.indexOf(u8, text, "\ntest \"") orelse return error.MissingOwnerTest));
    }
    const unpack = try f.source("src/native_unpack.zig");
    try testing.expect((std.mem.indexOf(u8, unpack, "fn testFreshDatabaseInstall(") orelse return error.MissingUnpackSetup) <
        (std.mem.indexOf(u8, unpack, "linux.fork()") orelse return error.MissingFork));
    const backend = try f.source("src/production_backend.zig");
    try support.contains(backend, "_ = linux.kill(pid, .KILL);");
    try support.contains(backend, "linux.waitpid(pid, &status, 0)");
    const runner = try f.source("src/maintainer_script.zig");
    try testing.expect(std.mem.indexOf(u8, runner, "std.process.run(") == null);
    for ([_][]const u8{
        "linux.open(\"/dev/null\"",        "linux.chroot(\".\")",           "linux.unshare(linux.CLONE.NEWNS)",
        "live_root.cloneMountDescriptor(", "live_root.setMountAttributes(", "linux.move_mount(",
    }) |marker| try support.contains(runner, marker);
    const live = try f.source("src/live_root.zig");
    try testing.expect(std.mem.indexOf(u8, live, "std.process.run(") == null);
    for ([_][]const u8{
        "linux.unshare(linux.CLONE.NEWNS)", "linux.mount(",      ".open_tree,",
        ".mount_setattr,",                  "linux.move_mount(",
    }) |marker| try support.contains(live, marker);
    const orchestrator = try f.source("src/apt_system_orchestrator.zig");
    const first_test = std.mem.indexOf(u8, orchestrator, "\ntest \"") orelse return error.MissingOrchestratorTests;
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, orchestrator, "linux.fork()"));
    try testing.expect((std.mem.indexOf(u8, orchestrator, "linux.fork()") orelse return error.MissingFork) > first_test);
    for ([_][]const u8{
        "linux.unshare(", "linux.setns(", "linux.mount(", "linux.move_mount(", "linux.umount2(",
    }) |marker| {
        var position: usize = 0;
        while (std.mem.indexOfPos(u8, orchestrator, position, marker)) |match| {
            try testing.expect(match > first_test);
            position = match + marker.len;
        }
    }
}

test "security: download action consumes opaque CLI-owned archive and pinned blob API" {
    var f = try Fixture.init();
    defer f.deinit();
    const manifest = try f.source("actions/download/package.json");
    var parsed = try std.json.parseFromSlice(std.json.Value, f.arena.allocator(), manifest, .{});
    defer parsed.deinit();
    const deps = parsed.value.object.get("dependencies").?.object;
    try testing.expect(deps.get("@actions/cache") == null);
    try testing.expectEqualStrings("12.31.0", deps.get("@azure/storage-blob").?.string);
    const cache = try f.source("actions/download/src/cache.ts");
    try support.contains(cache, "GetCacheEntryDownloadURL");
    try support.contains(cache, "downloadToFile(");
    try testing.expect(std.mem.indexOf(u8, cache, "restoreCache(") == null);
    try support.contains(try f.source("src/package_cache_archive.zig"), "pub const format_id = \"debz-package-cache-archive-v1\"");
}

test "security: install action uses pinned bundles and validates before emitting result" {
    var f = try Fixture.init();
    defer f.deinit();
    const manifest = try f.source("actions/install/package.json");
    var parsed = try std.json.parseFromSlice(std.json.Value, f.arena.allocator(), manifest, .{});
    defer parsed.deinit();
    const deps = parsed.value.object.get("dependencies").?.object;
    try testing.expectEqual(@as(usize, 1), deps.count());
    try testing.expectEqualStrings("3.0.1", deps.get("@actions/core").?.string);
    const runner = try f.source("actions/install/src/subprocess.ts");
    for ([_][]const u8{ "setup', 'dist', 'main', 'index.js", "download', 'dist', 'index.js", "DEBZ_DOWNLOAD_EXECUTABLE" }) |marker|
        try support.contains(runner, marker);
    try testing.expect(std.mem.indexOf(u8, runner, "shell: true") == null);
    const action = try f.source("actions/install/src/action.ts");
    try testing.expect((std.mem.indexOf(u8, action, "const download = await composition.download") orelse return error.MissingDownload) <
        (std.mem.indexOf(u8, action, "buildInstallArguments(inputs)") orelse return error.MissingInstall));
    try testing.expect((std.mem.indexOf(u8, action, "validateTransactionSummary(") orelse return error.MissingValidation) <
        (std.mem.indexOf(u8, action, "io.setOutput('transaction-result'") orelse return error.MissingResult));
}

test "security: policy-check inputs are regular and bounded, not symlink or special files" {
    var f = try Fixture.init();
    defer f.deinit();
    try f.work.directory.dir.symLink(support.io, "check-input", "linked-input", .{});
    const linked = try support.run(&.{ "python3", "tools/security-audit.py", "check", "action-pin", try f.path("linked-input") });
    defer linked.deinit();
    try linked.failsWith("check input must be a regular file");
    const huge = try f.arena.allocator().alloc(u8, 1024 * 1024 + 1);
    @memset(huge, 'x');
    const large = try f.check("action-pin", huge);
    defer large.deinit();
    try large.failsWith("at most 1 MiB");
    const oversized_native = try f.arena.allocator().alloc(u8, 2 * 1024 * 1024 + 1);
    @memset(oversized_native, 'x');
    const rejected_native = try f.check("native-final", oversized_native);
    defer rejected_native.deinit();
    try rejected_native.failsWith("at most 2 MiB");
}

test "security: recovery bootstrap, signed consumer, and repository evidence are inventoried" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{
        "test/native_recovery_bootstrap.zig",
        "test/native_recovery_parity_evidence.zig",
        "test/native_recovery_repository.zig",
    }) |path| {
        const fixture = try std.json.Stringify.valueAlloc(f.arena.allocator(), .{ .path = path, .append = "\n// sha256 evidence mutation canary\n" }, .{});
        const rejected = try f.check("digest-inventory", fixture);
        defer rejected.deinit();
        try rejected.failsWith("digest policy finding inventory changed");
    }
}

test "security: signed consumer receipts enforce retained proof and final database" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "native-consumer", "test/native_recovery_parity.zig", &.{
        "try retained.verify(fixture, root, arch, digest, case.exit_status != 0);",
        "try support.absent(fixture, try relative(fixture, root, completion_path));",
    });
    try nativeMutations(&f, "native-consumer", "test/native_recovery_parity_evidence.zig", &.{
        "try debz.native_provenance.verifyEvidence(allocator, root, proof);",
        "try finalDatabase(allocator, root, architecture, proof);",
        "try equal(&proof.request_sha256, &caller.caller.request_sha256);",
    });
}

test "security: projected repository evidence and chunked secret scan refuse mutations" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "native-repository", "test/native_recovery_repository.zig", &.{
        "try terminalEvidence(fixture, root, relative, case, resuming, logical, retained_bytes, helper_before.?);",
        "try parity_evidence.verifyProjected(fixture, root, debz.live_root.logical_root_path, state.state.architecture,",
        "try unchangedBindings(fixture, root, state.state, abandoned.record, publisher.record);",
        "try checkpointAt(fixture, root, checkpoint);",
        "try checkHelper(fixture, root, original_helper orelse return error.MissingRepositoryHelper);",
        "try scanQuerySecret(fixture.io, fixture.dir, path);",
        "const count = reader.interface.readSliceShort(buffer[overlap .. overlap + 64 * 1024]) catch return reader.err.?;",
        "if (std.mem.indexOf(u8, buffer[0 .. overlap + count], secret) != null)",
        "std.mem.copyForwards(u8, buffer[0..next_overlap], buffer[end - next_overlap .. end]);",
        "test \"repository network evidence scans large files and split secrets\"",
        "try std.testing.expectError(error.NetworkFixtureLeakedCredential, assertNoQuerySecret(&fixture, root));",
        "else if (std.mem.eql(u8, case, \"deadline\")) \"15000\" else \"60000\"",
        "(std.mem.eql(u8, case, \"deadline\") and elapsed >= 20000)",
        "std.debug.print(\"repository CLI {s}: exit={s}, diagnostic={s}; expected resource limit\\n\", .{",
        "return error.InvalidRepositoryDeadlineDiagnostic;",
        "try std.testing.expectEqual(@as(u64, 20), try cliWatchdog(&.{ \"--deadline-ms\", \"15000\" }, 0, \"deadline\"));",
    });
}

test "security: report provenance readers reject unbound paths and symlinks" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_]struct { path: []const u8, token: []const u8 }{
        .{ .path = "test/native_recovery_oracle.zig", .token = "if (!std.mem.eql(u8, reported, expected)) return error.UnboundRecoveryProof;" },
        .{ .path = "test/native_recovery_acceptance.zig", .token = "_ = try oracle.reportProvenancePath(report.provenance_path orelse return error.MissingReportBinding, provenance_path);" },
        .{ .path = "test/native_recovery_scriptless.zig", .token = "const proof_path = try reportProvenancePath(report.value.provenance_path);" },
        .{ .path = "test/native_recovery_conffile.zig", .token = "const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);" },
        .{ .path = "test/native_recovery_literal.zig", .token = "const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);" },
        .{ .path = "test/native_recovery_metadata.zig", .token = "const proof_path = try process.reportProvenancePath(recovered.value.provenance_path);" },
        .{ .path = "test/native_recovery_statoverride.zig", .token = "const proof_path = try process.reportProvenancePath(report.value.provenance_path);" },
        .{ .path = "test/native_recovery_unit.zig", .token = "try sandbox.dir.symLink(sandbox.io, external, \"var/lib/debz/proof.json\", .{});" },
    }) |mutation| try nativeMutations(&f, "native-report", mutation.path, &.{mutation.token});
}

test "security: core completion and ordinary recovery remain executed and bound" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "native-core", "build.zig", &.{
        "recovery_helper.addArtifactArg(recovery_helper_executable);",
        "recovery_helper.addArtifactArg(native_lifecycle_tests);",
        "b.step(\"test-native-recovery-helper-zig\",",
    });
    try nativeMutations(&f, "native-core", "test/native_recovery_helper.zig", &.{
        "try completedWithoutLiveHelper(&fixture, driver, reference.executable, reference.architecture);",
        "try missingPackageOwnedHelper(&fixture, driver, reference.architecture);",
        "try rehashedCallerPolicy(&fixture, driver, reference.architecture);",
        "try afterActiveClearLegacyEvidence(&fixture, driver, reference.executable, reference.architecture);",
        "\"NativeHelperBootstrapOwnerMissing\"",
        "\"RecoveryRequestBindingMismatch\"",
        "\"after_active_clear\"",
        "try sealJsonDigest(fixture, &persisted.value, \"debz-native-execution-request-v1\\x00\");",
        "debz.native_recovery.sealIntent(&altered_intent);",
        "const orphaned = try projected.rootInventory(fixture, root, false);",
        "try std.testing.expectEqualSlices(u8, orphaned, try projected.rootInventory(fixture, root, false));",
        "try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, directory), old_proof.document);",
        ".config_content = config,",
        "const config = \"#!/bin/sh\\n# config:1\\nprintf '%s\\\\n' 'config:1' >> /config-invoked\\nexit 97\\n\";",
        "try std.testing.expectEqualSlices(u8, before, try projected.rootInventory(fixture, root, true));",
        "try same(try bytes(fixture, root, \"var/lib/dpkg/tmp.ci/config\", 64 * 1024), config);",
        "try missing(fixture, root, \"var/lib/dpkg/info/\" ++ foundation.package ++ \".config\");",
        "try missing(fixture, root, \"config-invoked\");",
    });
    try nativeMutationsIn(&f, "native-core", "test/native_recovery_helper.zig", "fn rehashedCallerPolicy(", "\nfn afterActiveClearLegacyEvidence(", &.{"            .isolated_helper = false,"});
    try nativeMutations(&f, "native-core", "test/native_lifecycle_support.zig", &.{
        "config_content: ?[]const u8 = null,",
        "try fixture.write(config, configuration, 0o755);",
    });
    try nativeMutationsIn(&f, "native-core", "test/native_recovery_helper.zig", "fn recoveredOrdinary(", "\nfn blockedUnknown(", &.{
        "if (try invoke(fixture, driver, root, arch, crash_output, .{",
        "try fixture.dir.deleteFile(fixture.io, archive_relative);",
        "const request = try originalRequestFor(fixture, root, intent.intent, case.isolated_helper, case.caller_owned, archive);",
        "if (reference_exit != (if (case.known_preinst_failure)",
        "try foundation.compare(fixture.*, expected, root, comparison);",
        "try verifyProofFor(fixture, root, repeated.value, intent.intent, request, proof_outcome, true, case.isolated_helper, case.caller_owned);",
        "try std.testing.expectEqualSlices(u8, root_before, try projected.rootInventory(fixture, root, case.caller_owned));",
        "try sameHelper(fixture, root, helper_before);",
        ".acknowledge = true,",
    });
    try nativeMutations(&f, "native-core", "test/native_recovery_helper.zig", &.{
        "try recoveredOrdinary(",
        "\"after_execution_intent\", \"during_filesystem_publication\",\n        \"after_script_outcome\",   \"after_provenance\",",
        "\"typed-runtime-known-failure\" else \"caller-known-failure\"",
        "\"after_execution_intent\", \"during_filesystem_publication\", \"during_database_publication\",\n        \"after_script_prepared\",  \"after_script_outcome\",          \"after_provenance\",",
        ".name = \"known-failure-compensation\",",
    });
}

test "security: final recovery matrix and prior completion are mutation enforced" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "native-final", "test/native_recovery_helper.zig", &.{
        "if (!claim.value.object.swapRemove(changing)) return error.InvalidRootClaim;",
        "\"generation\", \"state\", \"phase\", \"step\", \"updated_unix\", \"digest_sha256\"",
        "try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, false);",
        "try blockedUnknown(&fixture, driver, reference.executable, reference.architecture, true);",
        "try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, false);",
        "try triggerOutcome(&fixture, driver, reference.executable, reference.architecture, true);",
        "for ([_]Corruption{ .intent, .progress, .artifact, .managed_root, .completed_phase }) |which|",
        "try corruptedOrdinary(&fixture, driver, reference.architecture, which);",
    });
    try nativeMutationsIn(&f, "native-final", "test/native_recovery_helper.zig", "fn blockedUnknown(", "\nfn triggerOutcome(", &.{
        "\"after_upgrade_postrm_return_before_outcome\" else \"after_script_return_before_outcome\"",
        "try same(try text(script.value, \"outcome\"), \"in_flight\");",
        "try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, scenario.native_root));",
        "try same(try stickyActiveClaim(fixture, scenario.native_root), original_claim);",
    });
    try nativeMutationsIn(&f, "native-final", "test/native_recovery_helper.zig", "fn triggerOutcome(", "\nconst Corruption =", &.{
        "\"after_trigger_outcome\"",
        "if (events.value.events.len != 2) return error.IncorrectTriggerEventCount;",
        "observed[0].origin != .automatic or observed[1].origin != .dynamic",
        "try same(observed[1].trigger, \"debz-b\");",
        ".acknowledge = true,",
    });
    try nativeMutationsIn(&f, "native-final", "test/native_recovery_helper.zig", "fn corruptedOrdinary(", "\nfn caseRun(", &.{
        ".scripts = .{ .only_postinst = corruption == .completed_phase },",
        "if (artifact != null) return error.DuplicateRetainedArtifact;",
        "raw[0] = 'X';",
        "\"corrupt\\n\"",
        "\"external replacement\\n\"",
        "try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, root));",
        "try same(try stickyActiveClaim(fixture, root), original_claim);",
    });
    try nativeMutations(&f, "native-final", "test/native_lifecycle_support.zig", &.{
        "only_postinst: bool = false,",
        "if (options.only_postinst and !std.mem.eql(u8, kind, \"postinst\")) continue;",
    });
    try nativeMutationsIn(&f, "native-final", "src/native_unpack.zig", "var preexisting = try completion_store.read(allocator);", "if (record.provenance == .pending)", &.{
        "previous.bindsRecord(record)",
        "record.provenance == .published",
        "record.generation - previous.record_generation != 1",
        "record.provenance_sha256 == null",
        "root_operation.provenanceDigest(record, .{",
        ".document_sha256 = previous.digest_sha256,",
        "!std.mem.eql(u8, &record.provenance_sha256.?, &published_digest)",
        "!std.mem.eql(u8, prior_evidence, current_evidence)",
        "if (!retained_completion) try completion_store.publish(allocator, statement.document);",
    });
    try nativeMutations(&f, "native-final", "src/native_unpack.zig", &.{"var preexisting = try completion_store.read(allocator);"});
}

test "security: recovery entry points execute expected output shape and modes" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "native-entry", "test/native_recovery_acceptance.zig", &.{
        "const archive = try support.makePackage(fixture, arch, \"1\", foundation.package, packages, .{});",
        "const archive = try support.makePackage(fixture, arch, \"1\", foundation.package, \"deadline-startup/packages\", .{});",
        "const archive = try support.makePackage(fixture, arch, \"1\", foundation.package, \"deadline-persisted/packages\", .{});",
        "try support.scripts(fixture, source, foundation.package, \"1\");",
        "try rootAbsent(fixture, root, \"config-invoked\");",
        "try debz.native_provenance.verifyEvidence(fixture.allocator, debz.root_fs.Root.init(fixture.io, guarded), typed_proof.document);",
        "var request = try debz.native_execution_request.decodePersisted(fixture.allocator, request_bytes);",
        "if (scripts == 0) return error.MissingCoreScriptOutcome;",
        "try debz.native_recovery.validateScriptOutcome(outcome.value);",
        "try oracle.validateHelperInvocation(fixture.allocator, root, helper.source_path, helper.target_path, helper.sha256,",
        "try oracle.validateScriptTrace(fixture.allocator, trace, &invocations);",
    });
    try nativeMutations(&f, "native-entry", "test/native_recovery_projected_workflows.zig", &.{
        "try readOnlyProjection(fixture, runner, driver, arch);",
        "DEBZ_NATIVE_PROJECTION_FIXTURE=1",
        "native_transaction_result.test.projected root external fixture...OK",
        "apt_system_orchestrator.test.projected native dispatch external fixture...OK",
        "if (!std.mem.eql(u8, before, try evidenceInventory(fixture, root, true)))",
    });
    try nativeMutations(&f, "native-entry", ".github/workflows/ci.yml", &.{
        "          zig build test-native-recovery-zig -Dnative-reference-dpkg=\"$reference_dpkg\" -j2 --summary all",
        "          zig build test-native-recovery-zig -Dnative-reference-dpkg=\"$reference_dpkg\" -Doptimize=ReleaseSafe -j2 --summary all",
    });
}

test "security: complete recovery selector graph and pinned fixture handoffs refuse mutation" {
    var f = try Fixture.init();
    defer f.deinit();
    const build = try f.source("build.zig");
    const valid = try nativeCheck(&f, "native-gate", "build.zig", build);
    defer valid.deinit();
    try valid.ok();
    for ([_][]const u8{ "tools/test-native-recovery.py", "tools/test_native_recovery.py" }) |entry| {
        const restored = try std.fmt.allocPrint(f.arena.allocator(), "{s}\n\"{s}\"\n", .{ build, entry });
        const refused = try nativeCheck(&f, "native-gate", "build.zig", restored);
        defer refused.deinit();
        try refused.failsWith("retired Python recovery gate was restored");
    }
    try nativeMutationsIn(&f, "native-gate", "build.zig", "const selectors = [_]bool{", "\n    var selected:", &.{
        "native_core_only,",           "native_deadline_only,",      "native_script_failure_only,",
        "repository_projection_only,", "repository_execution_only,", "repository_cli_only,",
        "native_parity_only,",         "native_helper_only,",        "native_diversions_only,",
    });
    try nativeMutations(&f, "native-gate", "build.zig", &.{
        "native_recovery.dependOn(&run_native_recovery_tests.step);",
        "native_recovery.dependOn(&run_recovery_unit_tests.step);",
        "native_recovery.dependOn(&run_repository_recovery_unit.step);",
        "if (selected > 1 or focused)",
        "focused Zig case options cannot narrow the complete test-native-recovery gate",
        "zig_core_only or zig_deadline_only or family_executed_only or",
        "parity_case != null or bootstrap_case != null or repository_case != null or diversion_case != null",
        "if (native_core_only or zig_core_only) recovery_zig.addArg(\"--core-only\");",
        "if (native_deadline_only or zig_deadline_only) recovery_zig.addArg(\"--deadline-only\");",
        "if (native_script_failure_only or native_core_only) recovery_helper.addArg(\"--script-failure-only\");",
        "if (repository_projection_only) recovery_family.addArg(\"--projection-only\");",
        "if (repository_projection_only) repository_recovery.addArg(\"--projection-only\");",
        "if (repository_execution_only) repository_recovery.addArg(\"--execution-only\");",
        "if (repository_cli_only) repository_recovery.addArg(\"--cli-only\");",
        "recovery_family.addArtifactArg(native_trigger_helper);",
        "recovery_family.addArtifactArg(cli);",
        "recovery_bootstrap.addArtifactArg(native_trigger_helper);",
        "repository_recovery.addArtifactArg(cli);",
        "const repository_fixture_parent = b.addSystemCommand(&.{ \"mkdir\", \"-p\", b.pathFromRoot(\".tmp\") });",
        "run_repository_recovery_unit.step.dependOn(&repository_fixture_parent.step);",
        "repository_recovery.step.dependOn(&repository_fixture_parent.step);",
        "recovery_parity.addArtifactArg(cli);",
        "recovery_parity.addArtifactArg(native_trigger_helper);",
        "}) |runner| runner.addArgs(&.{ \"--reference-dpkg\", path });",
    });
    try nativeMutationsIn(&f, "native-gate", "build.zig", "if (native_deadline_only) {\n            native_recovery.dependOn(", "\n    if (b.option([]const u8, \"native-reference-dpkg\"", &.{
        "native_recovery.dependOn(&recovery_zig.step);",
        "native_recovery.dependOn(&recovery_helper.step);",
        "native_recovery.dependOn(&recovery_bootstrap.step);",
        "native_recovery.dependOn(&recovery_diversions.step);",
        "native_recovery.dependOn(&recovery_family.step);",
        "native_recovery.dependOn(&repository_recovery.step);",
    });
    try nativeMutationsIn(&f, "native-gate", "build.zig", "} else if (native_parity_only) {", "} else if (native_core_only) {", &.{
        "recovery_parity,",     "recovery_diversions,", "statoverride_recovery,",
        "conffile_recovery,",   "metadata_recovery,",   "literal_recovery,",
        "scriptless_recovery,",
    });
    try nativeMutationsIn(&f, "native-gate", "build.zig", "} else if (native_core_only) {", "        } else {\n            for ([_]*std.Build.Step.Run{", &.{
        "recovery_zig,",        "recovery_helper,",       "recovery_bootstrap,", "recovery_family,",
        "recovery_diversions,", "statoverride_recovery,", "conffile_recovery,",  "metadata_recovery,",
        "literal_recovery,",
    });
    try nativeMutationsIn(&f, "native-gate", "build.zig", "        } else {\n            for ([_]*std.Build.Step.Run{\n                recovery_zig,       recovery_family", "\n    if (b.option([]const u8, \"native-reference-dpkg\"", &.{
        "recovery_zig,",        "recovery_family,",       "recovery_parity,",     "recovery_helper,",
        "final_gaps,",          "recovery_bootstrap,",    "repository_recovery,", "rollback_clock,",
        "scriptless_recovery,", "statoverride_recovery,", "literal_recovery,",    "metadata_recovery,",
        "conffile_recovery,",   "recovery_diversions,",
    });
    try nativeMutationsIn(&f, "native-gate", "build.zig", "    if (b.option([]const u8, \"native-reference-dpkg\"", "    if (b.option(\n        []const u8,\n        \"native-reference-architecture\"", &.{
        "recovery_zig,",        "recovery_family,",       "recovery_parity,",     "recovery_helper,",
        "final_gaps,",          "recovery_bootstrap,",    "repository_recovery,", "rollback_clock,",
        "scriptless_recovery,", "statoverride_recovery,", "literal_recovery,",    "metadata_recovery,",
        "conffile_recovery,",   "recovery_diversions,",
    });
    for ([_][]const u8{
        "native-zig-recovery-family-fixture-python",
        "native-zig-recovery-parity-fixture-python",
        "native-repository-fixture-python",
    }) |option| {
        try nativeMutations(&f, "native-gate", "build.zig", &.{option});
    }
    try nativeMutations(&f, "native-gate", "build.zig", &.{
        "recovery_family.addArgs(&.{ \"--fixture-python\", path });",
        "recovery_parity.addArgs(&.{ \"--fixture-python\", path });",
        "repository_recovery.addArgs(&.{ \"--fixture-python\", python });",
    });
    for ([_][]const u8{
        "if (script_failure_only) {",                                                               "\"after_failure_outcome\", \"after_script_failure_state\"",
        "try knownScriptFailures(&fixture, driver, reference.executable, reference.architecture);",
    }) |token| try nativeMutations(&f, "native-gate", "test/native_recovery_helper.zig", &.{token});
    try nativeMutations(&f, "native-gate", "test/native_recovery_family.zig", &.{
        "if (projection_only) {",
        "try projected.runReadOnly(&fixture, self orelse return error.MissingSelf, driver, reference.architecture);",
    });
    try nativeMutations(&f, "native-gate", "test/native_recovery_projected_workflows.zig", &.{
        "try readOnlyProjection(fixture, runner, driver, arch);",
    });
    try nativeMutations(&f, "native-gate", "test/native_recovery_repository.zig", &.{
        "const selected = try selectMode(false, projection_only, execution_only, cli_only);",
        "selected == null or selected == .projection or selected == .execution or selected == .cli",
    });
}

test "security: signed FAMILY and projected workflow acceptance refuse unwired evidence" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "native-workflow", "build.zig", &.{
        "recovery_family.addArg(\"--self\");",
        "recovery_family.addArtifactArg(native_lifecycle_tests);",
        "recovery_family.addArg(\"--cli\");",
        "recovery_family.addArtifactArg(cli);",
    });
    try nativeMutations(&f, "native-workflow", "test/native_recovery_family.zig", &.{
        "return projected.inside(init, allocator, root);",
        "try ordinaryFamilyTimeline(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try verificationRefusals(fixture, driver, request, returned, original_summary, \"executed\");",
        "try verificationRefusals(fixture, driver, original, first_completion, summary, name);",
        "const no_result_path = try support.path(fixture.allocator, name, \"verify-first-without-result\");",
        "const equivalent_path = try support.path(fixture.allocator, name, \"verify-create-as-customize\");",
        "try assertFamilySummary(fixture, driver, original, first_completion, summary, try support.path(fixture.allocator, name, \"verify-final\"));",
        "try batchWorkflow(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        "try ownedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ordinaryKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try publicVerify(fixture, cli, scenario.native_root, lock, arch, \"executed/workflow-batch/verify-after-refusals\", true);",
        "try reconciliation(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);",
        "try ordinaryRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);",
        "try publicVerify(fixture, cli, scenario.native_root, lock, arch, try support.path(fixture.allocator, name, \"verify-public-recovered\"), true);",
        "try ownedRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try ownedFinalizationBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
        "try projected.run(&fixture, self orelse return error.MissingSelf, driver, reference.executable, reference.architecture);",
        "try assertFamilySummary(fixture, driver, request, completion, summary, try support.path(fixture.allocator, prefix, \"refuse-unsettled-verified-again\"));",
        "const root_before = try projected.rootInventory(fixture, request.root, true);",
        "const pending_evidence = try projected.rootInventory(fixture, scenario.native_root, true);",
        "const before_evidence = try projected.rootInventory(fixture, update.native_root, true);",
        "\"executed/{s}-verify-without-result\"",
        "\"executed/{s}-verify-as-install\"",
        "const failed_evidence = try projected.rootInventory(fixture, scenario.native_root, true);",
        ".force = invocation.force,",
        "\"wrong-conffile\"",
        "\"{s}/replacement-{s}\"",
        "\"changed-request\"",
        "\"verify-damaged-{s}\"",
        "\"verify-unresolved-{s}\"",
        "\"verify-partial-acknowledgment\"",
        "\"acknowledge-damaged-receipt\"",
        "\"verify-public-owner-retained\"",
        "\"verify-terminal-foreign-attempt\"",
        "\"verify-public-pending\"",
        "\"verify-public-native-acknowledged\"",
        "\"verify-public-pending-failure\"",
        "\"verify-public-failed-acknowledgment\"",
        "\"verify-public-final-failure\"",
        "\"verify-success-as-failure\"",
        "\"verify-pending-as-released\"",
        "\"executed/workflow-owned-success/verify-finalized-as-released\"",
        "try inspectInstalledFamily(fixture, driver, scenario.native_root, arch, \"executed/inspect-initial\", \"essential-core\", true, false);",
        "\"executed/inspect-while-root-lock-held\"",
        "\"executed/inspect-failed-same-root\"",
        "\"executed/missing-helper-inspection\"",
        "const reference_failure = \"executed/same-root-failure-reference\";",
        "linux.flock(holder.handle, 2 | 4)",
        "\"verify-before-execution\"",
        "\"verify-failed-result\"",
        "\"verify-relabeled-failure\"",
        "\"verify-failed-without-result\"",
        "\"ordinary-to-FAMILY same-root timeline: signed success, full verification refusals, failed install and clean recovery matched pinned dpkg",
        "\"semantic request\") == null",
        "try std.testing.expectEqual(@as(i64, 3), (try field(update_lock_document.value, \"version\")).integer);",
        "try std.testing.expectEqual(@as(usize, 24), parsed.value.object.count());",
        "try std.testing.expectEqual(@as(usize, 13), capability.value.object.count());",
        "try std.testing.expectEqual(@as(usize, 24), verified.report.value.object.count());",
        "try std.testing.expectEqual(@as(i64, 3), (try field(install_lock.value, \"version\")).integer);",
        "try referenceSingleFailure(fixture, reference, scenario.reference_root, arch, name)",
        "\"verify-public-finalized\"",
        "try support.compare(fixture, scenario.reference_root, scenario.native_root, \"executed/same-root-failure-comparison\", true);",
    });
    try nativeMutations(&f, "native-workflow", "test/native_recovery_projected_workflows.zig", &.{
        "for ([_][]const u8{ \"success\", \"recovered\", \"failed\" }) |outcome|",
        "\"/usr/bin/unshare\", \"--mount\", \"--pid\", \"--fork\"",
        ".prepare_acknowledged_review = .{ .lock_sha256 = lock_digest, .generation = 6 },",
        ".prepare_cleared_review = .{ .lock_sha256 = lock_digest, .receipt_sha256 = receipt_digest, .generation = 8 },",
        "const evidence_before = if (step.verification) |check|",
        "const review_baseline = try evidenceInventory(fixture, scenario.native_root, false);",
        "return inventory(fixture, root, \".\", include_metadata);",
        "const damaged_state = try evidenceInventory(fixture, scenario.native_root, true);",
        "const orphan_state = try evidenceInventory(fixture, scenario.native_root, true);",
        "try std.testing.expectEqual(@as(i64, 2), (try field(owner_v2.value, \"version\")).integer);",
        "try support.absent(fixture, withheld_operation);",
    });
}

test "security: signed FAMILY allocation boundaries retain each scenario reset" {
    var f = try Fixture.init();
    defer f.deinit();
    const path = "test/native_recovery_family.zig";
    try nativeMutations(&f, "native-workflow", path, &.{
        "const source = try fixture.absolute(\"executed/workflow.sources\");\n    const keyring = try fixture.absolute(\"executed/repository/fixture-keyring.gpg\");\n    var phase_arena: std.heap.ArenaAllocator = .init(init.gpa);",
        "fixture.allocator = phase_arena.allocator();",
        "defer fixture.allocator = allocator;",
        "const lock = try persistent_allocator.dupe(u8, try fixture.absolute(\"executed/lock.json\"));",
        "first_completion = try std.json.parseFromSlice(std.json.Value, persistent_allocator,",
        "    for ([_]bool{ true, false }) |selected| {\n        _ = phase_arena.reset(.free_all);",
    });
    const source = try f.source(path);
    for ([_]struct { call: []const u8, indent: []const u8 }{
        .{ .call = "try refusals(&fixture, reference.architecture);", .indent = "        " },
        .{ .call = "try transport(&fixture, driver, reference.architecture);", .indent = "        " },
        .{ .call = "try planning(&fixture, driver);", .indent = "        " },
        .{ .call = "try activeInspection(&fixture, driver, reference.architecture);", .indent = "    " },
        .{ .call = "try archiveExecution(&fixture, allocator, &phase_arena, driver, helper orelse return error.MissingHelper, reference.executable, reference.architecture, python, source, keyring);", .indent = "    " },
        .{ .call = "try ordinaryFamilyTimeline(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);", .indent = "    " },
        .{ .call = "try batchWorkflow(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);", .indent = "    " },
        .{ .call = "try ownedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);", .indent = "    " },
        .{ .call = "try reconciliation(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);", .indent = "    " },
        .{ .call = "try ordinaryRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli orelse return error.MissingPublicCli);", .indent = "    " },
        .{ .call = "try ordinaryKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);", .indent = "    " },
        .{ .call = "try ownedAbandon(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring);", .indent = "    " },
        .{ .call = "try ownedRecoveryBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);", .indent = "    " },
        .{ .call = "try ownedKnownFailure(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);", .indent = "    " },
        .{ .call = "try ownedFinalizationBoundaries(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);", .indent = "    " },
        .{ .call = "try projected.run(&fixture, self orelse return error.MissingSelf, driver, reference.executable, reference.architecture);", .indent = "    " },
        .{ .call = "try missingHelper(&fixture, driver, reference.executable, reference.architecture);", .indent = "    " },
        .{ .call = "try failedTransaction(&fixture, driver, reference.executable, reference.architecture, false);", .indent = "    " },
    }) |scenario| {
        const before = try std.fmt.allocPrint(f.arena.allocator(), "{s}\n{s}_ = phase_arena.reset(.free_all);", .{ scenario.call, scenario.indent });
        const changed = try f.replace(source, before, scenario.call);
        const rejected = try nativeCheck(&f, "native-workflow", path, changed);
        defer rejected.deinit();
        try testing.expectEqual(@as(u8, 1), rejected.code);
        try rejected.failsWith("scenario allocations retained after");
    }
    for ([_]struct { original: []const u8, weakened: []const u8 }{
        .{
            .original = "first_completion = try std.json.parseFromSlice(std.json.Value, persistent_allocator,",
            .weakened = "first_completion = try std.json.parseFromSlice(std.json.Value, fixture.allocator,",
        },
        .{
            .original = "        _ = phase_arena.reset(.free_all);\n        const label:",
            .weakened = "        const label:",
        },
        .{
            .original = "    }\n    _ = phase_arena.reset(.free_all);\n    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);",
            .weakened = "    }\n    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);",
        },
        .{
            .original = "try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);\n    _ = phase_arena.reset(.free_all);\n    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, true);",
            .weakened = "try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, false);\n    try interruptedFamilyRecovery(fixture, driver, helper, reference, arch, source, keyring, first_completion.?.value, true);",
        },
    }) |mutation| {
        const changed = try f.replace(source, mutation.original, mutation.weakened);
        const rejected = try nativeCheck(&f, "native-workflow", path, changed);
        defer rejected.deinit();
        try testing.expectEqual(@as(u8, 1), rejected.code);
        try rejected.failsWith("security-audit: native_recovery_family.zig:");
    }
}

test "security: lifecycle gates retain reference refusals and required Zig selectors" {
    var f = try Fixture.init();
    defer f.deinit();
    const build = try f.source("build.zig");
    const valid = try nativeCheck(&f, "native-lifecycle", "build.zig", build);
    defer valid.deinit();
    try valid.ok();
    for ([_][]const u8{
        "tools/test-native-lifecycle.py", "tools/test_native_lifecycle.py",
        "tools/test-native-triggers.py",  "tools/test_native_triggers.py",
    }) |entry| {
        const restored = try std.fmt.allocPrint(f.arena.allocator(), "{s}\n\"{s}\"\n", .{ build, entry });
        const refused = try nativeCheck(&f, "native-lifecycle", "build.zig", restored);
        defer refused.deinit();
        try refused.failsWith("retired Python acceptance gate was restored");
    }
    try nativeMutations(&f, "native-lifecycle", "build.zig", &.{
        "const native_lifecycle_step = b.step(\"test-native-lifecycle\",",
        "const native_triggers_step = b.step(\"test-native-triggers\",",
        "native_lifecycle_step.dependOn(&lifecycle_zig.step);",
        "native_triggers_step.dependOn(&trigger_zig.step);",
        "native_triggers_step.dependOn(&run_native_trigger_queue_tests.step);",
        "lifecycle_zig.addArtifactArg(native_lifecycle_tests);",
        "trigger_zig.addArtifactArg(native_lifecycle_tests);",
        "trigger_zig.addArg(\"--native-helper\");",
        "trigger_zig.addArtifactArg(native_trigger_helper);",
        "test_step.dependOn(&run_lifecycle_zig_tests.step);",
        "test_step.dependOn(&run_trigger_zig_tests.step);",
        "test_step.dependOn(&run_settlement_tests.step);",
        "b.step(\"test-native-lifecycle-zig-oracle\",",
        "b.step(\"test-native-triggers-zig-oracle\",",
        "b.step(\"test-native-triggers-zig-settlement-reference\",",
        "settlement_oracle_zig.addArgs(&.{ \"--oracle-only\", \"--diversion-settlement-reference-only\" });",
        "settlement_unit_step.dependOn(&run_settlement_lowering_tests.step);",
    });
    try nativeMutations(&f, "native-lifecycle", "test/native_trigger_acceptance.zig", &.{
        "failedPostinstUnconfiguredListener(&fixture, reference.executable, reference.architecture)",
        "fn refuseUnconfiguredListenerProgram(",
        "refuseUnconfiguredListenerProgram(&fixture, native_driver, selected, reference.executable, reference.architecture)",
        "if (oracle_only == (driver != null) or (helper != null) != (driver != null))",
        "if (settlement_reference_only and (!oracle_only or diversions_only))",
        "if (fixture.oracle_only) return;",
        "settlement.run(&fixture, native_driver, reference.executable, selected, reference.architecture)",
    });
    try nativeMutationsIn(&f, "native-lifecycle", "test/native_trigger_acceptance.zig", "fn refuseUnconfiguredListenerProgram(", "\nfn interruptedTriggerHandler(", &.{
        "case.seedWith(handler, false)",
        "report.value.detail, \"program_compile_rejected\"",
        "foundation.captureRealRoot(",
        "support.assertNoActiveEvidence(",
    });
    try nativeMutationsIn(&f, "native-lifecycle", "test/native_trigger_acceptance.zig", "fn failedPostinstUnconfiguredListener(", "\nfn refuseMalformedQueue(", &.{
        "for ([_]bool{ false, true }) |awaiting|",
        ".no_scripts = true",
        "support.reference(fixture, dpkg, root",
        "Status: install ok unpacked",
        "Status: install ok half-configured",
        "Triggers-Pending:",
        "Triggers-Awaited:",
        "queue.len != 0",
        "activation-returned",
        "exit 1",
    });
}

test "security: retired lifecycle fixtures stay import-only and all consumers remain wired" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{
        "tools/test-native-lifecycle.py", "tools/test_native_lifecycle.py",
        "tools/test-native-triggers.py",  "tools/test_native_triggers.py",
        "tools/test-native-recovery.py",  "tools/test_native_recovery.py",
    }) |path| {
        const restored = try nativeCheck(&f, "native-fixtures", path, "");
        defer restored.deinit();
        try restored.failsWith("retired Python test entry point still exists");
    }
    for ([_][]const u8{ "tools/native-lifecycle-fixtures.py", "tools/native-trigger-fixtures.py" }) |path| {
        const source = try f.source(path);
        const valid = try nativeCheck(&f, "native-fixtures", path, source);
        defer valid.deinit();
        try valid.ok();
        const missing = try nativeCheck(&f, "native-fixtures", path, null);
        defer missing.deinit();
        try missing.failsWith("required import-only fixture module is missing");
        for ([_][]const u8{
            "#!/usr/bin/env python3\n",         "\nimport argparse\n", "\ndef main() -> int:\n",
            "\nif __name__ == \"__main__\":\n",
        }) |marker| {
            const altered = try std.fmt.allocPrint(f.arena.allocator(), "{s}{s}", .{ marker, source });
            const refused = try nativeCheck(&f, "native-fixtures", path, altered);
            defer refused.deinit();
            try refused.failsWith("fixture module restored a Python CLI entry point");
        }
    }
    for ([_][]const u8{
        "tools/native-trigger-fixtures.py",              "tools/dpkg-config-reference.py",
        "actions/install/__tests__/integration.test.ts",
    }) |path| {
        const source = try f.source(path);
        const altered = try f.replace(source, "native-lifecycle-fixtures.py", "missing.py");
        const refused = try nativeCheck(&f, "native-fixtures", path, altered);
        defer refused.deinit();
        try refused.failsWith("required fixture import is missing");
    }
}
