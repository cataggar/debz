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

const ci_concurrency_block =
    \\concurrency:
    \\  group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.event.pull_request.number || github.event_name == 'push' && github.ref || github.run_id }}
    \\  cancel-in-progress: ${{ github.event_name == 'push' || github.event_name == 'pull_request' }}
;

test "security: CI concurrency cancels only superseded push and PR runs" {
    var f = try Fixture.init();
    defer f.deinit();
    const source = try f.source(".github/workflows/ci.yml");
    const valid = try f.check("ci-concurrency", source);
    defer valid.deinit();
    try valid.ok();

    for ([_]struct { from: []const u8, to: []const u8 }{
        .{ .from = ci_concurrency_block ++ "\n", .to = "" },
        .{
            .from = "cancel-in-progress: ${{ github.event_name == 'push' || github.event_name == 'pull_request' }}",
            .to = "cancel-in-progress: false",
        },
        .{
            .from = "group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.event.pull_request.number || github.event_name == 'push' && github.ref || github.run_id }}",
            .to = "group: ${{ github.workflow }}-${{ github.ref }}",
        },
        .{
            .from = "group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.event_name == 'pull_request' && github.event.pull_request.number || github.event_name == 'push' && github.ref || github.run_id }}",
            .to = "group: ${{ github.workflow }}-${{ github.event_name }}-${{ github.base_ref }}",
        },
    }) |mutation| {
        const changed = try f.replace(source, mutation.from, mutation.to);
        const refused = try f.check("ci-concurrency", changed);
        defer refused.deinit();
        try testing.expectEqual(@as(u8, 1), refused.code);
        try refused.failsWith("CI concurrency");
    }
}

const ActionCandidateMutation = enum {
    none,
    metadata,
    input,
    capability,
    bundle_capability,
    action_capability,
    action_guard,
    bundle,
    handoff,
};

fn actionCandidate(
    f: *Fixture,
    action: []const u8,
    mutation: ActionCandidateMutation,
) ![]const u8 {
    const allocator = f.arena.allocator();
    const prefix = try std.fmt.allocPrint(allocator, "actions/{s}/", .{action});
    const metadata_path = try std.fmt.allocPrint(allocator, "{s}action.yml", .{prefix});
    const inputs_path = try std.fmt.allocPrint(allocator, "{s}src/inputs.ts", .{prefix});
    const bundle_path = try std.fmt.allocPrint(allocator, "{s}dist/index.js", .{prefix});
    const child_path = try std.fmt.allocPrint(allocator, "{s}src/subprocess.ts", .{prefix});
    var metadata = try f.replace(try f.source(metadata_path), "default: legacy_dpkg", "default: native");
    const original_inputs = try f.source(inputs_path);
    var inputs = try f.replace(original_inputs, "'legacy_dpkg';", "'native';");
    inputs = try f.replace(inputs, "transactionBackend !== 'legacy_dpkg' && transactionBackend !== 'native'", "transactionBackend !== 'native'");
    inputs = try f.replace(inputs, "transaction-backend must be 'legacy_dpkg' or 'native'", "transaction-backend refuses legacy_dpkg: Recover this operation with debz >=0.3.0,<0.4.0 before installing a native-only release.");
    const default_expression = if (std.mem.eql(u8, action, "download"))
        "optionalScalar(e,\"TRANSACTION_BACKEND\")??\"native\""
    else
        "exactScalar(e,\"TRANSACTION_BACKEND\")||\"native\"";
    var bundle: []const u8 = try std.fmt.allocPrint(
        allocator,
        "const s={s};if(s!==\"native\"){{throw Error(\"legacy refusal\")}};setOutput(\"backend-capability\",\"native-transaction-execution-v1\");",
        .{default_expression},
    );
    var overrides: std.json.ObjectMap = .empty;
    if (mutation == .metadata) metadata = try f.replace(metadata, "default: native", "default: legacy_dpkg");
    if (mutation == .input) inputs = if (std.mem.eql(u8, action, "download"))
        try f.replace(inputs, "?? 'native';", "?? 'legacy_dpkg';")
    else
        try f.replace(inputs, "|| 'native';", "|| 'legacy_dpkg';");
    if (mutation == .capability) metadata = try f.replace(metadata, "  backend-capability:", "  missing-capability:");
    if (mutation == .bundle_capability) bundle = try f.replace(bundle, "\"backend-capability\"", "\"missing-capability\"");
    try overrides.put(allocator, metadata_path, .{ .string = metadata });
    try overrides.put(allocator, inputs_path, .{ .string = inputs });
    if (mutation != .bundle) try overrides.put(allocator, bundle_path, .{ .string = bundle });
    const action_path = try std.fmt.allocPrint(allocator, "{s}src/action.ts", .{prefix});
    const original_action = try f.source(action_path);
    const marker = if (std.mem.eql(u8, action, "download"))
        "  const inputs = await readInputs();"
    else
        "  const protectedFiles = await Promise.all(";
    const guarded = if (std.mem.eql(u8, action, "download"))
        try std.fmt.allocPrint(
            allocator,
            "{s}\n  if (inputs.transactionBackend !== 'native') throw new Error('legacy refusal');",
            .{marker},
        )
    else
        try std.fmt.allocPrint(
            allocator,
            "  if (inputs.transactionBackend !== 'native') throw new Error('legacy refusal');\n{s}",
            .{marker},
        );
    var action_source = try f.replace(original_action, marker, guarded);
    if (mutation == .action_capability) action_source = try f.replace(action_source, "'backend-capability'", "'missing-capability'");
    if (mutation == .action_guard) action_source = original_action;
    try overrides.put(allocator, action_path, .{ .string = action_source });
    if (std.mem.eql(u8, action, "install")) {
        const original_child = try f.source(child_path);
        const old = "const expectedBackendCapability =\n    inputs.transactionBackend === 'legacy_dpkg'\n      ? 'legacy-dpkg-execution-deprecated-v1'\n      : 'native-transaction-execution-v1';";
        var child = try f.replace(original_child, old, "const expectedBackendCapability = 'native-transaction-execution-v1';");
        if (mutation == .handoff) child = try f.replace(child, "DEBZ_DOWNLOAD_TRANSACTION_BACKEND: this.inputs.transactionBackend", "DEBZ_DOWNLOAD_TRANSACTION_BACKEND: 'legacy_dpkg'");
        try overrides.put(allocator, child_path, .{ .string = child });
    } else if (mutation == .handoff) {
        const runner_path = try std.fmt.allocPrint(allocator, "{s}src/runner.ts", .{prefix});
        const runner = try f.source(runner_path);
        const wrong = try std.mem.replaceOwned(u8, allocator, runner, "package-cache-v5", "package-cache-v3");
        try overrides.put(allocator, runner_path, .{ .string = wrong });
    }
    return std.json.Stringify.valueAlloc(allocator, .{ .action = action, .overrides = std.json.Value{ .object = overrides } }, .{});
}

test "security: both Actions rehearse native-only contracts without changing the shipped release" {
    var f = try Fixture.init();
    defer f.deinit();
    for ([_][]const u8{ "download", "install" }) |action| {
        const baseline = try f.check("actions-native-only", try std.json.Stringify.valueAlloc(
            f.arena.allocator(),
            .{ .action = action, .overrides = std.json.Value{ .object = .empty } },
            .{},
        ));
        defer baseline.deinit();
        try baseline.failsWith("action.yml: candidate transaction-backend default must be native");
        try baseline.failsWith("inputs.ts: candidate omitted backend must select native");
        try baseline.failsWith("dist/index.js: checked-in bundle is stale or accepts legacy");
        const future = try f.check("actions-native-only", try actionCandidate(&f, action, .none));
        defer future.deinit();
        try future.ok();
        for ([_]struct { mutation: ActionCandidateMutation, message: []const u8 }{
            .{ .mutation = .metadata, .message = "action.yml: candidate transaction-backend default must be native" },
            .{ .mutation = .input, .message = "inputs.ts: candidate omitted backend must select native" },
            .{ .mutation = .capability, .message = "action.yml: candidate must publish backend-capability" },
            .{ .mutation = .bundle_capability, .message = "dist/index.js: native backend-capability evidence is missing" },
            .{ .mutation = .action_capability, .message = "action.ts: native backend-capability output is missing" },
            .{ .mutation = .action_guard, .message = "action.ts: candidate must reject a forged legacy input before work" },
            .{ .mutation = .bundle, .message = "dist/index.js: checked-in bundle is stale or accepts legacy" },
            .{ .mutation = .handoff, .message = if (std.mem.eql(u8, action, "download"))
                "download runner.ts: native lock/fingerprint/cache contract is missing"
            else
                "install subprocess.ts: selected backend is not handed to download" },
        }) |negative| {
            const refused = try f.check("actions-native-only", try actionCandidate(&f, action, negative.mutation));
            defer refused.deinit();
            try refused.failsWith(negative.message);
        }
    }
}

fn productionCandidateOverrides(f: *Fixture, overrides: std.json.ObjectMap) !support.Result {
    const input = try std.json.Stringify.valueAlloc(
        f.arena.allocator(),
        .{ .overrides = std.json.Value{ .object = overrides } },
        .{},
    );
    return f.check("native-only-candidate", input);
}

fn productionCandidate(f: *Fixture, path: ?[]const u8, text: ?[]const u8) !support.Result {
    var overrides: std.json.ObjectMap = .empty;
    if (path) |relative| try overrides.put(
        f.arena.allocator(),
        relative,
        if (text) |value| .{ .string = value } else .null,
    );
    return productionCandidateOverrides(f, overrides);
}

test "security: native-only production candidate refuses shipped routes and exact negative mutations" {
    var f = try Fixture.init();
    defer f.deinit();

    const baseline = try productionCandidate(&f, null, null);
    defer baseline.deinit();
    for ([_][]const u8{
        "src/main.zig: candidate cutover task: remove CLI legacy selection/default",
        "src/cli_backend_policy.zig: candidate cutover task: remove new-execution CLI legacy fallback",
        "build.zig: candidate cutover task: change CLI shipped native-only mode",
        "src/transaction_executor.zig: legacy production dpkg/dpkg-deb command adapter remains",
        "src/transaction_executor.zig: active legacy journal recovery still launches dpkg",
        "src/transaction_recovery.zig: candidate cutover task: remove active legacy journal v4 publication/replay; retain v1-v4 decode",
        "src/root_operation.zig: candidate cutover task: remove root-operation active legacy publication default",
        "src/production_backend.zig: candidate cutover task:",
        "src/repository_backend.zig: candidate cutover task:",
        "src/package_family_backend.zig: candidate cutover task:",
        "src/apt_system_orchestrator.zig: candidate cutover task:",
        "src/target_apt_config.zig: candidate cutover task:",
        "download dist/index.js: checked-in bundle is stale or accepts legacy",
        "install dist/index.js: checked-in bundle is stale or accepts legacy",
    }) |message| try baseline.failsWith(message);
    try testing.expect(std.mem.indexOf(u8, baseline.stderr, "tools/prepare-native-dpkg.py:") == null);
    try testing.expect(std.mem.indexOf(u8, baseline.stderr, "tools/native-differential.py:") == null);

    for ([_]struct { path: []const u8, from: []const u8, to: []const u8, message: []const u8 }{
        .{ .path = "src/main.zig", .from = "var transaction_backend: debz.transaction_engine.Kind = .legacy_dpkg;", .to = "var transaction_backend: debz.transaction_engine.Kind = .native;", .message = "src/main.zig: stale reviewed inventory fingerprint" },
        .{ .path = "src/cli_backend_policy.zig", .from = ".legacy_capable => debz.transaction_engine.Kind.legacy_dpkg,", .to = ".legacy_capable => debz.transaction_engine.Kind.native,", .message = "src/cli_backend_policy.zig: stale reviewed inventory fingerprint" },
        .{ .path = "build.zig", .from = "release_cli_options.addOption(bool, \"native_only\", false);", .to = "release_cli_options.addOption(bool, \"native_only\", true);", .message = "build.zig: stale reviewed inventory fingerprint" },
        .{ .path = "actions/download/src/inputs.ts", .from = "?? 'legacy_dpkg';", .to = "?? 'native';", .message = "download inputs.ts: candidate must refuse legacy before reading lock" },
        .{ .path = "actions/install/src/inputs.ts", .from = "|| 'legacy_dpkg';", .to = "|| 'native';", .message = "install inputs.ts: candidate must refuse legacy before reading lock" },
        .{ .path = "actions/download/dist/index.js", .from = "legacy-dpkg-execution-deprecated-v1", .to = "forged-legacy-capability", .message = "actions/download/dist/index.js: stale reviewed inventory fingerprint" },
        .{ .path = "src/transaction_recovery.zig", .from = "pub fn persist(allocator:", .to = "pub fn persistLegacy(allocator:", .message = "src/transaction_recovery.zig: stale reviewed inventory fingerprint" },
        .{ .path = "src/transaction_executor.zig", .from = ".argv = invocation.argv,", .to = ".argv = &.{ \"/usr/bin/dpkg\" },", .message = "src/transaction_executor.zig: stale reviewed inventory fingerprint" },
        .{ .path = "src/live_root.zig", .from = "const forked = linux.fork();", .to = "const other = linux.syscall5(.execveat, fd, path, argv, envp, flags);\n        const forked = linux.fork();", .message = "src/live_root.zig: unreviewed/stale child-process allowance" },
        .{ .path = "src/package_family_backend.zig", .from = "const std = @import(\"std\");", .to = "const std = @import(\"std\");\nfn unreviewedLaunch() void { _ = std.process.run(allocator, io, args); }", .message = "src/package_family_backend.zig: unreviewed production child-process launch" },
        .{ .path = "tools/native-differential.py", .from = "#!/usr/bin/env python3", .to = "#!/usr/bin/env python3\n# changed oracle", .message = "tools/native-differential.py: stale reviewed inventory fingerprint" },
    }) |mutation| {
        const source = try f.source(mutation.path);
        const changed = try f.replace(source, mutation.from, mutation.to);
        const refused = try productionCandidate(&f, mutation.path, changed);
        defer refused.deinit();
        try refused.failsWith(mutation.message);
    }

    const missing = try productionCandidate(&f, "src/maintainer_script.zig", null);
    defer missing.deinit();
    try missing.failsWith("src/maintainer_script.zig: missing/unreadable candidate inventory path");
    const inventory = try f.source("security/native-only-production-policy.json");
    const changed_inventory = try f.replace(inventory, "\"linux.execve\": 1", "\"linux.execveat\": 1");
    const unreviewed = try productionCandidate(&f, "security/native-only-production-policy.json", changed_inventory);
    defer unreviewed.deinit();
    try unreviewed.failsWith("src/maintainer_script.zig: unreviewed child-process operator");
    try unreviewed.failsWith("src/maintainer_script.zig: unreviewed/stale child-process allowance");
    const stale = try f.replace(inventory, "eb546e88d64091c9", "ab546e88d64091c9");
    const wrong_fingerprint = try productionCandidate(&f, "security/native-only-production-policy.json", stale);
    defer wrong_fingerprint.deinit();
    try wrong_fingerprint.failsWith("src/transaction_executor.zig: stale reviewed inventory fingerprint");

    const live_root = try f.source("src/live_root.zig");
    const indirect = try f.replace(
        live_root,
        "const forked = linux.fork();",
        "const executed = linux.syscall5(.execveat, fd, path, argv, envp, flags);\n        const forked = linux.fork();",
    );
    var digest: [64]u8 = undefined;
    std.crypto.hash.sha2.Sha512.hash(indirect, &digest, .{});
    const updated_hash = std.fmt.bytesToHex(digest, .lower);
    const reviewed = try f.replace(
        inventory,
        "73c3b5707811b3d6d9835c7303c45bb90dd4e0d103521620e4ddfc12963a8ab97790702f886e5489d27c7cee698524d5f38fdc6ebff85b7393290a28cad10c61",
        updated_hash[0..],
    );
    var overrides: std.json.ObjectMap = .empty;
    try overrides.put(f.arena.allocator(), "src/live_root.zig", .{ .string = indirect });
    try overrides.put(f.arena.allocator(), "security/native-only-production-policy.json", .{ .string = reviewed });
    const repinned = try productionCandidateOverrides(&f, overrides);
    defer repinned.deinit();
    try repinned.failsWith("src/live_root.zig: unreviewed/stale child-process allowance");
    try testing.expect(std.mem.indexOf(u8, repinned.stderr, "src/live_root.zig: stale reviewed inventory fingerprint") == null);

    const fake_reference = try productionCandidate(&f, "tools/unreviewed-dpkg-oracle.py", "dpkg-query");
    defer fake_reference.deinit();
    try fake_reference.failsWith("candidate fixture has unknown override path");
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

const workload_needs = "    needs: [build-and-test-workload, build-and-test-workload-production, build-and-test-workload-apt-system, build-and-test-workload-native, build-and-test-workload-release, native-recovery-zig-workflows, native-recovery-zig-repository, native-recovery-zig-helper, native-recovery-zig-family, native-recovery-zig-scenarios, native-recovery-zig-diversions]";
const full_matrix_input =
    \\      run_full_matrix:
    \\        description: "Run the standard build/test matrix (off for snapshot-only validation)"
    \\        required: true
    \\        type: boolean
    \\        default: true
;
const full_matrix_condition = "github.event_name != 'workflow_dispatch' || inputs.run_full_matrix";
const aggregate_condition = "${{ always() && (" ++ full_matrix_condition ++ ") }}";
const full_integration_condition = "github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.run_full_matrix)";

const WorkloadJob = struct {
    name: []const u8,
    next: []const u8,
    partition: []const u8,
    steps: []const []const u8,
    commands: []const []const u8,
    mutations: []const []const u8,
};

const workload_jobs = [_]WorkloadJob{
    .{
        .name = "build-and-test-workload",
        .next = "\n  build-and-test-workload-production:\n",
        .partition = "test-workload-core",
        .steps = &.{ "Build and test workload core", "Check ReleaseSafe CLI help", "Prepare native download action fixture", "Prepare native exact-lock package closure", "Validate native download action outputs" },
        .commands = &.{ "build -Doptimize={s} -j2 --summary all", "build test-workload-core -Doptimize={s} -j2 --summary all" },
        .mutations = &.{
            "          zig build -Doptimize=\"$OPTIMIZE\" -j2 --summary all\n",
            "        run: zig build -Doptimize=ReleaseSafe -j2 run -- --help\n",
            "          python3 tools/generate-integration-repository.py \\\n",
            "        uses: ./actions/download\n",
            "          test \"$DOWNLOADED\" -gt 0\n",
        },
    },
    .{
        .name = "build-and-test-workload-production",
        .next = "\n  build-and-test-workload-apt-system:\n",
        .partition = "test-workload-production",
        .steps = &.{ "Build and test workload production", "Compare native triggers and diversion settlement with dpkg" },
        .commands = &.{"build test-workload-production -Doptimize={s} -j2 --summary all"},
        .mutations = &.{
            "          mkdir -p .tmp\n",
            "          reference_dpkg=\"$(python3 tools/prepare-native-dpkg.py)\"\n",
            " test-native-diversion-settlement-zig",
            "-Dnative-reference-dpkg=\"$reference_dpkg\" ",
        },
    },
    .{
        .name = "build-and-test-workload-apt-system",
        .next = "\n  build-and-test-workload-native:\n",
        .partition = "test-workload-apt-system",
        .steps = &.{ "Build and test workload apt system", "Run required real apt facade acceptance", "Normalize apt facade acceptance diagnostics", "Run required privileged orchestration crash suite", "Normalize privileged orchestration diagnostics" },
        .commands = &.{"build test-workload-apt-system -Doptimize={s} -j2 --summary all"},
        .mutations = &.{
            "            \"$(command -v zig)\" build test-apt-system-acceptance \\\n",
            "              -Doptimize=\"$OPTIMIZE\" -j2 --summary all\n",
            "              -Drequire-privileged-orchestration-tests=true \\\n",
            "            TMPDIR=\"$PWD/.zig-cache\" \\\n",
            "            PYTHONPYCACHEPREFIX=\"$PWD/.zig-cache/pycache\" \\\n",
            "            ZIG_GLOBAL_CACHE_DIR=\"$PWD/.zig-cache/apt-system-acceptance-global\" \\\n",
            "            ZIG_LOCAL_CACHE_DIR=\"$PWD/.zig-cache/apt-system-acceptance-local\" \\\n",
            "          sudo rm -rf /run/debz\n",
        },
    },
    .{
        .name = "build-and-test-workload-native",
        .next = "\n  build-and-test-workload-release:\n",
        .partition = "test-workload-native",
        .steps = &.{ "Build and test workload native", "Compare native materialization, conffiles, differential, and lifecycle with dpkg", "Require private native helper namespaces" },
        .commands = &.{"build test-workload-native -Doptimize={s} -j2 --summary all"},
        .mutations = &.{
            " test-native-conffiles",
            " test-native-differential",
            "          zig build test-native-lifecycle-zig \\\n",
            "          mkdir -p .tmp\n",
            "          zig build test-native-helper-namespace -Doptimize=\"$OPTIMIZE\" -j2 --summary all\n",
        },
    },
    .{
        .name = "build-and-test-workload-release",
        .next = "\n  native-recovery-zig-workflows:\n",
        .partition = "test-workload-release",
        .steps = &.{ "Build and test workload release", "Test release packaging", "Run pinned dpkg lifecycle and trigger reference oracles", "Exercise standalone Zig workspace selectors and fail-closed combinations" },
        .commands = &.{ "build test-workload-release -Doptimize={s} -j2 --summary all", "build fuzz -Doptimize={s} -j2 --summary all" },
        .mutations = &.{
            "          zig build fuzz -Doptimize=\"$OPTIMIZE\" -j2 --summary all\n",
            "        run: zig build test-release -j2 --summary all\n",
            " test-native-triggers-zig-settlement-reference",
            "          zig build build-native-acceptance-zig -Doptimize=\"$OPTIMIZE\" -j2 --summary all\n",
            "            zig-out/bin/native-lifecycle-zig-acceptance --oracle-only --diversions-only \\\n",
            "            zig-out/bin/native-trigger-zig-acceptance --oracle-only --diversion-settlement-reference-only \\\n",
            "          grep -Fxq 'error: InvalidSettlementSelection' \"$PWD/.tmp/zig-invalid-selector.log\"\n",
            "          grep -Fxq 'error: PathAlreadyExists' \"$PWD/.tmp/zig-existing-workspace.log\"\n",
        },
    },
};

const workload_results = [_]struct { variable: []const u8, job: []const u8 }{
    .{ .variable = "BUILD_RESULT", .job = "build-and-test-workload" },
    .{ .variable = "BUILD_PRODUCTION_RESULT", .job = "build-and-test-workload-production" },
    .{ .variable = "BUILD_APT_SYSTEM_RESULT", .job = "build-and-test-workload-apt-system" },
    .{ .variable = "BUILD_NATIVE_RESULT", .job = "build-and-test-workload-native" },
    .{ .variable = "BUILD_RELEASE_RESULT", .job = "build-and-test-workload-release" },
};

fn partitionCommand(f: *Fixture, partition: []const u8) ![]const u8 {
    return std.fmt.allocPrint(f.arena.allocator(), "          zig build {s} -Doptimize=\"$OPTIMIZE\" -j2 --summary all\n", .{partition});
}

test "security: CI dispatch matrix opt-out requires a typed default-true input" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const valid = try f.check("ci-recovery", workflow);
    defer valid.deinit();
    try valid.ok();
    for ([_][]const u8{
        "",
        try f.replace(full_matrix_input, "required: true", "required: false"),
        try f.replace(full_matrix_input, "type: boolean", "type: string"),
        try f.replace(full_matrix_input, "default: true", "default: false"),
        try f.replace(full_matrix_input, "        default: true", ""),
        try std.fmt.allocPrint(f.arena.allocator(), "{s}\n{s}", .{ full_matrix_input, full_matrix_input }),
    }) |replacement| {
        const refused = try f.check("ci-recovery", try f.replace(workflow, full_matrix_input, replacement));
        defer refused.deinit();
        try refused.failsWith("run_full_matrix must be a required boolean dispatch input defaulting to true");
    }
}

test "security: CI dispatch matrix gates preserve non-dispatch coverage on every shard" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const gate = "    if: " ++ full_matrix_condition ++ "\n";
    const first = std.mem.indexOfScalar(u8, workload_needs, '[') orelse return error.MissingNeeds;
    var names = std.mem.tokenizeAny(u8, workload_needs[first + 1 ..], ", ]");
    while (names.next()) |name| {
        const marker = try std.fmt.allocPrint(f.arena.allocator(), "  {s}:\n", .{name});
        const start = std.mem.indexOf(u8, workflow, marker) orelse return error.MissingJob;
        const end = std.mem.indexOfPos(u8, workflow, start + marker.len, "\n    steps:\n") orelse return error.MissingSteps;
        const header = workflow[start..end];
        for ([_][]const u8{
            "",
            "    if: false\n",
            "    if: inputs.run_full_matrix\n",
            "    if: github.event_name == 'pull_request' || inputs.run_full_matrix\n",
            "    if: github.event_name != 'workflow_dispatch' || inputs.run_native_real_snapshot\n",
            gate ++ gate,
        }) |replacement| {
            const changed = try f.replace(workflow, header, try f.replace(header, gate, replacement));
            const refused = try f.check("ci-recovery", changed);
            defer refused.deinit();
            try refused.failsWith(try std.fmt.allocPrint(f.arena.allocator(), "ci.yml: {s} must retain its exact dispatch matrix condition", .{name}));
        }
    }
}

test "security: CI dispatch aggregate and full integration conditions cannot hide omitted work" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    for ([_]struct { name: []const u8, next: []const u8, condition: []const u8, mutations: []const []const u8 }{
        .{
            .name = "build-and-test",
            .next = "\n  security-audit:\n",
            .condition = aggregate_condition,
            .mutations = &.{
                "${{ always() }}",
                "${{ " ++ full_matrix_condition ++ " }}",
                "${{ success() && (" ++ full_matrix_condition ++ ") }}",
                "${{ always() && inputs.run_full_matrix }}",
            },
        },
        .{
            .name = "integration-full",
            .next = "\n  ubuntu-real-snapshot:\n",
            .condition = full_integration_condition,
            .mutations = &.{
                "github.event_name == 'workflow_dispatch' && inputs.run_full_matrix",
                "github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'",
                "github.event_name == 'schedule' && inputs.run_full_matrix",
                full_matrix_condition,
            },
        },
    }) |selected| {
        const body = try job(workflow, selected.name, selected.next);
        const condition = try std.fmt.allocPrint(f.arena.allocator(), "    if: {s}\n", .{selected.condition});
        const message = try std.fmt.allocPrint(f.arena.allocator(), "ci.yml: {s} must retain its exact dispatch matrix condition", .{selected.name});
        for (selected.mutations) |mutation| {
            const changed = try f.replace(workflow, body, try f.replace(body, condition, try std.fmt.allocPrint(f.arena.allocator(), "    if: {s}\n", .{mutation})));
            const refused = try f.check("ci-recovery", changed);
            defer refused.deinit();
            try refused.failsWith(message);
        }
        for ([_][]const u8{ "", try std.fmt.allocPrint(f.arena.allocator(), "{s}{s}", .{ condition, condition }) }) |replacement| {
            const changed = try f.replace(workflow, body, try f.replace(body, condition, replacement));
            const refused = try f.check("ci-recovery", changed);
            defer refused.deinit();
            try refused.failsWith(message);
        }
    }
    const required = try job(workflow, "integration-required", "\n  integration-full:\n");
    const changed = try f.replace(workflow, required, try f.replace(required, "  integration-required:\n", "  integration-required:\n    if: " ++ full_matrix_condition ++ "\n"));
    const refused = try f.check("ci-recovery", changed);
    defer refused.deinit();
    try refused.failsWith("required integration roots must remain unconditional");
}

test "security: required CI modes, architecture and aggregate failure propagation refuse mutations" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const valid = try f.check("ci-recovery", workflow);
    defer valid.deinit();
    try valid.ok();
    for ([_]struct { original: []const u8, changed: []const u8, message: []const u8 }{
        .{ .original = "optimize: [Debug, ReleaseSafe]", .changed = "optimize: [Debug]", .message = "both architectures and optimization modes within 45 minutes" },
        .{ .original = "name: [linux-x64, linux-arm64]", .changed = "name: [linux-x64]", .message = "both architectures and optimization modes within 45 minutes" },
        .{ .original = workload_needs, .changed = "    needs: [build-and-test-workload]", .message = "existing required build checks" },
        .{ .original = "zig build test-release -j2 --summary all", .changed = "echo skip release", .message = "must execute Test release packaging exactly as reviewed in Debug" },
    }) |mutation| {
        const changed = try f.replace(workflow, mutation.original, mutation.changed);
        const rejected = try f.check("ci-recovery", changed);
        defer rejected.deinit();
        try rejected.failsWith(mutation.message);
    }
}

test "security: every split build workload job, mode and step fails closed under mutation" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    for (workload_jobs) |workload_job| {
        const body = try job(workflow, workload_job.name, workload_job.next);
        const limit = try std.fmt.allocPrint(f.arena.allocator(), "ci.yml: {s} must require both architectures and optimization modes within 45 minutes", .{workload_job.name});
        for ([_]struct { before: []const u8, after: []const u8 }{
            .{ .before = "    timeout-minutes: 45", .after = "    timeout-minutes: 90" },
            .{ .before = "    timeout-minutes: 45", .after = "    timeout-minutes: 46" },
            .{ .before = "    timeout-minutes: 45", .after = "    timeout-minutes: 45\n    timeout-minutes: 45" },
            .{ .before = "name: [linux-x64, linux-arm64]", .after = "name: [linux-x64]" },
            .{ .before = "optimize: [Debug, ReleaseSafe]", .after = "optimize: [Debug]" },
            .{ .before = "optimize: [Debug, ReleaseSafe]", .after = "optimize: [ReleaseSafe]" },
            .{ .before = "      OPTIMIZE: ${{ matrix.optimize }}", .after = "      OPTIMIZE: Debug" },
            .{ .before = "        include:", .after = "        exclude:" },
            .{ .before = "          - os: ubuntu-24.04-arm\n", .after = "" },
            .{ .before = "      fail-fast: false", .after = "      fail-fast: true" },
            .{ .before = "\n    steps:\n", .after = "\n    continue-on-error: true\n    steps:\n" },
        }) |mutation| {
            const changed = try f.replace(workflow, body, try f.replace(body, mutation.before, mutation.after));
            const rejected = try f.check("ci-recovery", changed);
            defer rejected.deinit();
            if (rejected.code == 0) std.debug.print("CI mutation missed {s}: {s}\n", .{ workload_job.name, mutation.before });
            try rejected.failsWith(limit);
        }
        const setup = try std.fmt.allocPrint(f.arena.allocator(), "ci.yml: {s} must retain pinned Zig and metadata dependencies", .{workload_job.name});
        for ([_][]const u8{ "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U", "liblzma-dev libzstd-dev python3-jsonschema", "          persist-credentials: false\n" }) |token| {
            const changed = try f.replace(workflow, body, try f.replace(body, token, ""));
            const rejected = try f.check("ci-recovery", changed);
            defer rejected.deinit();
            try rejected.failsWith(setup);
        }
        const tokens = [_][]const []const u8{ workload_job.mutations, &.{ try partitionCommand(&f, workload_job.partition), "-Doptimize=\"$OPTIMIZE\"" } };
        for (tokens) |group| for (group) |token| {
            const changed = try f.replace(workflow, body, try f.replace(body, token, ""));
            const rejected = try f.check("ci-recovery", changed);
            defer rejected.deinit();
            if (rejected.code == 0) std.debug.print("CI mutation missed {s}: {s}\n", .{ workload_job.name, token });
            try rejected.failsWith("ci.yml:");
        };
        for (workload_job.steps) |name| {
            const selected = try step(body, name);
            const marker = try std.fmt.allocPrint(f.arena.allocator(), "      - name: {s}\n", .{name});
            const disabled = if (std.mem.indexOf(u8, selected, "        if: ")) |if_start| blk: {
                const if_end = std.mem.indexOfPos(u8, selected, if_start, "\n") orelse return error.MissingCondition;
                break :blk try f.replace(selected, selected[if_start..if_end], "        if: false");
            } else try f.replace(selected, marker, try std.fmt.allocPrint(f.arena.allocator(), "{s}        if: false\n", .{marker}));
            const altered = try f.replace(workflow, selected, disabled);
            const refused = try f.check("ci-recovery", altered);
            defer refused.deinit();
            const diagnostic = try std.fmt.allocPrint(f.arena.allocator(), "ci.yml: {s} must execute {s} exactly as reviewed", .{ workload_job.name, name });
            try refused.failsWith(diagnostic);
            const unreviewed = try f.replace(workflow, selected, try std.fmt.allocPrint(f.arena.allocator(), "      - name: Unreviewed extra step\n        run: echo skipped\n{s}", .{selected}));
            const extra = try f.check("ci-recovery", unreviewed);
            defer extra.deinit();
            try extra.failsWith("has a missing, reordered or unreviewed workload step");
        }
    }
    const normalization = try step(try job(workflow, "build-and-test-workload-apt-system", "\n  build-and-test-workload-native:\n"), "Normalize apt facade acceptance diagnostics");
    const disabled = try f.replace(workflow, normalization, try f.replace(normalization, "        if: ${{ always() }}", "        if: success()"));
    const refused = try f.check("ci-recovery", disabled);
    defer refused.deinit();
    try refused.failsWith("ci.yml: build-and-test-workload-apt-system must execute Normalize apt facade acceptance diagnostics exactly as reviewed");
}

test "security: every former workload target runs exactly once across the split jobs" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const inventory = "ci.yml: every former build workload target must execute exactly once across the workload jobs";
    for (workload_jobs, 0..) |workload_job, index| {
        const command = try partitionCommand(&f, workload_job.partition);
        try testing.expectEqual(@as(usize, 1), std.mem.count(u8, workflow, command));
        const body = try job(workflow, workload_job.name, workload_job.next);
        const other = workload_jobs[(index + 1) % workload_jobs.len];
        const other_body = try job(workflow, other.name, other.next);
        const other_command = try partitionCommand(&f, other.partition);
        const duplicated = try f.replace(workflow, other_body, try f.replace(other_body, other_command, try std.fmt.allocPrint(f.arena.allocator(), "{s}{s}", .{ other_command, command })));
        const repeated = try f.check("ci-recovery", duplicated);
        defer repeated.deinit();
        try repeated.failsWith(inventory);
        const without = try f.replace(workflow, body, try f.replace(body, command, ""));
        const moved = try f.replace(without, other_body, try f.replace(other_body, other_command, try std.fmt.allocPrint(f.arena.allocator(), "{s}{s}", .{ other_command, command })));
        const balanced = try f.check("ci-recovery", moved);
        defer balanced.deinit();
        const diagnostic = try std.fmt.allocPrint(f.arena.allocator(), "ci.yml: {s} must execute", .{other.name});
        try balanced.failsWith(diagnostic);
        const outside = try std.fmt.allocPrint(f.arena.allocator(), "{s}\n  extra-partition:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: zig build {s} -j2\n", .{ workflow, workload_job.partition });
        const escaped = try f.check("ci-recovery", outside);
        defer escaped.deinit();
        const once = try std.fmt.allocPrint(f.arena.allocator(), "ci.yml: workload partition {s} must execute exactly once", .{workload_job.partition});
        try escaped.failsWith(once);
    }
    for ([_][]const u8{
        "zig build test -Doptimize=\"$OPTIMIZE\" -j2 --summary all",
        "zig build --summary all test",
        "\"$(command -v zig)\" build test-release test",
    }) |aggregate| {
        const release = try job(workflow, "build-and-test-workload-release", "\n  native-recovery-zig-workflows:\n");
        const fuzz = "          zig build fuzz -Doptimize=\"$OPTIMIZE\" -j2 --summary all\n";
        const restored = try f.replace(workflow, release, try f.replace(release, fuzz, try std.fmt.allocPrint(f.arena.allocator(), "{s}          {s}\n", .{ fuzz, aggregate })));
        const rejected = try f.check("ci-recovery", restored);
        defer rejected.deinit();
        try rejected.failsWith("ci.yml: aggregate zig build test must not duplicate the workload partitions");
        const elsewhere = try std.fmt.allocPrint(f.arena.allocator(), "{s}\n  extra-aggregate:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: |\n          {s}\n", .{ workflow, aggregate });
        const outside = try f.check("ci-recovery", elsewhere);
        defer outside.deinit();
        try outside.failsWith("ci.yml: aggregate zig build test must not duplicate the workload partitions");
    }
    const lifecycle = "          zig build test-native-lifecycle-zig \\\n            -Dnative-reference-dpkg=\"$reference_dpkg\" -Doptimize=\"$OPTIMIZE\" -j2 --summary all\n";
    const native = try job(workflow, "build-and-test-workload-native", "\n  build-and-test-workload-release:\n");
    const repeated_target = try f.replace(workflow, native, try f.replace(native, lifecycle, try std.fmt.allocPrint(f.arena.allocator(), "{s}{s}", .{ lifecycle, lifecycle })));
    const duplicate = try f.check("ci-recovery", repeated_target);
    defer duplicate.deinit();
    try duplicate.failsWith(inventory);
}

test "security: build.zig test is exactly the disjoint union of the CI workload partitions" {
    var f = try Fixture.init();
    defer f.deinit();
    const build = try f.source("build.zig");
    const valid = try f.check("workload-build", build);
    defer valid.deinit();
    try valid.ok();
    const partitions = [_][]const u8{ "workload_core", "workload_production", "workload_apt_system", "workload_native", "workload_release" };
    var members: usize = 0;
    var lines = std.mem.splitScalar(u8, build, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trimStart(u8, line, " ");
        const partition = for (partitions) |candidate| {
            if (std.mem.startsWith(u8, trimmed, candidate) and std.mem.startsWith(u8, trimmed[candidate.len..], ".dependOn(")) break candidate;
        } else continue;
        members += 1;
        const entry = try std.fmt.allocPrint(f.arena.allocator(), "{s}\n", .{line});
        const target = if (std.mem.eql(u8, partition, "workload_core")) "workload_native" else "workload_core";
        const moved_line = try std.fmt.allocPrint(f.arena.allocator(), "    {s}{s}\n", .{ target, trimmed[partition.len..] });
        for ([_][]const u8{ "", moved_line, try std.fmt.allocPrint(f.arena.allocator(), "{s}{s}", .{ entry, moved_line }) }) |replacement| {
            const changed = try f.replace(build, entry, replacement);
            const rejected = try f.check("workload-build", changed);
            defer rejected.deinit();
            if (rejected.code == 0) std.debug.print("workload partition mutation missed: {s} -> {s}\n", .{ line, replacement });
            try rejected.failsWith("build.zig:");
        }
    }
    try testing.expectEqual(@as(usize, 45), members);
    for (partitions) |partition| {
        const binding = try std.fmt.allocPrint(f.arena.allocator(), "    test_step.dependOn({s});\n", .{partition});
        const removed = try f.check("workload-build", try f.replace(build, binding, ""));
        defer removed.deinit();
        try removed.failsWith("build.zig: aggregate test step must depend only on every workload partition");
    }
    for ([_]struct { before: []const u8, after: []const u8 }{
        .{ .before = "    test_step.dependOn(workload_release);\n", .after = "    test_step.dependOn(workload_release);\n    test_step.dependOn(&run_tests.step);\n" },
        .{ .before = "    workload_release.dependOn(native_only_rehearsal);\n", .after = "    test_step.dependOn(native_only_rehearsal);\n" },
        .{ .before = "addHelpFlagTests(b, workload_core,", .after = "addHelpFlagTests(b, workload_native," },
        .{ .before = "addHelpFlagTests(b, workload_core,", .after = "addHelpFlagTests(b, test_step," },
        .{ .before = "b.step(\"test-workload-native\",", .after = "b.step(\"test-workload-natives\"," },
        .{ .before = "    test_step.dependOn(workload_release);\n", .after = "    test_step.dependOn(workload_release);\n    b.step(\"test-extra\", \"x\").dependOn(workload_native);\n" },
    }) |mutation| {
        const rejected = try f.check("workload-build", try f.replace(build, mutation.before, mutation.after));
        defer rejected.deinit();
        if (rejected.code == 0) std.debug.print("workload build mutation missed: {s}\n", .{mutation.after});
        try rejected.failsWith("build.zig:");
    }
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
        workload_needs,
        "    if: " ++ aggregate_condition,
        "        name: [linux-x64, linux-arm64]",
        "          BUILD_RESULT: ${{ needs.build-and-test-workload.result }}",
        "          BUILD_PRODUCTION_RESULT: ${{ needs.build-and-test-workload-production.result }}",
        "          BUILD_APT_SYSTEM_RESULT: ${{ needs.build-and-test-workload-apt-system.result }}",
        "          BUILD_NATIVE_RESULT: ${{ needs.build-and-test-workload-native.result }}",
        "          BUILD_RELEASE_RESULT: ${{ needs.build-and-test-workload-release.result }}",
        "          RECOVERY_WORKFLOWS_RESULT: ${{ needs.native-recovery-zig-workflows.result }}",
        "          RECOVERY_REPOSITORY_RESULT: ${{ needs.native-recovery-zig-repository.result }}",
        "          RECOVERY_HELPER_RESULT: ${{ needs.native-recovery-zig-helper.result }}",
        "          RECOVERY_FAMILY_RESULT: ${{ needs.native-recovery-zig-family.result }}",
        "          RECOVERY_SCENARIOS_RESULT: ${{ needs.native-recovery-zig-scenarios.result }}",
        "          RECOVERY_DIVERSIONS_RESULT: ${{ needs.native-recovery-zig-diversions.result }}",
        "          test \"$BUILD_RESULT\" = success",
        "          test \"$BUILD_PRODUCTION_RESULT\" = success",
        "          test \"$BUILD_APT_SYSTEM_RESULT\" = success",
        "          test \"$BUILD_NATIVE_RESULT\" = success",
        "          test \"$BUILD_RELEASE_RESULT\" = success",
        "          test \"$RECOVERY_WORKFLOWS_RESULT\" = success",
        "          test \"$RECOVERY_REPOSITORY_RESULT\" = success",
        "          test \"$RECOVERY_HELPER_RESULT\" = success",
        "          test \"$RECOVERY_FAMILY_RESULT\" = success",
        "          test \"$RECOVERY_SCENARIOS_RESULT\" = success",
        "          test \"$RECOVERY_DIVERSIONS_RESULT\" = success",
    }) |token| {
        const changed = try f.replace(workflow, gate, try f.replace(gate, token, ""));
        const rejected = try f.check("ci-recovery", changed);
        defer rejected.deinit();
        try rejected.failsWith("ci.yml:");
    }
    const shards = [_]struct { name: []const u8, next: []const u8, targets: []const []const u8 }{
        .{ .name = "native-recovery-zig-workflows", .next = "\n  native-recovery-zig-repository:\n", .targets = &.{"test-native-recovery-zig"} },
        .{ .name = "native-recovery-zig-repository", .next = "\n  native-recovery-zig-helper:\n", .targets = &.{"test-native-recovery-zig-repository"} },
        .{ .name = "native-recovery-zig-helper", .next = "\n  native-recovery-zig-family:\n", .targets = &.{
            "test-native-recovery-helper-zig", "test-native-recovery-zig-bootstrap",
            "test-native-recovery-zig-parity", "test-native-recovery-zig-rollback-clock",
        } },
        .{ .name = "native-recovery-zig-family", .next = "\n  native-recovery-zig-scenarios:\n", .targets = &.{"test-native-recovery-zig-family"} },
        .{ .name = "native-recovery-zig-scenarios", .next = "\n  native-recovery-zig-diversions:\n", .targets = &.{
            "test-native-recovery-zig-scriptless",  "test-native-recovery-zig-statoverride",
            "test-native-recovery-zig-literal",     "test-native-recovery-zig-metadata",
            "test-native-recovery-zig-conffile",    "test-native-recovery-zig-final-gaps",
            "test-native-recovery-zig-publication", "test-native-recovery-zig-mutation-boundaries",
        } },
        .{ .name = "native-recovery-zig-diversions", .next = "\n  arm64-dpkg-oracles:\n", .targets = &.{"test-native-recovery-zig-diversions"} },
    };
    for (shards) |shard| {
        const body = try job(workflow, shard.name, shard.next);
        const diversion_shard = std.mem.eql(u8, shard.name, "native-recovery-zig-diversions");
        const timeout_minutes: u8 = if (std.mem.eql(u8, shard.name, "native-recovery-zig-scenarios") or diversion_shard) 75 else 35;
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
        if (!std.mem.eql(u8, shard.name, "native-recovery-zig-scenarios") and !diversion_shard) {
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
            const root_import = try step(body, "Compare pinned-dpkg root import and copied-root refusals");
            for ([_][]const u8{
                "          zig build test-native-root-import -Dnative-reference-dpkg=\"$reference_dpkg\" -j2 --summary all",
                "          zig build test-native-root-import -Dnative-reference-dpkg=\"$reference_dpkg\" -Doptimize=ReleaseSafe -j2 --summary all",
            }) |command| {
                try testing.expectEqual(@as(usize, 1), std.mem.count(u8, workflow, command));
                const absent = try f.replace(workflow, root_import, try f.replace(root_import, command, ""));
                const removed = try f.check("ci-recovery", absent);
                defer removed.deinit();
                try removed.failsWith("ci.yml: native-recovery-zig-workflows must execute Compare pinned-dpkg root import");
                const duplicate = try f.replace(workflow, root_import, try f.replace(root_import, command, try std.fmt.allocPrint(f.arena.allocator(), "{s}\n{s}", .{ command, command })));
                const repeated = try f.check("ci-recovery", duplicate);
                defer repeated.deinit();
                try repeated.failsWith("ci.yml: pinned-dpkg root import must run once per mode only in the required core shard");
                const untrusted = try f.replace(workflow, root_import, try f.replace(root_import, command, try f.replace(command, "\"$reference_dpkg\"", "\"$untrusted_dpkg\"")));
                const unpinned = try f.check("ci-recovery", untrusted);
                defer unpinned.deinit();
                try unpinned.failsWith("ci.yml: native-recovery-zig-workflows must execute Compare pinned-dpkg root import");
                const moved = try std.fmt.allocPrint(f.arena.allocator(), "{s}\n  duplicate-root-import:\n    runs-on: ubuntu-24.04\n    steps:\n      - name: Duplicate root import\n        run: |\n{s}\n", .{ workflow, command });
                const elsewhere = try f.check("ci-recovery", moved);
                defer elsewhere.deinit();
                try elsewhere.failsWith("ci.yml: pinned-dpkg root import must run once per mode only in the required core shard");
            }
            const without_step = try f.replace(workflow, root_import, "");
            const dropped = try f.check("ci-recovery", without_step);
            defer dropped.deinit();
            try dropped.failsWith("ci.yml: native-recovery-zig-workflows has an unreviewed recovery step");
        }
        for (shard.targets) |target| {
            for ([_][]const u8{ "", " -Doptimize=ReleaseSafe" }) |mode| {
                const shard_option: []const u8 = if (diversion_shard) " -Dnative-zig-recovery-diversion-shard=\"${{ matrix.shard }}\"" else "";
                const command = try std.fmt.allocPrint(f.arena.allocator(), "          zig build {s}{s} -Dnative-reference-dpkg=\"$reference_dpkg\"{s} -j2 --summary all", .{ target, shard_option, mode });
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
            &.{ "Exercise Zig recovery units in both modes", "Exercise Zig core recovery", "Compare pinned-dpkg root import and copied-root refusals" }
        else if (std.mem.eql(u8, shard.name, "native-recovery-zig-repository"))
            &.{"Exercise Zig repository recovery"}
        else if (std.mem.eql(u8, shard.name, "native-recovery-zig-helper"))
            &.{"Exercise Zig helper, bootstrap, parity and rollback recovery"}
        else if (std.mem.eql(u8, shard.name, "native-recovery-zig-family"))
            &.{"Exercise Zig signed FAMILY recovery"}
        else if (diversion_shard)
            &.{"Exercise counted Zig diversion recovery shard"}
        else
            &.{"Exercise Zig recovery scenario and mutation matrices"};
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
    try extra.failsWith("ci.yml: recovery targets must execute only in the six required Zig shards");
}

test "security: aggregate gate rejects failure, cancellation, skip and unknown job results" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const gate = try job(workflow, "build-and-test", "\n  security-audit:\n");
    const commands = try script(try step(gate, "Require every build and native recovery shard"));
    const states = [_][]const u8{ "success", "failure", "cancelled", "skipped", "unknown" };
    const names = [_][]const u8{
        "BUILD_RESULT",               "BUILD_PRODUCTION_RESULT",    "BUILD_APT_SYSTEM_RESULT",
        "BUILD_NATIVE_RESULT",        "BUILD_RELEASE_RESULT",       "RECOVERY_WORKFLOWS_RESULT",
        "RECOVERY_REPOSITORY_RESULT", "RECOVERY_HELPER_RESULT",     "RECOVERY_FAMILY_RESULT",
        "RECOVERY_SCENARIOS_RESULT",  "RECOVERY_DIVERSIONS_RESULT",
    };
    for (0..names.len + 1) |changed| {
        for (states) |state| {
            var values: [names.len][]const u8 = undefined;
            for (names, 0..) |name, index| {
                values[index] = try std.fmt.allocPrint(f.arena.allocator(), "{s}={s}", .{ name, if (changed == names.len or index == changed) state else "success" });
            }
            var argv: [names.len + 4][]const u8 = undefined;
            argv[0] = "env";
            @memcpy(argv[1 .. names.len + 1], &values);
            argv[names.len + 1] = "bash";
            argv[names.len + 2] = "-e";
            argv[names.len + 3] = "-c";
            const result = try support.run(&(argv ++ [_][]const u8{commands}));
            defer result.deinit();
            try testing.expectEqual(std.mem.eql(u8, state, "success"), result.code == 0);
        }
    }
}

test "security: every counted diversion shard is required exactly once per architecture" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    const body = try job(workflow, "native-recovery-zig-diversions", "\n  arm64-dpkg-oracles:\n");
    for ([_]struct { os: []const u8, name: []const u8 }{
        .{ .os = "ubuntu-24.04", .name = "linux-x64" },
        .{ .os = "ubuntu-24.04-arm", .name = "linux-arm64" },
    }) |arch| {
        for (1..5) |shard| {
            const row = try std.fmt.allocPrint(f.arena.allocator(), "          - os: {s}\n            name: {s}\n            shard: {d}\n", .{ arch.os, arch.name, shard });
            try testing.expectEqual(@as(usize, 1), std.mem.count(u8, body, row));
            for ([_][]const u8{ "", try std.fmt.allocPrint(f.arena.allocator(), "{s}{s}", .{ row, row }) }) |replacement| {
                const changed = try f.replace(workflow, body, try f.replace(body, row, replacement));
                const rejected = try f.check("ci-recovery", changed);
                defer rejected.deinit();
                try rejected.failsWith("ci.yml: native-recovery-zig-diversions must require every reviewed architecture and mode within 75 minutes");
            }
        }
    }
}

test "security: Debug and ReleaseSafe build workloads execute all commands and propagate failures" {
    var f = try Fixture.init();
    defer f.deinit();
    const workflow = try f.source(".github/workflows/ci.yml");
    for (workload_jobs) |workload_job| {
        const workload = try job(workflow, workload_job.name, workload_job.next);
        const commands = try script(try step(workload, workload_job.steps[0]));
        for ([_][]const u8{ "Debug", "ReleaseSafe" }) |mode| {
            const optimize = try std.fmt.allocPrint(f.arena.allocator(), "OPTIMIZE={s}", .{mode});
            var expected: std.ArrayList(u8) = .empty;
            for (workload_job.commands) |command| {
                try expected.print(f.arena.allocator(), "{s}\n", .{try std.mem.replaceOwned(u8, f.arena.allocator(), command, "{s}", mode)});
            }
            const printed = expected.items;
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

fn digestInventoryAppendFixture(
    f: *Fixture,
    path: []const u8,
    append: []const u8,
) ![]const u8 {
    return std.json.Stringify.valueAlloc(f.arena.allocator(), .{
        .path = path,
        .append = append,
    }, .{});
}

fn digestInventorySyntheticFixture(f: *Fixture, case: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(f.arena.allocator(), .{ .case = case }, .{});
}

fn digestSemanticAllowlistSyntheticFixture(f: *Fixture, case: []const u8) ![]const u8 {
    return std.json.Stringify.valueAlloc(f.arena.allocator(), .{ .case = case }, .{});
}

test "security: frozen digest inventory, typed authority, and narrow reviewed compatibility" {
    var f = try Fixture.init();
    defer f.deinit();
    const policy = try f.source("security/digest-cutover-policy.json");
    const valid = try f.check("digest-inventory-synthetic", try digestInventorySyntheticFixture(&f, "valid"));
    defer valid.deinit();
    try valid.ok();
    const real_drift = try f.check(
        "digest-inventory",
        try digestInventoryAppendFixture(&f, "src/content_digest.zig", "\n// sha256 inventory drift canary\n"),
    );
    defer real_drift.deinit();
    try real_drift.failsWith("digest inventory record changed: src/content_digest.zig");
    for ([_]struct { case: []const u8, diagnostic: []const u8 }{
        .{ .case = "added", .diagnostic = "digest inventory record changed: src/digest_synthetic.zig" },
        .{ .case = "removed", .diagnostic = "digest inventory record changed: src/digest_synthetic.zig" },
        .{ .case = "edited", .diagnostic = "digest inventory record changed: src/digest_synthetic.zig" },
        .{ .case = "missing-record", .diagnostic = "digest inventory is missing a record: src/digest_synthetic.zig" },
        .{ .case = "extra-missing-file", .diagnostic = "digest inventory contains an unexpected record: tools/zzzz_digest_inventory_canary.py" },
        .{ .case = "extra-no-findings", .diagnostic = "digest inventory contains an unexpected record: doc/empty-digest-synthetic.md" },
        .{ .case = "unsorted", .diagnostic = "digest inventory records are not sorted" },
        .{ .case = "duplicate", .diagnostic = "digest inventory contains a duplicate record" },
        .{ .case = "malformed", .diagnostic = "digest inventory line" },
        .{ .case = "absolute-path", .diagnostic = "has an invalid path" },
        .{ .case = "parent-path", .diagnostic = "has an invalid path" },
        .{ .case = "glob-path", .diagnostic = "has an invalid path" },
        .{ .case = "outside-scope-path", .diagnostic = "has an invalid path" },
        .{ .case = "invalid-scope", .diagnostic = "has an invalid scope" },
        .{ .case = "old-schema", .diagnostic = "digest cutover policy identity changed" },
        .{ .case = "unclassified-scope", .diagnostic = "digest policy does not classify every tracked audit scope" },
    }) |mutation| {
        const result = try f.check("digest-inventory-synthetic", try digestInventorySyntheticFixture(&f, mutation.case));
        defer result.deinit();
        try result.failsWith(mutation.diagnostic);
    }
    const baseline = try f.check("digest-allowlist", policy);
    defer baseline.deinit();
    try baseline.ok();
    const overbroad = try f.replace(policy, "\"src/content_digest.zig\"", "\"src/*\"");
    const widened = try f.check("digest-allowlist", overbroad);
    defer widened.deinit();
    try widened.failsWith("digest semantic allowlist contains an invalid or overbroad entry");
    const semantic_valid = try f.check("digest-semantic-allowlist-synthetic", try digestSemanticAllowlistSyntheticFixture(&f, "valid"));
    defer semantic_valid.deinit();
    try semantic_valid.ok();
    for ([_]struct { case: []const u8, diagnostic: []const u8 }{
        .{ .case = "missing", .diagnostic = "digest semantic allowlist is missing a record: synthetic-raw-controls:src/member.zig" },
        .{ .case = "extra", .diagnostic = "digest semantic allowlist contains an unexpected record: synthetic-raw-controls:src/not-member.zig" },
        .{ .case = "unsorted", .diagnostic = "digest semantic allowlist records are not sorted" },
        .{ .case = "duplicate", .diagnostic = "digest semantic allowlist contains a duplicate record" },
        .{ .case = "malformed", .diagnostic = "digest semantic allowlist line" },
        .{ .case = "non-member-candidate", .diagnostic = "src/not_member.zig:new_control: unreviewed raw 32 byte field" },
        .{ .case = "member-without-candidates", .diagnostic = "digest semantic allowlist changed: synthetic-raw-controls" },
        .{ .case = "changed-count", .diagnostic = "digest semantic allowlist record changed: synthetic-raw-controls:src/member.zig" },
        .{ .case = "changed-sha512", .diagnostic = "digest semantic allowlist record changed: synthetic-raw-controls:src/member.zig" },
        .{ .case = "missing-entry", .diagnostic = "digest semantic allowlist contains an unexpected record: missing-entry:src/member.zig" },
    }) |mutation| {
        const result = try f.check("digest-semantic-allowlist-synthetic", try digestSemanticAllowlistSyntheticFixture(&f, mutation.case));
        defer result.deinit();
        try result.failsWith(mutation.diagnostic);
    }
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
    try f.work.write("security/digest-inventory-v1.tsv", "");
    try f.work.write("security/digest-semantic-allowlist-v1.tsv", "");
    const created = try support.run(&.{ "git", "init", "-q", f.work.root });
    defer created.deinit();
    try created.ok();
    const fixture = try std.json.Stringify.valueAlloc(f.arena.allocator(), .{ .root = f.work.root }, .{});
    const discovered = try f.check("digest-untracked", fixture);
    defer discovered.deinit();
    try discovered.ok();
    try support.contains(discovered.stdout, "src/sha512_transaction_e2e_test.zig\n");
    try support.contains(discovered.stdout, "security/digest-cutover-policy.json\n");
    try support.contains(discovered.stdout, "security/digest-inventory-v1.tsv\n");
    try support.contains(discovered.stdout, "security/digest-semantic-allowlist-v1.tsv\n");
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
            const owns_namespace = std.mem.indexOf(u8, source, "linux.clone2(") != null or
                std.mem.indexOf(u8, source, "linux.unshare(") != null or
                std.mem.indexOf(u8, source, "linux.setns(") != null or
                std.mem.indexOf(u8, source, "linux.mount(") != null or
                std.mem.indexOf(u8, source, "linux.move_mount(") != null or
                std.mem.indexOf(u8, source, "linux.umount2(") != null;
            try testing.expectEqual(std.mem.eql(u8, entry.name, "live_root.zig") or
                std.mem.eql(u8, entry.name, "maintainer_script.zig"), owns_namespace);
        }
        const owns_capability = std.mem.indexOf(u8, source, "linux.capget(") != null or
            std.mem.indexOf(u8, source, "linux.capset(") != null or
            std.mem.indexOf(u8, source, "linux.syscall2(\n        .capget,") != null or
            std.mem.indexOf(u8, source, "linux.syscall2(\n        .capset,") != null or
            std.mem.indexOf(u8, source, "linux.prctl(") != null;
        try testing.expectEqual(std.mem.eql(u8, entry.name, "maintainer_script.zig"), owns_capability);
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
        "linux.open(\"/dev/null\"",                      "linux.chroot(\".\")",                    "linux.unshare(linux.CLONE.NEWNS)",
        "live_root.cloneMountDescriptor(",               "live_root.setMountAttributes(",          "linux.move_mount(",
        "const clone_flags = linux.CLONE.NEWNET |",      "linux.CLONE.NEWNS | linux.CLONE.NEWPID", "fn setupPrivateLoopback() linux.E",
        "\"private-network-loopback-v1\\x00\"",          "fn sealInheritedDescriptors() linux.E",  "linux.PR.CAPBSET_DROP",
        "linux.PR.SET_NO_NEW_PRIVS",                     "linux.PR.SET_PDEATHSIG",                 "linux.syscall2(\n        .capget,",
        "linux.syscall2(\n        .capset,",             "linux.SECCOMP.SET_MODE_FILTER",          "restrictScriptPrivileges(null, false)",
        "restrictScriptPrivileges(failure_stage, true)", "linux.syscall3(\n        .close_range,", "@offsetOf(KernelCapabilityHeader, \"pid\")",
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
    const inventory = try f.source("security/digest-inventory-v1.tsv");
    for ([_][]const u8{
        "test/native_recovery_bootstrap.zig",
        "test/native_recovery_parity_evidence.zig",
        "test/native_recovery_repository.zig",
    }) |path| {
        try support.contains(inventory, try std.fmt.allocPrint(f.arena.allocator(), "{s}\t", .{path}));
    }
}

test "security: signed consumer receipts enforce retained proof and final database" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "native-consumer", "test/native_recovery_parity.zig", &.{
        "try retained.verify(fixture, root, arch, digest, case.exit_status != 0);",
        "try support.absent(fixture, try relative(fixture, root, completion_path));",
        "try verifyFifoLock(fixture, signed.repository, lock.lock, version, fifos);",
        "try support.compare(fixture, scenario.reference_root, scenario.native_root, remove_compare, true);",
        "try scenario.phase(.{ .operation = \"purge\", .packages = &selected }, false);",
        "if (fifo_closures != oracle.parity_suites.len) return error.MissingSignedFifoClosure;",
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
        "const limit_seconds: i64 = if (std.mem.eql(u8, name, \"repository-execution-success\")) 240 else 120;",
        "const progress_ceiling_factor = 2;",
        "const ceiling_seconds = if (progress_watched) limit_seconds * progress_ceiling_factor else limit_seconds;",
        "if (stalled_ms == null and elapsed >= deadline_ms and deadline_ms < ceiling_seconds * 1000) {",
        "previous = snapshotProcessTree(fixture, name, log, pid, deadline_ms, elapsed, host_before, previous);",
        "const timed_out = stalled_ms != null or term == .exited and term.exited == 124 or wall_ms >= ceiling_seconds * 1000;",
        "reportRunner(init.io, allocator);",
        "test \"repository watchdog bounds time between fixture passes by a fixed ceiling\"",
        "test \"repository watchdog samples a blocked child tree and host CPU\"",
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
    try nativeMutationsIn(&f, "native-core", "test/native_recovery_helper.zig", "fn recoveredOrdinary(", "\n}\n", &.{
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
        "try noInterestOutcome(&fixture, driver, reference.executable, reference.architecture, false);",
        "try noInterestOutcome(&fixture, driver, reference.executable, reference.architecture, true);",
        "for ([_]Corruption{ .intent, .progress, .artifact, .managed_root, .completed_phase }) |which|",
        "try corruptedOrdinary(&fixture, driver, reference.architecture, which);",
    });
    try nativeMutationsIn(&f, "native-final", "test/native_recovery_helper.zig", "fn blockedUnknown(", "\nfn triggerOutcome(", &.{
        "\"after_upgrade_postrm_return_before_outcome\" else \"after_script_return_before_outcome\"",
        "try same(try text(script.value, \"outcome\"), \"in_flight\");",
        "try std.testing.expectEqualSlices(u8, stable, try rootWithoutActiveClaim(fixture, scenario.native_root));",
        "try same(try stickyActiveClaim(fixture, scenario.native_root), original_claim);",
    });
    try nativeMutationsIn(&f, "native-final", "test/native_recovery_helper.zig", "fn triggerOutcome(", "\nfn noInterestOutcome(", &.{
        "\"after_trigger_outcome\"",
        "if (events.value.events.len != 2) return error.IncorrectTriggerEventCount;",
        "observed[0].origin != .automatic or observed[1].origin != .dynamic",
        "try same(observed[1].trigger, \"debz-b\");",
        ".acknowledge = true,",
    });
    try nativeMutationsIn(&f, "native-final", "test/native_recovery_helper.zig", "fn noInterestOutcome(", "\nconst Corruption =", &.{
        "\"after_script_outcome\"",
        ".activations = &.{ \"debz-unwatched\", \"/usr/share/debz-unwatched/child\" },",
        ".activation_await = true,",
        "\"debz-unwatched \"",
        "std.mem.indexOf(u8, line, \"debz-trigger-source\") == null",
        "std.mem.indexOf(u8, status, \"Triggers-Awaited:\") != null or",
        "std.mem.indexOf(u8, status, \"Triggers-Pending:\") != null",
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
    try nativeMutationsIn(&f, "native-final", "src/native_unpack.zig", "fn readProductionCompletion(", "\nfn ", &.{
        "nativeAction(.provenance, std.math.maxInt(u32), 0, 0),\n    ) orelse return error.InvalidRecoveryProvenance;",
        "if (terminal.stage != .terminal or switch (receipt.document.outcome) {",
        ".succeeded => terminal.result != .succeeded and terminal.result != .recovered,",
        ".failed => terminal.result != .failed,",
        ".recovery_required => true,\n    }) return error.InvalidRecoveryProvenance;",
        "if (!std.mem.eql(u8, &retained_progress.document.head_sha256, &receipt.document.progress_head_sha256) or\n        retained_progress.document.records.len != receipt.document.progress_record_count)\n        return error.InvalidRecoveryProgress;",
        "try native_provenance.verifyScriptOutcomes(receipt.document, retained_progress.document);",
    });
    try nativeMutationsIn(&f, "native-final", "src/native_unpack.zig", "fn callerOwnedLifecycleFixture(", "\nfn ", &.{
        ") catch |err| return .{ .outcome = .refused, .detail = @errorName(err) };",
    });
}

test "security: completed and recovered script outcome components are mutation enforced" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "native-final", "test/native_recovery_helper.zig", &.{
        "try completedScriptComponents(&fixture, driver, reference.executable, reference.architecture);",
        ".name = \"caller-script-components-recovered\",\n        .crash = \"after_script_outcome\",\n        .caller_owned = true,\n        .isolated_helper = true,\n        .script_components = true,",
        "try callerScriptComponents(fixture, driver, root, arch, case.name, true);",
        "try callerScriptComponents(fixture, driver, root, arch, name, false);",
    });
    try nativeMutationsIn(&f, "native-final", "test/native_recovery_helper.zig", "fn callerScriptComponents(", "\nfn scriptComponentRefused(", &.{
        "if (recovered != (receipt.document.recovered_phase_count != 0)) return error.UnexpectedRecoveredPhaseCount;",
        "\"changed-script_outcome-{d}\"",
        "\"EvidenceChanged\"",
        "\"deleted-script_outcome-{d}\"",
        "\"FileNotFound\"",
        "if (scripts < 2) return error.MissingRetainedScriptOutcome;",
        "for (std.enums.values(ScriptReceiptTamper)) |tamper| {",
        "break :omitted \"EvidenceMissing\";",
        "break :duplicated \"InvalidRecoveryProgress\";",
        "break :rebound \"EvidenceMismatch\";",
        "break :reindexed \"EvidenceMissing\";",
        "break :summary \"EvidenceMismatch\";",
        "break :phases \"InvalidRecoveryProgress\";",
        "break :head \"InvalidRecoveryProgress\";",
        "forged.evidence_files_sha256 = provenance.evidenceDigest(forged.evidence_files);",
    });
    try nativeMutationsIn(&f, "native-final", "test/native_recovery_helper.zig", "fn scriptComponentRefused(", "\nfn completedScriptComponents(", &.{
        "        .caller_verification = expected_receipt,\n    }), \"refused\", expected_error);",
        "        .acknowledge = true,\n    }), \"recovery_required\", expected_error);",
        "try held.owed(fixture, root, receipt);",
    });
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
        "parity_case != null or bootstrap_case != null or repository_case != null or",
        "diversion_case != null or route_case != null or diversion_shard != null or mutation_boundary_case != null",
        "b.option([]const u8, \"native-zig-recovery-diversion-shard\",",
        "recovery_diversions.addArgs(&.{ \"--shard\", shard });",
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
    try nativeMutations(&f, "native-gate", "test/native_recovery_diversions.zig", &.{
        ".{ .first = 1, .last = 25 },",
        ".{ .first = 26, .last = 50 },",
        ".{ .first = 51, .last = 75 },",
        ".{ .first = 76, .last = 100 },",
        "if (shard.first != next or shard.last < shard.first or shard.last > cases.len)",
        "if (next != cases.len + 1) @compileError(",
        "if (selected_shard.? == 0 or selected_shard.? > case_shards.len) return error.InvalidDiversionShard;",
        "if (c.number < bounds.first or c.number > bounds.last) continue;",
        "const run_routes = selected == null and (selected_shard == null or selected_shard.? == case_shards.len);",
        "if (run_routes) for (route_cases) |c| {",
        "if (route_executed != (if (!run_routes)",
        ".{ .name = \"cache-refresh\", .crash = \"after_upgrade_postrm_cache_refresh\" },",
        ".{ .name = \"route-checkpoint\", .crash = \"after_upgrade_postrm_route_checkpoint\" },",
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
        "recovery_parity,",     "recovery_diversions,",  "statoverride_recovery,",
        "conffile_recovery,",   "metadata_recovery,",    "literal_recovery,",
        "scriptless_recovery,", "publication_recovery,",
    });
    try nativeMutationsIn(&f, "native-gate", "build.zig", "} else if (native_core_only) {", "\n        } else {\n            for ([_]*std.Build.Step.Run{", &.{
        "recovery_zig,",        "recovery_helper,",       "recovery_bootstrap,",   "recovery_family,",
        "recovery_diversions,", "statoverride_recovery,", "conffile_recovery,",    "metadata_recovery,",
        "literal_recovery,",    "mutation_boundaries,",   "publication_recovery,",
    });
    try nativeMutationsIn(&f, "native-gate", "build.zig", "        } else {\n            for ([_]*std.Build.Step.Run{", "\n    if (b.option([]const u8, \"native-reference-dpkg\"", &.{
        "recovery_zig,",        "recovery_family,",       "recovery_parity,",     "recovery_helper,",
        "final_gaps,",          "recovery_bootstrap,",    "repository_recovery,", "rollback_clock,",
        "scriptless_recovery,", "statoverride_recovery,", "literal_recovery,",    "metadata_recovery,",
        "conffile_recovery,",   "recovery_diversions,",   "mutation_boundaries,", "publication_recovery,",
    });
    try nativeMutationsIn(&f, "native-gate", "build.zig", "    if (b.option([]const u8, \"native-reference-dpkg\"", "    if (b.option(\n        []const u8,\n        \"native-reference-architecture\"", &.{
        "recovery_zig,",        "recovery_family,",       "recovery_parity,",     "recovery_helper,",
        "final_gaps,",          "recovery_bootstrap,",    "repository_recovery,", "rollback_clock,",
        "scriptless_recovery,", "statoverride_recovery,", "literal_recovery,",    "metadata_recovery,",
        "conffile_recovery,",   "recovery_diversions,",   "mutation_boundaries,", "publication_recovery,",
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

test "security: native provenance component tamper coverage stays wired" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "native-provenance", "build.zig", &.{
        "            \"native_provenance_binding.test.\",\n",
        "    workload_native.dependOn(&run_sha512_e2e_tests.step);",
    });
    try nativeMutations(&f, "native-provenance", "src/sha512_transaction_e2e_test.zig", &.{
        "    _ = @import(\"native_provenance_binding_test.zig\");",
    });
    try nativeMutations(&f, "native-provenance", "src/native_provenance_binding_test.zig", &.{
        "test \"native_provenance_binding.test.completed attempt binds every acceptance component\" {",
        "test \"native_provenance_binding.test.recovered attempt binds every acceptance component\" {",
        "test \"native_provenance_binding.test.recovery_required attempt keeps typed evidence without success-shaped settlement\" {",
        "try tamperSettled(&env, &settled);",
        "try testing.expect(settled.recovered_phase_count >= 1);",
        "try env.expectSecondOperationRefused();",
        "for ([_]native_provenance.Outcome{ .succeeded, .failed }) |outcome| {",
        "\"receipt.evidence_files[{s}] omitted\"",
        "\"retained {s} bytes\"",
        "\"completion.transaction_provenance=provenanceDigest\"",
        "\"live pending trigger claim\"",
        "\"deferred owner reinstated\"",
        "try testing.expect(!std.mem.eql(u8, &receipt_digest, &provenance_digest));",
        "\"live payload bytes\", error.LivePayloadChanged",
        "\"live payload removed\", error.LivePayloadChanged",
        "for (std.enums.values(PayloadReplacement)) |replacement|",
        "\"caller verify of live payload\", error.LivePayloadChanged",
        "try expectCallerPayloadBound(env, attempt, receipt.digest_sha256);",
        "native_transaction_result.verifyCallerSuccessReporting(allocator, attempt, receipt_digest, &change),",
        "try testing.expectEqualStrings(\"demo\", owner.package);",
        "try testing.expectEqualStrings(\"1.0\", owner.version);",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/native_transaction_result.zig", "\nfn verifyStateEvidence(", "\nfn ", &.{
        "        &route_conffiles,\n    );",
        "    _ = try native_runtime.verifySettledPayload(",
        "        route_conffiles.items,\n",
        "        payload_change,\n",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/native_transaction_result.zig", "\nfn verifyCaller(", "\nfn ", &.{
        "        null,\n        payload_change,\n    );",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/native_recovery.zig", "\npub fn verifySettledManagedStateReporting(", "\n}\n", &.{
        "            if (change) |out| out.* = SettledPayloadChange.init(allocator, expected, reason) catch null;",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/native_recovery.zig", "\ntest \"native_recovery.test.settled managed state binds live payload kind, mode and bytes\" {", "\n}\n", &.{
        "try testing.expectEqual(expected.reason, found.reason);",
        "try testing.expectEqualSlices(u8, &hexDigest(bytes_digest), &found.expected_sha256.?);",
        "try testing.expectEqual(found.reason, parsed.value.reason);",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/native_unpack.zig", "\n    pub fn verifySettledPayload(", "\n    }\n", &.{
        "                describeSettledPayloadOwner(allocator, root, program.target_architecture, found) catch {};",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/native_unpack.zig", "\n    fn describeSettledPayloadOwner(", "\n    }\n", &.{
        "        const owners = ownership.ownersOf(change.path);",
        "        if (owners.len != 1) return;",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/production_backend.zig", "\n    fn recoverNative(", "\n    fn ", &.{
        "                .add => return repositoryOwnedRecovery(.recover, attempt.record(), repository_recovery_resume),",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/production_backend.zig", "\nfn repositoryOwnedRecovery(", "\n}\n", &.{
        "        .surface = .repository_bootstrap,",
        "        .resume_path = .rerun_same_repository_add,",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/production_backend.zig", "\ntest \"production native recovery names the repository bootstrap that owns a held attempt\" {", "\n}\n", &.{
        "try std.testing.expectEqual(api.RecoveryOwner.Surface.repository_bootstrap, owner.surface);",
        "try std.testing.expectEqual(api.RecoveryOwner.ResumePath.rerun_same_repository_add, owner.resume_path);",
        "try std.testing.expectEqualStrings(before, after);",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/repository_backend.zig", "\nfn nativeRepositoryCheckpointLoaded(", "\nfn ", &.{
        "    var package_state = verifyNativePackageStateReporting(allocator, input, &payload_change) catch |err| {",
        "        if (err == error.LivePayloadChanged)\n            return refuseNativeLivePayload(allocator, input, observer, stage, original, err, if (payload_change) |*change| change else null);",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/repository_backend.zig", "\nfn refuseNativeLivePayload(", "\nfn ", &.{
        "    if (retained.receipt.document.outcome != .succeeded or !nativeStageImports(stage, prior.phase)) return cause;",
        "    publication.persist(allocator, current.state, original.paths) catch |err| return err;",
        "    const detail: ?[]u8 = if (payload_change) |change| (change.diagnostic(allocator) catch null) else null;",
        "    return publication.failMessage(allocator, &current, original.paths, .installed_verification_failed, cause, detail orelse @errorName(cause));",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/repository_backend.zig", "\nfn testProjectedNativeImport(", "\nfn ", &.{
        "try std.testing.expectError(error.LivePayloadChanged, importAndRefreshNative(allocator, input, reporting));",
        "try std.testing.expectEqual(api.DiagnosticId.installed_verification_failed, reported.diagnostics[0].id);",
        "try expectLivePayloadDiagnostic(allocator, reported.diagnostics[0].message, state.state.managed_files[0], state.state.descriptor.?);",
        "try std.testing.expectError(error.LivePayloadChanged, completeNative(allocator, input));",
        "try std.testing.expectEqual(root_operation.ProvenanceState.pending, attempt.record().provenance);",
        "try std.testing.expectEqual(api.DiagnosticId.installed_verification_failed, failed.state.diagnostic_id.?);",
        "try expectLivePayloadDiagnostic(allocator, failed.state.diagnostic, state.state.managed_files[0], state.state.descriptor.?);",
    });
    try nativeMutationsIn(&f, "native-provenance", "src/repository_backend.zig", "\nfn expectLivePayloadDiagnostic(", "\nfn ", &.{
        "    var parsed = try native_recovery.parseSettledPayloadDiagnostic(allocator, message);",
        "    try std.testing.expectEqualStrings(removed.logical_path[1..], fields.path);",
        "    try std.testing.expectEqualStrings(&expected_sha256, fields.expected_sha256.?);",
        "    try std.testing.expectEqualStrings(descriptor.package, fields.package.?);",
        "    try std.testing.expectEqualStrings(descriptor.version, fields.version.?);",
    });
    try nativeMutationsIn(&f, "native-workflow", "test/native_recovery_family.zig", "\nfn ownedComponents(", "\nfn ", &.{
        "const retained_kinds = [_]provenance.EvidenceKind{ .authorization, .program, .execution_request, .intent, .progress, .managed_state, .trigger_events, .script_outcome };",
        "if (!observed_kinds.contains(kind) and (kind != .script_outcome or check.scripts))",
        "\"retained-{s}-{d}\"",
        "outcome_other_terminal,\n        outcome_recovery_required,",
        "final_database_generation,\n        final_state,",
        "if (check.outcome == .failed) \"TransactionNotFailed\" else \"TransactionNotSuccessful\"",
        "else => \"EvidenceMismatch\",",
        ".expected_error = \"ReceiptMissing\"",
        ".expected_error = \"CompletionMissing\"",
        ".expected_error = \"OwnershipMismatch\"",
        "\"live-payload-bytes\", selected, lock, check, \"LivePayloadChanged\"",
        "\"live-payload-removed\", selected, lock, check, \"LivePayloadChanged\"",
        "\"administrator-conffile-edit\", selected, lock, check",
        "\"receipt-script_outcome-duplicated\" else \"receipt-script_outcome-omitted\"",
    });
    try nativeMutations(&f, "native-workflow", "test/native_recovery_family.zig", &.{
        "    try ownedComponents(fixture, driver, &scenario, arch, name, selected, lock, .{",
        "        .state = \"released\",\n        .outcome = .succeeded,\n        .scripts = false,",
        "        .state = \"released\",\n        .outcome = .succeeded,\n        .scripts = true,",
        "        .state = \"pending\",\n        .outcome = .failed,\n        .scripts = true,",
        "    try ownedScriptedSuccess(&fixture, driver, helper.?, reference.executable, reference.architecture, source, keyring, cli.?);",
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
        "workload_native.dependOn(&run_lifecycle_zig_tests.step);",
        "workload_native.dependOn(&run_trigger_zig_tests.step);",
        "workload_native.dependOn(&run_settlement_tests.step);",
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

test "security: protected reference CI stays opt-in, root-staged, bounded and unskippable" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "protected-reference", ".github/workflows/ci.yml", &.{
        "      run_protected_reference:\n",
        "  schedule:\n    - cron: \"23 3 * * 1\"\n",
        "          test \"$(git rev-parse HEAD)\" = \"$GITHUB_SHA\"\n          test -z \"$(git status --porcelain)\"\n",
        "            mkdir -m 0700 -- \"$tree\"\n",
        "            git --git-dir=\"$tree/bare.git\" fsck --full --no-dangling\n",
        "            test \"$(git -C \"$tree/checkout\" rev-parse HEAD)\" = \"$expected\"\n",
        "          sudo -n tar -C \"$PROTECTED_TREE/upload\" -cf - . >\"$RUNNER_TEMP/protected-evidence.tar\"\n",
        "          path: ${{ runner.temp }}/protected-reference-${{ matrix.architecture }}/\n          if-no-files-found: error\n",
        "              kill -KILL \"${victims[@]}\" 2>/dev/null || true\n",
        "            rm -rf --one-file-system -- \"$tree\"\n",
    });
    try nativeMutations(&f, "protected-reference", "tools/real-snapshot-reference-protected-ci.sh", &.{
        "trap collect EXIT\n",
        "test \"$(git -C \"$checkout\" rev-parse HEAD)\" = \"$commit\"\n",
        "step zig-verify 0 \"\" python3 -I tools/verify-minisign.py --public-key \"$zig_public_key\" \\\n",
        "chmod -R go-w zig-pkg \"$tree/zig-global\"\n",
        "step zig-pkg-verify 0 \"\" python3 -I tools/real-snapshot-reference-tree-check.py packages \\\n",
        "step tree-staged 0 \"\" python3 -I tools/real-snapshot-reference-tree-check.py tree \"$tree\"\n",
        "negative mutable-ancestor \"writable or non-root ancestor\" \\\n",
        "negative swapped-dpkg \"reference dpkg executable is not the pinned architecture artifact\" \\\n",
        "negative wrong-architecture \"reference dpkg executable is not the pinned architecture artifact\" \\\n",
        "step negative-swapped-keyring refused '\"summary\":\"WrongSigningKey\"' swapped_keyring_stage\n",
        "    echo \"negative-$name launched before refusing\" >&2\n",
        "step proof 0 \"executed without skips\" timeout --signal=TERM --kill-after=60s 45m \\\n",
        "  mode=native-staging\n",
        "print(verify_keyring(Path(sys.argv[2]), int(sys.argv[3]), sys.argv[4]))\n",
        "module.verify_extracted_bindings(prefix, architecture)\n",
    });
    try nativeMutations(&f, "protected-reference", "tools/real-snapshot-protected-native-ci.sh", &.{
        "  export DEBZ_ZIG=${inputs[0]} REFERENCE_DPKG=${inputs[1]} DEBZ_REAL_SNAPSHOT_KEYRING=${inputs[2]}\n",
        "    exec bash \"$checkout/tools/real-snapshot-acceptance.sh\" \"$checkout/zig-out/bin/debz\" \\\n",
        "    exec bash tools/real-snapshot-reference.sh \"$REFERENCE_DPKG\" \\\n",
        "            if total > 512 * 1024 * 1024:\n",
    });
    try nativeMutations(&f, "protected-reference", "tools/real-snapshot-acceptance.sh", &.{
        "    --check-keyring \"$keyring\" >/dev/null\n",
        "python3 -I - \"$repository_root/tools\" \"$repository_root\" \"$debz\" <<'PY'\n",
    });
    try nativeMutations(&f, "protected-reference", "tools/real-snapshot-reference.sh", &.{
        "\"$zig\" build-exe tools/real-snapshot-reference-launcher.zig -O ReleaseSafe -lc \\\n",
        "  --zig-lib-dir \"$(dirname -- \"$zig\")/lib\" \\\n",
    });
    try nativeMutations(&f, "protected-reference", "tools/real_snapshot_reference_paths.py", &.{
        "        if meta.st_size != size or len(payload) != size or actual != digest:\n",
        "                if not target.is_relative_to(library):\n",
    });
    try nativeMutations(&f, "protected-reference", "build.zig", &.{"        \"--profile-scripts\",\n"});
    try nativeMutations(&f, "protected-reference", "tools/real-snapshot-reference-protected-stage.sh", &.{
        "  printf -- '-Dreference-protected-profile-scripts=%s\\n' \"$profiles\"\n",
    });
    try nativeMutations(&f, "protected-reference", "tools/test_real_snapshot_reference_protected.py", &.{
        "    profiles = prove_profiles(args, scripts)\n",
        "    \"systemd\": (\"proc-read-only\", \"proc-sys-masked\", \"proc-boot-id\"),\n",
        "    \"udev\": (\"proc-pid-only\",),\n",
    });
    try nativeMutations(&f, "protected-reference", "tools/real-snapshot-reference-escape-probe.zig", &.{
        "    const pid_one_root = statIdentity(\"/proc/1/root\", 0);\n",
        "    report(\"proc-pid-only\", ",
    });
    try nativeMutations(&f, "protected-reference", "tools/verify-minisign.py", &.{
        "    ed25519_verify(key, blob[10:] + trusted, global_signature)\n",
    });
    const workflow = try f.source(".github/workflows/ci.yml");
    const ci_script = try f.source("tools/real-snapshot-reference-protected-ci.sh");
    const harness = try f.source("tools/test_real_snapshot_reference_protected.py");
    const gate = "    if: github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.run_protected_reference)\n";
    const stage = "      - name: Stage the reviewed commit in a root-owned tree and run the protected proof\n";
    for ([_]struct { path: []const u8, text: []const u8 }{
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, gate, "    if: false\n") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, gate, "    if: github.event_name == 'pull_request' || github.event_name == 'schedule' || (github.event_name == 'workflow_dispatch' && inputs.run_protected_reference)\n") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, stage, stage ++ "        continue-on-error: true\n") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, stage, stage ++ "        if: false\n") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, "          sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n", "          env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, "          sudo -n env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n", "          sudo env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/root LC_ALL=C \\\n") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, "          if-no-files-found: error\n          retention-days: 14\n      - name: Kill protected", "          if-no-files-found: warn\n          retention-days: 14\n      - name: Kill protected") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, "    timeout-minutes: 90\n    strategy:\n      fail-fast: false\n      matrix:\n        include:\n          - architecture: amd64\n            runner: ubuntu-24.04\n          - architecture: arm64\n            runner: ubuntu-24.04-arm\n    env:\n      ARCHITECTURE", "    timeout-minutes: 90\n    strategy:\n      fail-fast: false\n      matrix:\n        include:\n          - architecture: arm64\n            runner: ubuntu-24.04-arm\n    env:\n      ARCHITECTURE") },
        .{ .path = "tools/real-snapshot-reference-protected-ci.sh", .text = try f.replace(ci_script, "trap collect EXIT\n", "trap collect EXIT\nexit 0\n") },
        .{ .path = "tools/real-snapshot-reference-protected-ci.sh", .text = try f.replace(ci_script, "  -Doptimize=ReleaseSafe -j4 --summary all\n", "  -Doptimize=ReleaseSafe -j4 --summary all || true\n") },
        .{ .path = "tools/test_real_snapshot_reference_protected.py", .text = try f.replace(harness, "    profiles = prove_profiles(args, scripts)\n", "    profiles = \"skipped\"\n    unittest.SkipTest\n") },
    }) |mutation| {
        const refused = try nativeCheck(&f, "protected-reference", mutation.path, mutation.text);
        defer refused.deinit();
        if (refused.code == 0) std.debug.print("unchecked protected-reference mutation in {s}\n", .{mutation.path});
        try testing.expectEqual(@as(u8, 1), refused.code);
        try refused.failsWith("security-audit:");
    }
    const missing = try nativeCheck(&f, "protected-reference", "tools/real-snapshot-reference-protected-ci.sh", null);
    defer missing.deinit();
    try testing.expectEqual(@as(u8, 1), missing.code);
}

test "security: root reference capability proof stays required outside the sudo-free audit" {
    var f = try Fixture.init();
    defer f.deinit();
    try nativeMutations(&f, "reference-root", ".github/workflows/ci.yml", &.{
        "      - name: Prove root reference capability transition\n",
        "        run: zig build test-real-snapshot-reference-launcher-root --summary all\n",
    });
    try nativeMutations(&f, "reference-root", "build.zig", &.{
        "    audit_step.dependOn(&run_reference_launcher_tests.step);\n",
        "\"sudo\", \"-n\", \"--\" ",
        "    run_reference_launcher_root_tests.addArtifactArg(reference_launcher_root_tests);\n",
        "b.step(\"test-real-snapshot-reference-launcher-root\", ",
    });
    try nativeMutations(&f, "reference-root", "tools/real-snapshot-reference-launcher.zig", &.{
        "    if (linux.W.EXITSTATUS(status) == 14) return error.CapabilityProbeRequiresRoot;\n",
        "        if (linux.geteuid() != 0 or linux.getuid() != 0) linux.exit(14);\n",
        "        if (restrictReferencePrivileges() != .PERM) linux.exit(4);\n",
        "    try unprivilegedTransitionProbe();\n",
    });
    try nativeMutations(&f, "reference-root", "tools/real-snapshot-reference-launcher-root-test.zig", &.{
        "    try launcher.capabilityTransitionProbe();\n",
    });
    const workflow = try f.source(".github/workflows/ci.yml");
    const root_step = "      - name: Prove root reference capability transition\n";
    const build = try f.source("build.zig");
    const launcher = try f.source("tools/real-snapshot-reference-launcher.zig");
    const root_test = try f.source("tools/real-snapshot-reference-launcher-root-test.zig");
    for ([_]struct { path: []const u8, text: []const u8 }{
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, root_step, root_step ++ "        if: false\n") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, root_step, root_step ++ "        continue-on-error: true\n") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, "    name: Security and dependency policy\n", "    name: Security and dependency policy\n    if: false\n") },
        .{ .path = ".github/workflows/ci.yml", .text = try f.replace(workflow, "--summary all\n\n  release-dry-run:", "--summary all\n        if: ${{ github.event_name == 'push' }}\n\n  release-dry-run:") },
        .{ .path = "build.zig", .text = try f.replace(build, "    audit_step.dependOn(&run_reference_launcher_tests.step);\n", "    audit_step.dependOn(&run_reference_launcher_tests.step);\n    audit_step.dependOn(&run_reference_launcher_root_tests.step);\n") },
        .{ .path = "build.zig", .text = try f.replace(build, "const run_reference_launcher_tests = b.addRunArtifact(reference_launcher_tests);", "const run_reference_launcher_tests = b.addSystemCommand(&.{ \"sudo\", \"-n\", \"--\" });") },
        .{ .path = "tools/real-snapshot-reference-launcher.zig", .text = try f.replace(launcher, "test \"reference launcher rejects wider", "test \"reference capability transition as root\" {\n    try capabilityTransitionProbe();\n}\n\ntest \"reference launcher rejects wider") },
        .{ .path = "tools/real-snapshot-reference-launcher.zig", .text = try f.replace(launcher, "return error.CapabilityProbeRequiresRoot;", "return error.SkipZigTest;") },
        .{ .path = "tools/real-snapshot-reference-launcher-root-test.zig", .text = try f.replace(root_test, "    try launcher.capabilityTransitionProbe();\n", "    if (@import(\"std\").os.linux.geteuid() != 0) return error.SkipZigTest;\n    try launcher.capabilityTransitionProbe();\n") },
    }) |mutation| {
        const refused = try nativeCheck(&f, "reference-root", mutation.path, mutation.text);
        defer refused.deinit();
        if (refused.code == 0) std.debug.print("unchecked reference-root mutation in {s}\n", .{mutation.path});
        try testing.expectEqual(@as(u8, 1), refused.code);
        try refused.failsWith("security-audit:");
    }
    const missing = try nativeCheck(&f, "reference-root", "tools/real-snapshot-reference-launcher-root-test.zig", null);
    defer missing.deinit();
    try testing.expectEqual(@as(u8, 1), missing.code);
}
