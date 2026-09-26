const std = @import("std");
const debz = @import("debz");
const foundation = @import("native_test_foundation.zig");
const support = @import("native_lifecycle_support.zig");
const family = @import("native_recovery_family.zig");
const oracle = @import("native_recovery_oracle.zig");
const retained = @import("native_recovery_parity_evidence.zig");
const options = @import("native_test_options");

const namespace = "var/lib/debz/";
const helper_path = "usr/bin/dpkg-trigger";
const provenance_path = namespace ++ "native-transaction-provenance-v2.json";
const completion_path = namespace ++ "root-operation-completion-v2.json";
const operation_path = namespace ++ "root-operation-v1.json";
const intent_path = namespace ++ "native-execution-intent-v1.json";

const Identity = struct { inode: u64, digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 };

fn relative(fixture: *foundation.Fixture, root: []const u8, path: []const u8) ![]const u8 {
    if (root.len <= fixture.path.len or !std.mem.startsWith(u8, root, fixture.path) or
        root[fixture.path.len] != '/') return error.NotDisposableRoot;
    return support.path(fixture.allocator, root[fixture.path.len + 1 ..], path);
}

fn identity(fixture: *foundation.Fixture, root: []const u8) !Identity {
    const name = try relative(fixture, root, helper_path);
    var file = try fixture.dir.openFile(fixture.io, name, .{ .follow_symlinks = false });
    defer file.close(fixture.io);
    const inode = (try file.stat(fixture.io)).inode;
    var reader = file.reader(fixture.io, &.{});
    const bytes = try reader.interface.allocRemaining(fixture.allocator, .limited(8 * 1024 * 1024));
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return .{ .inode = inode, .digest = digest };
}

fn rootDocument(fixture: *foundation.Fixture, root: []const u8, name: []const u8) !std.json.Parsed(std.json.Value) {
    return family.parse(fixture, try relative(fixture, root, name), 16 * 1024 * 1024);
}

fn text(value: std.json.Value, name: []const u8, expected: []const u8) !void {
    try family.same(try family.string(value, name), expected);
}

fn flag(value: std.json.Value, name: []const u8, expected: bool) !void {
    const member = try family.field(value, name);
    if (member != .bool or member.bool != expected) return error.UnexpectedConsumerResult;
}

fn nullField(value: std.json.Value, name: []const u8) !void {
    if (try family.field(value, name) != .null) return error.UnexpectedConsumerResult;
}

fn diagnostics(core: std.json.Value, family_result: std.json.Value, suite: []const u8, arch: []const u8, case: oracle.ParityCase) !void {
    const failed = case.exit_status != 0;
    try text(core, "schema", "io.github.cataggar.debz.command.v1");
    if ((try family.string(core, "summary")).len == 0) return error.UnexpectedConsumerDiagnostic;
    const items = try family.field(core, "items");
    const entries = try family.field(core, "diagnostics");
    if (items != .array or entries != .array or
        items.array.items.len != (if (failed) @as(usize, 0) else case.archives.len) or
        entries.array.items.len != (if (failed) @as(usize, 1) else 0))
        return error.UnexpectedConsumerDiagnostic;
    if (!failed) for (case.archives) |selector| {
        const equals = std.mem.indexOfScalar(u8, selector, '=');
        const package = if (equals) |index| selector[0..index] else selector;
        const version = if (equals) |index| selector[index + 1 ..] else if (std.mem.eql(u8, package, "trigger-pkg"))
            if (std.mem.eql(u8, suite, "debian-stable")) "1.0-1debian1" else "1.0-1ubuntu1"
        else
            "1.0-1";
        const package_arch = if (std.mem.eql(u8, package, "recommended-addon")) "all" else arch;
        var found: usize = 0;
        for (items.array.items) |item| {
            if (!std.mem.eql(u8, try family.string(item, "package"), package)) continue;
            found += 1;
            try text(item, "version", version);
            try text(item, "architecture", package_arch);
            try text(item, "detail", if (case.update or case.conffile != null) "upgrade" else "install");
        }
        if (found != 1) return error.UnexpectedConsumerItem;
    };
    if (failed) {
        const diagnostic = entries.array.items[0];
        try text(diagnostic, "id", "transaction_failed");
        try text(diagnostic, "message", try family.string(core, "summary"));
        const family_diagnostic = try family.field(family_result, "diagnostic");
        try text(family_diagnostic, "id", "backend_failed");
        try flag(family_diagnostic, "recoverable", true);
        for ([_][]const u8{ try family.string(core, "summary"), try family.string(family_diagnostic, "message") }) |message|
            if (!std.mem.startsWith(u8, message, "native transaction failed; receipt sha256=") or
                std.mem.indexOf(u8, message, "; evidence=var/lib/debz/native-receipts-v1/") == null)
                return error.UnexpectedConsumerDiagnostic;
    } else try nullField(family_result, "diagnostic");
}

fn archive(fixture: *foundation.Fixture, suite: []const u8, arch: []const u8, selector: []const u8) ![]const u8 {
    const equals = std.mem.indexOfScalar(u8, selector, '=');
    const name = if (equals) |index| selector[0..index] else selector;
    const version = if (equals) |index| selector[index + 1 ..] else if (std.mem.eql(u8, name, "trigger-pkg"))
        if (std.mem.eql(u8, suite, "debian-stable")) "1.0-1debian1" else "1.0-1ubuntu1"
    else
        "1.0-1";
    const package_arch = if (std.mem.eql(u8, name, "recommended-addon")) "all" else arch;
    return fixture.absolute(try std.fmt.allocPrint(fixture.allocator, "parity/{s}/repository/pool/main/{s}_{s}_{s}.deb", .{
        suite, name, version, package_arch,
    }));
}

fn setHold(fixture: *foundation.Fixture, reference: []const u8, root: []const u8, package: []const u8, destination: []const u8) !void {
    const input = try std.fmt.allocPrint(fixture.allocator, "{s}/selection", .{destination});
    try fixture.write(input, try std.fmt.allocPrint(fixture.allocator, "{s} hold\n", .{package}), 0o644);
    var selection = try fixture.dir.openFile(fixture.io, input, .{});
    defer selection.close(fixture.io);
    const root_flag = try std.fmt.allocPrint(fixture.allocator, "--root={s}", .{root});
    var child = try std.process.spawn(fixture.io, .{
        .argv = &.{ "/usr/bin/timeout", "--kill-after=2s", "30s", reference, "--force-not-root", "--force-bad-path", root_flag, "--set-selections" },
        .environ_map = &fixture.environment,
        .stdin = .{ .file = selection },
        .stdout = .ignore,
        .stderr = .ignore,
    });
    const result = try child.wait(fixture.io);
    if (result != .exited or result.exited != 0) return error.HoldSelectionFailed;
}

fn public(
    fixture: *foundation.Fixture,
    executable: []const u8,
    destination: []const u8,
    operation: []const u8,
    common: []const []const u8,
    extra: []const []const u8,
    expected: u8,
) !std.json.Parsed(std.json.Value) {
    try fixture.directory(destination);
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(fixture.allocator, &.{ "/usr/bin/timeout", "--kill-after=2s", "120s", executable, operation });
    try argv.appendSlice(fixture.allocator, common);
    try argv.appendSlice(fixture.allocator, extra);
    const result = try std.process.run(fixture.allocator, fixture.io, .{
        .argv = argv.items,
        .environ_map = &fixture.environment,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(125), .clock = .awake } },
    });
    const log = try std.fmt.allocPrint(fixture.allocator, "{s}/stdout.json", .{destination});
    try fixture.write(log, result.stdout, 0o644);
    try fixture.write(try std.fmt.allocPrint(fixture.allocator, "{s}/stderr", .{destination}), result.stderr, 0o644);
    if (result.term != .exited or result.term.exited != expected or result.stderr.len != 0) {
        std.debug.print("public {s}: {any}, expected {d}; stdout: {s}; stderr: {s}\n", .{
            operation, result.term, expected, result.stdout, result.stderr,
        });
        return error.UnexpectedPublicConsumerExit;
    }
    var parsed = try family.parse(fixture, log, 1024 * 1024);
    errdefer parsed.deinit();
    if (!std.mem.eql(u8, operation, "transaction-result")) {
        try text(parsed.value, "operation", operation);
        const status = try family.field(parsed.value, "exit_status");
        if (status != .integer or status.integer != expected) return error.UnexpectedPublicConsumerExit;
    }
    return parsed;
}

fn generate(fixture: *foundation.Fixture, python: []const u8, suite: []const u8, arch: []const u8) !struct { source: []const u8, keyring: []const u8 } {
    const directory = try std.fmt.allocPrint(fixture.allocator, "parity/{s}", .{suite});
    try fixture.directory(directory);
    const script = try std.fs.path.join(fixture.allocator, &.{ options.repository, "tools/generate-integration-repository.py" });
    const repository = try fixture.absolute(try support.path(fixture.allocator, directory, "repository"));
    try fixture.run(&.{ python, script, "--output", repository, "--suite", suite, "--architecture", arch }, try support.path(fixture.allocator, directory, "generator.log"), 120);
    const keyring = try support.path(fixture.allocator, repository, "fixture-keyring.gpg");
    const source = try support.path(fixture.allocator, directory, "repository.sources");
    try fixture.write(source, try std.fmt.allocPrint(fixture.allocator, "Types: deb\nURIs: file://{s}\nSuites: {s}\nComponents: main\nArchitectures: {s}\nSigned-By: {s}\n", .{ repository, suite, arch, keyring }), 0o644);
    return .{ .source = try fixture.absolute(source), .keyring = keyring };
}

fn execute(
    fixture: *foundation.Fixture,
    driver: []const u8,
    cli: []const u8,
    helper: []const u8,
    dpkg: []const u8,
    arch: []const u8,
    suite: []const u8,
    case: oracle.ParityCase,
    source: []const u8,
    keyring: []const u8,
) !bool {
    const name = try std.fmt.allocPrint(fixture.allocator, "parity/{s}/{s}", .{ suite, case.id });
    var scenario = try support.Scenario.init(fixture, name, driver, dpkg, arch, true);
    defer scenario.deinit();
    const core_relative = try support.path(fixture.allocator, name, "core");
    const core = try fixture.makeRoot(core_relative, arch);
    try support.copyProgram(fixture, core_relative, "/bin/sh", "/bin/sh");
    try support.copyProgram(fixture, core_relative, "/usr/bin/dpkg-trigger", "/usr/bin/dpkg-trigger");
    try support.fixtureFile(fixture, try support.path(fixture.allocator, core_relative, support.trace), "", 0o644);
    const roots = [_][]const u8{ scenario.reference_root, scenario.native_root, core };
    var seeds: std.ArrayList([]const u8) = .empty;
    for ([_][]const u8{ "native-helper-target", "essential-core" }) |selector|
        try seeds.append(fixture.allocator, try archive(fixture, suite, arch, selector));
    for (case.seeds) |selector| try seeds.append(fixture.allocator, try archive(fixture, suite, arch, selector));
    if (case.conffile != null) {
        const old = try support.makePackage(fixture, arch, "0.1-1", "conffile-pkg", try support.path(fixture.allocator, name, "old"), .{
            .conffile_path = "etc/debz-fixture.conf",
            .conffile_content = "old package configuration\n",
            .no_scripts = true,
        });
        try seeds.append(fixture.allocator, old);
    }
    for (seeds.items, 0..) |seed, index| {
        try scenario.seed(seed);
        const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/core-seed-{d}", .{ name, index });
        try fixture.directory(destination);
        if (try support.reference(fixture, dpkg, core, .{ .operation = "install", .archives = &.{seed}, .triggers = true }, destination) != 0)
            return error.CoreSeedFailed;
        try support.fixtureFile(fixture, try support.path(fixture.allocator, core_relative, support.trace), "", 0o644);
    }
    var helper_file = try std.Io.Dir.cwd().openFile(fixture.io, helper, .{});
    defer helper_file.close(fixture.io);
    var helper_reader = helper_file.reader(fixture.io, &.{});
    const helper_bytes = try helper_reader.interface.allocRemaining(fixture.allocator, .limited(32 * 1024 * 1024));
    try fixture.write(try relative(fixture, scenario.native_root, helper_path), helper_bytes, 0o755);
    for (roots, 0..) |root, index| {
        if (case.conffile != null) {
            try support.fixtureFile(fixture, try relative(fixture, root, "etc/debz-fixture.conf"), "local user configuration\n", 0o644);
        }
        if (case.hold) |held| {
            const destination = try std.fmt.allocPrint(fixture.allocator, "{s}/selection-{d}", .{ name, index });
            try fixture.directory(destination);
            try setHold(fixture, dpkg, root, held, destination);
        }
    }
    const original = [_]Identity{
        try identity(fixture, roots[0]), try identity(fixture, roots[1]), try identity(fixture, roots[2]),
    };
    const before = [_][]const u8{
        try foundation.capture(fixture.allocator, fixture.io, roots[0]),
        try foundation.capture(fixture.allocator, fixture.io, roots[1]),
        try foundation.capture(fixture.allocator, fixture.io, roots[2]),
    };
    const core_lock = try fixture.absolute(try support.path(fixture.allocator, name, "core.lock.json"));
    const family_lock = try fixture.absolute(try support.path(fixture.allocator, name, "family.lock.json"));
    const policy = case.conffile orelse "keep_existing";
    const common: []const []const u8 = &.{
        "--install-root",        core,                                                                          "--architecture", arch,
        "--cache-path",          try fixture.absolute(try support.path(fixture.allocator, name, "core-cache")), "--state-path",   try fixture.absolute(try support.path(fixture.allocator, name, "core-state")),
        "--source",              source,                                                                        "--keyring",      keyring,
        "--transaction-backend", "native",                                                                      "--conffile",     if (case.conffile != null and std.mem.eql(u8, policy, "use_package_version")) "use-package-version" else "keep-existing",
        "--json",
    };
    var plan_args: std.ArrayList([]const u8) = .empty;
    if (case.recommends) try plan_args.append(fixture.allocator, "--recommends");
    try plan_args.appendSlice(fixture.allocator, &.{ "--lock-output", core_lock });
    if (case.package) |package| try plan_args.append(fixture.allocator, package);
    var core_plan = try public(fixture, cli, try support.path(fixture.allocator, name, "core-plan"), "plan", common, plan_args.items, 0);
    defer core_plan.deinit();
    var request: family.FamilyRequest = .{
        .operation = "resolve_lock",
        .root = scenario.native_root,
        .architecture = arch,
        .sources = &.{source},
        .keyrings = &.{keyring},
        .cache = try fixture.absolute(try support.path(fixture.allocator, name, "family-cache")),
        .state = try fixture.absolute(try support.path(fixture.allocator, name, "family-state")),
        .package = case.package,
        .conffile = policy,
        .recommends = case.recommends,
        .lock_output = family_lock,
    };
    var plan = try family.workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "family-plan"), .{
        .family_execution = request,
        .family_update_planning = case.update,
        .capture_evidence = true,
    });
    defer plan.deinit();
    try flag(plan.report.value, "succeeded", true);
    try flag(plan.report.value, "changed", false);
    try text(plan.report.value, "exit_status", "success");
    const core_lock_bytes = try support.read(fixture, try support.path(fixture.allocator, name, "core.lock.json"), 1024 * 1024);
    const family_lock_bytes = try support.read(fixture, try support.path(fixture.allocator, name, "family.lock.json"), 1024 * 1024);
    if (!std.mem.eql(u8, core_lock_bytes, family_lock_bytes)) return error.ConsumerLockMismatch;
    var lock = try debz.exact_lock_v3.decode(fixture.allocator, core_lock_bytes, 1024 * 1024);
    defer lock.deinit();
    var lock_doc = try family.parse(fixture, try support.path(fixture.allocator, name, "core.lock.json"), 1024 * 1024);
    defer lock_doc.deinit();
    const digest = try family.string(lock_doc.value, "digest_sha256");
    for (roots, before) |root, original_state| {
        const after = try foundation.capture(fixture.allocator, fixture.io, root);
        if (!std.mem.eql(u8, original_state, after)) return error.PlanMutatedInstalledRoot;
    }
    var execute_args: std.ArrayList([]const u8) = .empty;
    if (case.recommends) try execute_args.append(fixture.allocator, "--recommends");
    try execute_args.appendSlice(fixture.allocator, &.{ "--lock-input", core_lock, "--assume-yes", "--noninteractive" });
    if (case.package) |package| try execute_args.append(fixture.allocator, package);
    var result = try public(fixture, cli, try support.path(fixture.allocator, name, "core-execute"), if (case.update) "upgrade-all" else "install", common, execute_args.items, case.exit_status);
    defer result.deinit();
    request.operation = if (case.update) "update" else "create";
    request.lock_output = null;
    request.lock_input = family_lock;
    var executed = try family.workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "family-execute"), .{
        .family_execution = request,
        .capture_evidence = true,
    });
    defer executed.deinit();
    try diagnostics(result.value, executed.report.value, suite, arch, case);
    try text(executed.report.value, "exit_status", if (case.exit_status == 0) "success" else "transaction");
    try flag(executed.report.value, "succeeded", case.exit_status == 0);
    try flag(executed.report.value, "changed", case.archives.len != 0);
    try flag(result.value, "changed", case.archives.len != 0);
    try support.absent(fixture, try support.path(fixture.allocator, name, "family-state/transaction-result.json"));
    const evidence = executed.evidence orelse return error.MissingNativeEvidence;
    if (case.archives.len != 0) {
        if (case.reference_phases.len == 0) {
            var archives: std.ArrayList([]const u8) = .empty;
            for (case.archives) |selector| try archives.append(fixture.allocator, try archive(fixture, suite, arch, selector));
            try referencePhase(fixture, dpkg, scenario.reference_root, policy, case.exit_status, archives.items, try support.path(fixture.allocator, name, "reference-execute"));
        } else for (case.reference_phases, 0..) |phase, index| {
            var archives: std.ArrayList([]const u8) = .empty;
            for (phase) |selector| try archives.append(fixture.allocator, try archive(fixture, suite, arch, selector));
            try referencePhase(fixture, dpkg, scenario.reference_root, policy, case.exit_status, archives.items, try std.fmt.allocPrint(fixture.allocator, "{s}/reference-execute-{d}", .{ name, index }));
        }
    }
    const core_compare = try support.path(fixture.allocator, name, "compare-core");
    const family_compare = try support.path(fixture.allocator, name, "compare-family");
    try fixture.directory(core_compare);
    try fixture.directory(family_compare);
    try support.compare(fixture, scenario.reference_root, core, core_compare, true);
    try support.compare(fixture, scenario.reference_root, scenario.native_root, family_compare, true);
    for (roots, original) |root, snapshot| {
        const observed = try identity(fixture, root);
        if (snapshot.inode != observed.inode or !std.mem.eql(u8, &snapshot.digest, &observed.digest))
            return error.PackageOwnedHelperChanged;
    }
    for (roots[1..]) |root| {
        try support.absent(fixture, try relative(fixture, root, operation_path));
        try support.absent(fixture, try relative(fixture, root, intent_path));
        if (case.archives.len == 0) {
            try support.absent(fixture, try relative(fixture, root, provenance_path));
            try support.absent(fixture, try relative(fixture, root, completion_path));
            const prior = if (std.mem.eql(u8, root, roots[1])) before[1] else before[2];
            if (!std.mem.eql(u8, prior, try foundation.capture(fixture.allocator, fixture.io, root)))
                return error.HeldConsumerMutatedRoot;
            continue;
        }
        var receipt = try rootDocument(fixture, root, provenance_path);
        defer receipt.deinit();
        var completion = try rootDocument(fixture, root, completion_path);
        defer completion.deinit();
        try text(receipt.value, "outcome", if (case.exit_status == 0) "succeeded" else "failed");
        try text(receipt.value, "exact_lock_sha256", digest);
        const binding = try family.field(completion.value, "transaction_provenance");
        try text(binding, "document_sha256", try family.string(receipt.value, "digest_sha256"));
        try text(completion.value, "attempt_id", try family.string(receipt.value, "attempt_id"));
        try retained.verify(fixture, root, arch, digest, case.exit_status != 0);
    }
    if (case.archives.len == 0) {
        try nullField(evidence.value, "native_completion");
        try nullField(evidence.value, "native_install");
        try nullField(executed.report.value, "provenance_path");
    } else {
        try text(try family.field(evidence.value, "native_completion"), "outcome", if (case.exit_status == 0) "succeeded" else "failed");
        if (case.exit_status == 0) {
            var proof = try public(fixture, cli, try support.path(fixture.allocator, name, "core-proof"), "transaction-result", &.{ "verify", "--transaction-backend", "native", "--install-root", core, "--architecture", arch, "--lock-input", core_lock, "--json" }, &.{}, 0);
            defer proof.deinit();
            const previous = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
            var verified = try family.workflow(fixture, driver, scenario.native_root, arch, try support.path(fixture.allocator, name, "family-proof"), .{
                .family_verification = request,
                .verification_expect_failure = false,
                .verification_completion = try family.field(evidence.value, "native_completion"),
            });
            defer verified.deinit();
            try text(verified.report.value, "final_verification_status", "exact_match");
            try text(verified.report.value, "lock_evidence", "exact_match");
            try text(verified.report.value, "receipt_evidence", "exact_match");
            try text(verified.report.value, "outcome", "succeeded");
            try text(verified.report.value, "lock_sha256", digest);
            const after = try foundation.capture(fixture.allocator, fixture.io, scenario.native_root);
            if (!std.mem.eql(u8, previous, after)) return error.VerificationMutatedRoot;
        }
    }
    const actual_core = try foundation.captureRealRoot(fixture.allocator, fixture.io, core, .{}, &.{ foundation.guard, helper_path });
    const actual_family = try foundation.captureRealRoot(fixture.allocator, fixture.io, scenario.native_root, .{}, &.{ foundation.guard, helper_path });
    const actual_reference = try foundation.captureRealRoot(fixture.allocator, fixture.io, scenario.reference_root, .{}, &.{ foundation.guard, helper_path });
    return std.mem.eql(u8, core_lock_bytes, family_lock_bytes) and
        std.mem.eql(u8, actual_core, actual_reference) and
        std.mem.eql(u8, actual_family, actual_reference) and
        std.mem.eql(u8, &original[0].digest, &(try identity(fixture, roots[0])).digest) and
        std.mem.eql(u8, &original[1].digest, &(try identity(fixture, roots[1])).digest) and
        std.mem.eql(u8, &original[2].digest, &(try identity(fixture, roots[2])).digest);
}

fn referencePhase(fixture: *foundation.Fixture, dpkg: []const u8, root: []const u8, policy: []const u8, expected: u8, archives: []const []const u8, destination: []const u8) !void {
    try fixture.directory(destination);
    const result = try support.reference(fixture, dpkg, root, .{ .operation = "install", .archives = archives, .policy = policy, .triggers = true }, destination);
    if (result != @as(u8, if (expected == 0) 0 else 1)) {
        std.debug.print("{s}: dpkg exited {d}, expected {d}\n", .{ destination, result, @as(u8, if (expected == 0) 0 else 1) });
        return error.UnexpectedReferenceResult;
    }
}

pub fn main(init: std.process.Init) !void {
    var arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 4) return error.MissingConsumerExecutables;
    const driver = args[1];
    const cli = args[2];
    const helper = args[3];
    var pinned: ?[]const u8 = null;
    var python: []const u8 = "/usr/bin/python3";
    var selected: ?[]const u8 = null;
    var index: usize = 4;
    while (index < args.len) : (index += 2) {
        if (index + 1 >= args.len) return error.InvalidArguments;
        if (std.mem.eql(u8, args[index], "--reference-dpkg")) {
            pinned = args[index + 1];
        } else if (std.mem.eql(u8, args[index], "--fixture-python")) {
            python = args[index + 1];
        } else if (std.mem.eql(u8, args[index], "--case")) {
            selected = args[index + 1];
        } else return error.InvalidArguments;
    }
    const reference = try support.prerequisites(init, allocator, pinned);
    var fixture = try foundation.Fixture.init(allocator, init.io, options.repository);
    defer fixture.deinit();
    errdefer fixture.retain = true;
    errdefer support.assertHostUnchanged(allocator, init.io, reference.before) catch {};
    var rows: std.ArrayList(oracle.ParityRow) = .empty;
    for (oracle.parity_suites) |suite| {
        if (selected) |filter| if (!std.mem.startsWith(u8, filter, suite)) continue;
        const signed = try generate(&fixture, python, suite, reference.architecture);
        for (oracle.parity_cases) |case| {
            if (selected) |filter| {
                const full = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ suite, case.id });
                if (!std.mem.eql(u8, filter, full)) continue;
            }
            const matched = execute(&fixture, driver, cli, helper, reference.executable, reference.architecture, suite, case, signed.source, signed.keyring);
            const actual = matched catch |err| {
                std.debug.print("signed consumer parity {s}/{s}: {s}\n", .{ suite, case.id, @errorName(err) });
                return err;
            };
            try rows.append(allocator, .{
                .suite = suite,
                .case_id = case.id,
                .architecture = reference.architecture,
                .consumers = &oracle.parity_consumers,
                .matched = actual,
            });
            std.debug.print("signed consumer parity {s}/{s}: {s}\n", .{ suite, case.id, if (actual) "core + FAMILY + dpkg matched" else "mismatch" });
        }
    }
    if (selected == null) try oracle.validateConsumerParity(rows.items, reference.architecture) else {
        if (rows.items.len != 1 or !rows.items[0].matched) return error.ConsumerParityMismatch;
    }
    try support.assertHostUnchanged(allocator, init.io, reference.before);
}
