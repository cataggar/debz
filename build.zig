const std = @import("std");
const liblzma_build = @import("build/liblzma.zig");

const package_version = "0.3.0";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version = b.option([]const u8, "version", "Release version (SemVer)") orelse package_version;
    _ = std.SemanticVersion.parse(version) catch {
        std.debug.panic("invalid -Dversion '{s}': expected SemVer (for example 0.3.0 or 1.2.3-rc.1)", .{version});
    };

    const require_privileged_orchestration_tests = b.option(
        bool,
        "require-privileged-orchestration-tests",
        "Fail instead of skipping privileged production orchestration tests",
    ) orelse false;
    const native_helper_debug_info = b.option(
        bool,
        "native-helper-debug-info",
        "Retain debugger metadata in the private native helper",
    ) orelse false;
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
    build_options.addOption(bool, "native_helper_debug_info", native_helper_debug_info);
    build_options.addOption(
        bool,
        "require_privileged_orchestration_tests",
        require_privileged_orchestration_tests,
    );

    const zstd_dependency = b.dependency("zstd", .{
        .target = target,
        .optimize = optimize,
        .shared = false,
        .tools = false,
        .multithread = false,
    });
    const zstd = zstd_dependency.artifact("zstd");

    // Zig 0.16 exposes paths from dependencies without build.zig files, so
    // the repository-local module can compile the exact upstream XZ sources.
    const xz_dependency = b.dependency("xz", .{});
    const liblzma = liblzma_build.addStaticLibrary(b, xz_dependency, target, optimize);

    const libsolv_dependency = b.dependency("libsolv", .{
        .target = target,
        // libsolv relies on C's wrapping arithmetic and null-based container
        // offset idioms that Zig safety instrumentation rejects.
        .optimize = .ReleaseFast,
        .shared = false,
        .conda = false,
        .@"multi-semantics" = false,
        .debian = true,
        .ext = false,
        .zlib = false,
        .lzma = false,
        .bzip2 = false,
        .zstd = false,
        .tools = false,
    });
    const libsolv = libsolv_dependency.artifact("solv");

    const debz = b.addModule("debz", .{
        .root_source_file = b.path("src/debz.zig"),
        .target = target,
        .optimize = optimize,
    });
    debz.addOptions("debz_build_options", build_options);
    debz.addIncludePath(libsolv_dependency.path("src"));
    debz.addIncludePath(xz_dependency.path("src/liblzma/api"));
    debz.addIncludePath(zstd_dependency.path("lib"));
    debz.addCMacro("LZMA_API_STATIC", "1");
    debz.linkLibrary(libsolv);
    debz.linkLibrary(liblzma);
    debz.linkLibrary(zstd);
    debz.link_libc = true;

    const cli_backend_policy = b.createModule(.{
        .root_source_file = b.path("src/cli_backend_policy.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_backend_policy.addImport("debz", debz);
    const repository_cli = b.createModule(.{
        .root_source_file = b.path("src/repository_cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    repository_cli.addImport("debz", debz);
    repository_cli.addImport("cli_backend_policy", cli_backend_policy);

    const cli_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const release_cli_options = b.addOptions();
    release_cli_options.addOption(bool, "native_only", false);
    cli_module.addImport("debz", debz);
    cli_module.addImport("repository_cli", repository_cli);
    cli_module.addImport("cli_backend_policy", cli_backend_policy);
    cli_module.addOptions("cli_rehearsal_options", release_cli_options);

    const cli = b.addExecutable(.{
        .name = "debz",
        .root_module = cli_module,
    });
    const install_cli = b.addInstallArtifact(cli, .{});
    b.getInstallStep().dependOn(&install_cli.step);
    const release_install = b.step("release-install", "Install the complete release tree for packaging");
    release_install.dependOn(b.getInstallStep());
    installReleaseFiles(b, install_cli, release_install, target);

    const run_cli = b.addRunArtifact(cli);
    run_cli.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cli.addArgs(args);
    b.step("run", "Run the debz CLI").dependOn(&run_cli.step);

    const tests = b.addTest(.{ .root_module = debz });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit and CLI integration tests");
    const workload_core = b.step("test-workload-core", "Run the core unit, CLI, consumer and repository-add workload partition");
    const workload_production = b.step("test-workload-production", "Run the production backend, family, security and customize workload partition");
    const workload_apt_system = b.step("test-workload-apt-system", "Run the apt system facade and orchestrator workload partition");
    const workload_native = b.step("test-workload-native", "Run the native transaction, dpkg oracle and recovery unit workload partition");
    const workload_release = b.step("test-workload-release", "Run the release schema and native-only rehearsal workload partition");
    test_step.dependOn(workload_core);
    test_step.dependOn(workload_production);
    test_step.dependOn(workload_apt_system);
    test_step.dependOn(workload_native);
    test_step.dependOn(workload_release);
    workload_core.dependOn(&run_tests.step);

    const repository_cli_tests = b.addTest(.{ .root_module = repository_cli });
    const run_repository_cli_tests = b.addRunArtifact(repository_cli_tests);
    workload_core.dependOn(&run_repository_cli_tests.step);

    const cli_tests = b.addSystemCommand(&.{ "sh", "tools/test-cli.sh" });
    cli_tests.addArtifactArg(cli);
    cli_tests.addArg(version);
    workload_core.dependOn(&cli_tests.step);

    const help_cases = [_]struct {
        args: []const []const u8,
        usage: []const u8,
    }{
        .{ .args = &.{}, .usage = "debz <command> [options] [packages...]" },
        .{ .args = &.{"repo"}, .usage = "debz repo <command> [options]" },
        .{ .args = &.{ "repo", "add" }, .usage = "debz repo add --url URL [options]" },
        .{ .args = &.{"package-cache"}, .usage = "debz package-cache <command> [options]" },
        .{ .args = &.{ "package-cache", "fingerprint" }, .usage = "debz package-cache fingerprint --lock-input PATH" },
        .{ .args = &.{ "package-cache", "prepare" }, .usage = "debz package-cache prepare --lock-input PATH" },
        .{ .args = &.{"transaction-result"}, .usage = "debz transaction-result verify --state-path PATH" },
        .{ .args = &.{ "transaction-result", "verify" }, .usage = "debz transaction-result verify --state-path PATH" },
        .{ .args = &.{ "transaction-result", "capabilities" }, .usage = "debz transaction-result capabilities --transaction-backend native --json" },
        .{ .args = &.{"apt"}, .usage = "debz apt [--profile PATH] [--json] <command>" },
        .{ .args = &.{ "apt", "install" }, .usage = "debz apt [--profile PATH] [--json] install [-y] PACKAGE..." },
        .{ .args = &.{ "recover", "--system-profile", "/profile.json" }, .usage = "debz recover [--json] --system-profile PATH" },
        .{ .args = &.{"refresh"}, .usage = "debz refresh [options]" },
        .{ .args = &.{"install"}, .usage = "debz install [options] <package>" },
        .{ .args = &.{"remove"}, .usage = "debz remove [options] <package>" },
        .{ .args = &.{"upgrade"}, .usage = "debz upgrade [options] [package...]" },
        .{ .args = &.{"upgrade-all"}, .usage = "debz upgrade-all [options]" },
        .{ .args = &.{"reinstall"}, .usage = "debz reinstall [options] <package>" },
        .{ .args = &.{"download"}, .usage = "debz download [options] <package>" },
        .{ .args = &.{"plan"}, .usage = "debz plan [options] [package]" },
        .{ .args = &.{"list-installed"}, .usage = "debz list-installed [options]" },
        .{ .args = &.{"list-available"}, .usage = "debz list-available [options]" },
        .{ .args = &.{"info"}, .usage = "debz info [options] <package>..." },
        .{ .args = &.{"provides"}, .usage = "debz provides [options] <capability>..." },
        .{ .args = &.{"why"}, .usage = "debz why [options] <package>..." },
        .{ .args = &.{"clean"}, .usage = "debz clean [options]" },
        .{ .args = &.{"recover"}, .usage = "debz recover [options]" },
        .{ .args = &.{"package-family-capabilities"}, .usage = "debz package-family-capabilities" },
        .{ .args = &.{"version"}, .usage = "debz version" },
        // Help wins after positional or malformed arguments so parsing and IO never begin.
        .{ .args = &.{ "install", "example" }, .usage = "debz install [options] <package>" },
        .{ .args = &.{ "install", "--deadline-ms" }, .usage = "debz install [options] <package>" },
        .{ .args = &.{ "install", "--unknown" }, .usage = "debz install [options] <package>" },
        .{ .args = &.{ "repo", "add", "--url" }, .usage = "debz repo add --url URL [options]" },
        .{ .args = &.{ "repo", "add", "--unknown" }, .usage = "debz repo add --url URL [options]" },
        .{ .args = &.{ "package-cache", "prepare", "--lock-input" }, .usage = "debz package-cache prepare --lock-input PATH" },
        .{ .args = &.{ "package-cache", "fingerprint", "--unknown" }, .usage = "debz package-cache fingerprint --lock-input PATH" },
    };
    for (help_cases) |case| {
        addHelpFlagTests(b, workload_core, cli, case.args, case.usage);
    }

    const no_args_help = b.addRunArtifact(cli);
    no_args_help.expectExitCode(0);
    no_args_help.expectStdOutMatch("debz <command> [options] [packages...]");
    no_args_help.expectStdErrEqual("");
    workload_core.dependOn(&no_args_help.step);

    const positional_help = b.addRunArtifact(cli);
    positional_help.addArg("help");
    positional_help.expectExitCode(2);
    positional_help.expectStdOutEqual("");
    positional_help.expectStdErrMatch("debz: unknown command 'help'");
    workload_core.dependOn(&positional_help.step);

    const removed_version_flag = b.addRunArtifact(cli);
    removed_version_flag.addArg("--version");
    removed_version_flag.expectExitCode(2);
    removed_version_flag.expectStdOutEqual("");
    removed_version_flag.expectStdErrMatch("debz: unknown command '--version'");
    workload_core.dependOn(&removed_version_flag.step);

    const consumer_tests = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "--cache-dir",
        "../../.zig-cache/public-consumer",
    });
    consumer_tests.setCwd(b.path("test/consumer"));
    workload_core.dependOn(&consumer_tests.step);

    const integration_tests = b.addSystemCommand(&.{ "sh", "tools/test-integration-roots.sh" });
    integration_tests.addArtifactArg(cli);
    b.step("test-integration", "Run hermetic signed-repository integration roots")
        .dependOn(&integration_tests.step);

    const real_snapshot_comparator_module = b.createModule(.{
        .root_source_file = b.path("test/real-snapshot-comparator.zig"),
        .target = target,
        .optimize = optimize,
    });
    const real_snapshot_comparator = b.addExecutable(.{
        .name = "real-snapshot-comparator",
        .root_module = real_snapshot_comparator_module,
    });
    const install_real_snapshot_comparator = b.addInstallArtifact(
        real_snapshot_comparator,
        .{},
    );
    const real_snapshot_comparator_tests = b.addTest(.{
        .root_module = real_snapshot_comparator_module,
    });
    const run_real_snapshot_comparator_tests = b.addRunArtifact(
        real_snapshot_comparator_tests,
    );
    const real_snapshot_comparator_step = b.step(
        "test-real-snapshot-comparator",
        "Run Zig native/reference real-snapshot comparison assertions",
    );
    real_snapshot_comparator_step.dependOn(
        &run_real_snapshot_comparator_tests.step,
    );
    real_snapshot_comparator_step.dependOn(
        &install_real_snapshot_comparator.step,
    );
    workload_core.dependOn(&run_real_snapshot_comparator_tests.step);

    const debian_closure_inventory_module = b.createModule(.{
        .root_source_file = b.path("test/debian-closure-inventory.zig"),
        .target = target,
        .optimize = optimize,
    });
    debian_closure_inventory_module.addImport("debz", debz);
    for ([_][2][]const u8{
        .{ "debian_closure_amd64_apt_lock", "amd64-apt" },
        .{ "debian_closure_amd64_systemd_sysv_lock", "amd64-systemd-sysv" },
        .{ "debian_closure_arm64_apt_lock", "arm64-apt" },
        .{ "debian_closure_arm64_systemd_sysv_lock", "arm64-systemd-sysv" },
    }) |lock| debian_closure_inventory_module.addAnonymousImport(lock[0], .{
        .root_source_file = b.path(b.fmt(
            "tools/fixtures/debian-stable-closure-v1/{s}.lock.json",
            .{lock[1]},
        )),
    });
    debian_closure_inventory_module.addAnonymousImport("debian_closure_evidence", .{
        .root_source_file = b.path("tools/fixtures/debian-stable-closure-v1/evidence.json"),
    });
    debian_closure_inventory_module.addAnonymousImport("debian_stable_pin", .{
        .root_source_file = b.path("tools/fixtures/debian-stable-readiness-v1.json"),
    });
    const debian_closure_inventory = b.addExecutable(.{
        .name = "debian-closure-inventory",
        .root_module = debian_closure_inventory_module,
    });
    const install_debian_closure_inventory = b.addInstallArtifact(
        debian_closure_inventory,
        .{},
    );
    const debian_closure_inventory_tests = b.addTest(.{
        .root_module = debian_closure_inventory_module,
    });
    const run_debian_closure_inventory_tests = b.addRunArtifact(
        debian_closure_inventory_tests,
    );
    const debian_closure_inventory_step = b.step(
        "test-debian-closure-inventory",
        "Run Debian closure pre-mutation inventory and native gap classification tests",
    );
    debian_closure_inventory_step.dependOn(
        &run_debian_closure_inventory_tests.step,
    );
    debian_closure_inventory_step.dependOn(
        &install_debian_closure_inventory.step,
    );
    workload_core.dependOn(&run_debian_closure_inventory_tests.step);

    const apt_system_acceptance_module = b.createModule(.{
        .root_source_file = b.path("test/apt-system-acceptance.zig"),
        .target = target,
        .optimize = optimize,
    });
    apt_system_acceptance_module.link_libc = true;
    const apt_system_acceptance_binary = b.addExecutable(.{
        .name = "apt-system-acceptance",
        .root_module = apt_system_acceptance_module,
    });
    const apt_acceptance_unit_tests = b.addTest(.{ .root_module = apt_system_acceptance_module });
    const run_apt_acceptance_unit_tests = b.addRunArtifact(apt_acceptance_unit_tests);
    b.step("test-apt-system-acceptance-unit", "Check Zig acceptance fixture guards without root")
        .dependOn(&run_apt_acceptance_unit_tests.step);
    workload_core.dependOn(&run_apt_acceptance_unit_tests.step);
    const apt_system_acceptance_zig = b.addRunArtifact(apt_system_acceptance_binary);
    apt_system_acceptance_zig.addArtifactArg(cli);
    b.step("test-apt-system-acceptance-zig", "Run executable Zig apt facade acceptance (requires root)")
        .dependOn(&apt_system_acceptance_zig.step);
    const apt_system_acceptance_step = b.step(
        "test-apt-system-acceptance",
        "Run real apt facade and dpkg in a disposable root (requires root)",
    );
    apt_system_acceptance_step.dependOn(&apt_system_acceptance_zig.step);

    const native_differential_step = b.step(
        "test-native-differential",
        "Validate the native transaction compatibility corpus and comparator",
    );

    const repository_add_module = b.createModule(.{
        .root_source_file = b.path("test/repository-add-integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    repository_add_module.addImport("debz", debz);
    repository_add_module.addImport("repository_cli", repository_cli);
    const repository_add_harness = b.addExecutable(.{
        .name = "repository-add-integration",
        .root_module = repository_add_module,
    });
    const repository_add_tests = b.addSystemCommand(
        &.{ "sh", "tools/test-repository-add.sh" },
    );
    repository_add_tests.addArtifactArg(cli);
    repository_add_tests.addArtifactArg(repository_add_harness);
    const repository_add_step = b.step(
        "test-repository-add",
        "Run the hermetic Microsoft-shaped repository add integration",
    );
    repository_add_step.dependOn(&repository_add_tests.step);
    repository_add_step.dependOn(&run_repository_cli_tests.step);
    const repository_backend_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{ "repository_backend.test.", "repository_command.test.", "repository_api.test.", "repository_plan.test.", "target_apt_config.test.", "reviewed_repository_profile.test." },
    });
    const run_repository_backend_tests = b.addRunArtifact(repository_backend_tests);
    repository_add_step.dependOn(&run_repository_backend_tests.step);
    workload_core.dependOn(&repository_add_tests.step);
    // Manual evidence against the live Microsoft Noble repository. It needs
    // network access and sudo, so it is opt-in and never part of CI.
    const live_repository_add = b.step(
        "test-live-repository-add",
        "Manual live packages.microsoft.com repo add evidence (requires -Dlive-repository-tests=true, network and sudo)",
    );
    if (b.option(bool, "live-repository-tests", "Enable network-backed manual repository evidence steps") orelse false) {
        const live_repository_add_run = b.addSystemCommand(&.{ "sh", "tools/test-live-repository-add.sh" });
        live_repository_add_run.addArtifactArg(cli);
        live_repository_add_run.has_side_effects = true;
        live_repository_add.dependOn(&live_repository_add_run.step);
    } else {
        live_repository_add.dependOn(&b.addFail("test-live-repository-add requires -Dlive-repository-tests=true").step);
    }

    const fuzz_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("fuzz/fuzz_targets.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    fuzz_tests.root_module.addImport("debz", debz);
    const fuzz_options = b.addOptions();
    fuzz_options.addOption(
        usize,
        "smoke_cases",
        b.option(usize, "fuzz-cases", "Deterministic mutation cases per corpus seed") orelse 256,
    );
    fuzz_tests.root_module.addOptions("fuzz_options", fuzz_options);
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    b.step("fuzz", "Run parser fuzz targets (use --fuzz=<cases> for mutation fuzzing)")
        .dependOn(&run_fuzz_tests.step);

    const audit_step = b.step(
        "security-audit",
        "Run hermeticity, dependency-policy, license, secret, and docs gates",
    );
    const audit = b.addSystemCommand(&.{ "python3", "tools/security-audit.py" });
    audit_step.dependOn(&audit.step);
    const write_digest_inventory_step = b.step(
        "write-digest-inventory",
        "Regenerate the digest cutover inventories",
    );
    const write_digest_inventory = b.addSystemCommand(&.{ "python3", "tools/security-audit.py", "--write-digest-inventory" });
    write_digest_inventory_step.dependOn(&write_digest_inventory.step);
    const security_policy_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/security-policy.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_security_policy_tests = b.addRunArtifact(security_policy_tests);
    run_security_policy_tests.setCwd(b.path("."));
    audit_step.dependOn(&run_security_policy_tests.step);
    const snapshot_policy_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/real-snapshot-policy.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_snapshot_policy_tests = b.addRunArtifact(snapshot_policy_tests);
    run_snapshot_policy_tests.setCwd(b.path("."));
    audit_step.dependOn(&run_snapshot_policy_tests.step);
    const snapshot_repin_options = b.addOptions();
    snapshot_repin_options.addOptionPath("debz", cli.getEmittedBin());
    const snapshot_repin_module = b.createModule(.{
        .root_source_file = b.path("test/real-snapshot-repin.zig"),
        .target = target,
        .optimize = optimize,
    });
    snapshot_repin_module.addOptions("real_snapshot_repin_options", snapshot_repin_options);
    const run_snapshot_repin_tests = b.addRunArtifact(b.addTest(.{ .root_module = snapshot_repin_module }));
    run_snapshot_repin_tests.setCwd(b.path("."));
    b.step("test-real-snapshot-repin", "Drive the real-snapshot repin tool against synthetic signed snapshots")
        .dependOn(&run_snapshot_repin_tests.step);
    workload_release.dependOn(&run_snapshot_repin_tests.step);
    const audit_tests = b.addSystemCommand(
        &.{
            "env",
            "PYTHONDONTWRITEBYTECODE=1",
            "python3",
            "-m",
            "unittest",
            "tools/test_real_snapshot_reference_launcher.py",
            "tools/test_real_snapshot_reference_protected_ci.py",
            "tools/test_vendor_state_capture.py",
            "tools/test_dpkg_config_reference.py",
            "tools/test_dpkg_alternatives_reference.py",
            "tools/test_release_workflow_policy.py",
            "tools/test_debian_stable_readiness.py",
            "tools/test_debian_stable_closure.py",
            "tools/test_real_snapshot_repin.py",
        },
    );
    audit_step.dependOn(&audit_tests.step);
    const reference_launcher_module = b.createModule(.{
        .root_source_file = b.path("tools/real-snapshot-reference-launcher.zig"),
        .target = target,
        .optimize = optimize,
    });
    reference_launcher_module.link_libc = true;
    const reference_launcher_tests = b.addTest(.{ .root_module = reference_launcher_module });
    const run_reference_launcher_tests = b.addRunArtifact(reference_launcher_tests);
    b.step("test-real-snapshot-reference-launcher", "Check bounded reference operation, syscall filters and unprivileged capability refusal")
        .dependOn(&run_reference_launcher_tests.step);
    audit_step.dependOn(&run_reference_launcher_tests.step);
    // The capability transition must be proven with the real root authority the
    // protected launcher uses. It stays outside security-audit, which must run
    // without passwordless sudo; CI runs this step explicitly.
    const reference_launcher_root_module = b.createModule(.{
        .root_source_file = b.path("tools/real-snapshot-reference-launcher-root-test.zig"),
        .target = target,
        .optimize = optimize,
    });
    reference_launcher_root_module.link_libc = true;
    const reference_launcher_root_tests = b.addTest(.{ .root_module = reference_launcher_root_module });
    const run_reference_launcher_root_tests = b.addSystemCommand(&.{ "sudo", "-n", "--" });
    run_reference_launcher_root_tests.addArtifactArg(reference_launcher_root_tests);
    b.step("test-real-snapshot-reference-launcher-root", "Prove the reference capability transition as root through sudo -n")
        .dependOn(&run_reference_launcher_root_tests.step);
    // The protected proof stages this static probe itself; compiling it here
    // keeps it building on every audited architecture.
    const reference_escape_probe = b.addExecutable(.{
        .name = "real-snapshot-reference-escape-probe",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/real-snapshot-reference-escape-probe.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
        }),
    });
    audit_step.dependOn(&reference_escape_probe.step);
    const protected_reference = b.addSystemCommand(
        &.{ "python3", "tools/test_real_snapshot_reference_protected.py" },
    );
    protected_reference.addArgs(&.{
        "--launcher",
        b.option([]const u8, "reference-protected-launcher", "Root-owned protected ReleaseSafe launcher") orelse "",
        "--dpkg",
        b.option([]const u8, "reference-protected-dpkg", "Root-owned native hash-pinned dpkg 1.22.22") orelse "",
        "--root-template",
        b.option([]const u8, "reference-protected-root-template", "New protected script-free reference root template") orelse "",
        "--workspace",
        b.option([]const u8, "reference-protected-workspace", "New empty root-owned mode-0700 proof workspace") orelse "",
        "--archive",
        b.option([]const u8, "reference-protected-archive", "Protected authenticated test package archive") orelse "",
        "--archive-sha512",
        b.option([]const u8, "reference-protected-archive-sha512", "Authenticated archive SHA512") orelse "",
        "--archive-size",
        b.fmt("{d}", .{b.option(usize, "reference-protected-archive-size", "Authenticated archive byte size") orelse 0}),
        "--escape-probe",
        b.option([]const u8, "reference-protected-escape-probe", "Root-owned static escape probe run unconfined as a control") orelse "",
        "--escape-archive",
        b.option([]const u8, "reference-protected-escape-archive", "Protected archive whose preinst is the static escape probe") orelse "",
        "--escape-archive-sha512",
        b.option([]const u8, "reference-protected-escape-archive-sha512", "Escape probe archive SHA512") orelse "",
        "--escape-archive-size",
        b.fmt("{d}", .{b.option(usize, "reference-protected-escape-archive-size", "Escape probe archive byte size") orelse 0}),
        "--profile-scripts",
        b.option([]const u8, "reference-protected-profile-scripts", "Root-owned signed amd64 systemd/udev/sudo postinsts (empty on arm64)") orelse "",
        "--architecture",
        b.option([]const u8, "reference-protected-architecture", "Native amd64 or arm64") orelse "",
    });
    protected_reference.setCwd(b.path("."));
    b.step("test-real-snapshot-reference-protected", "Run non-skipped root-owned pinned-dpkg namespace proofs")
        .dependOn(&protected_reference.step);

    const release_test_step = b.step("test-release", "Run deterministic release packaging and audit tests");
    const release_policy_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("test/release-tooling.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_release_policy_tests = b.addRunArtifact(release_policy_tests);
    run_release_policy_tests.setCwd(b.path("."));
    release_test_step.dependOn(&run_release_policy_tests.step);
    const apt_schema_module = b.createModule(.{
        .root_source_file = b.path("test/apt-system-schema-tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    const apt_schema_tests = b.addTest(.{ .root_module = apt_schema_module });
    const run_apt_schema_tests = b.addRunArtifact(apt_schema_tests);
    b.step("test-apt-system-schema", "Validate local apt/system schemas with the Zig validator")
        .dependOn(&run_apt_schema_tests.step);
    release_test_step.dependOn(&run_apt_schema_tests.step);
    workload_release.dependOn(&run_apt_schema_tests.step);
    const install_layout_tests = b.addSystemCommand(&.{ "sh", "tools/test-release-install.sh" });
    install_layout_tests.addArg(b.graph.zig_exe);
    install_layout_tests.addArg(version);
    release_test_step.dependOn(&install_layout_tests.step);

    const solver_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"solver.test."},
    });
    const run_solver_tests = b.addRunArtifact(solver_tests);
    b.step("test-solver", "Run solver adapter tests").dependOn(&run_solver_tests.step);

    const production_backend_test_module = b.createModule(.{
        .root_source_file = b.path("src/production_backend.zig"),
        .target = target,
        .optimize = optimize,
    });
    production_backend_test_module.addOptions("debz_build_options", build_options);
    production_backend_test_module.addIncludePath(libsolv_dependency.path("src"));
    production_backend_test_module.addIncludePath(xz_dependency.path("src/liblzma/api"));
    production_backend_test_module.addIncludePath(zstd_dependency.path("lib"));
    production_backend_test_module.addCMacro("LZMA_API_STATIC", "1");
    production_backend_test_module.linkLibrary(libsolv);
    production_backend_test_module.linkLibrary(liblzma);
    production_backend_test_module.linkLibrary(zstd);
    production_backend_test_module.link_libc = true;
    const production_backend_tests = b.addTest(.{
        .root_module = production_backend_test_module,
        .filters = &.{"production "},
    });
    const run_production_backend_tests = b.addRunArtifact(production_backend_tests);
    const required_production_security_tests = b.addTest(.{
        .root_module = production_backend_test_module,
        .filters = &.{"production workflow required_security."},
    });
    const run_required_production_security_tests = b.addRunArtifact(
        required_production_security_tests,
    );
    const production_backend_test_step = b.step(
        "test-production-backend",
        "Run production backend core, workflow, and exact-lock tests",
    );
    production_backend_test_step.dependOn(&run_production_backend_tests.step);
    production_backend_test_step.dependOn(
        &run_required_production_security_tests.step,
    );
    const package_family_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{ "package_family_backend.test.", "product_api.test." },
    });
    const run_package_family_tests = b.addRunArtifact(package_family_tests);
    production_backend_test_step.dependOn(&run_package_family_tests.step);
    workload_production.dependOn(&run_package_family_tests.step);
    workload_production.dependOn(&run_production_backend_tests.step);

    const system_profile_test_module = b.createModule(.{
        .root_source_file = b.path("src/system_profile.zig"),
        .target = target,
        .optimize = optimize,
    });
    const system_profile_tests = b.addTest(.{
        .root_module = system_profile_test_module,
        .filters = &.{"system_profile.test."},
    });
    const run_system_profile_tests = b.addRunArtifact(system_profile_tests);

    const apt_system_api_test_module = b.createModule(.{
        .root_source_file = b.path("src/apt_system_api.zig"),
        .target = target,
        .optimize = optimize,
    });
    const apt_system_api_tests = b.addTest(.{
        .root_module = apt_system_api_test_module,
        .filters = &.{"apt_system_api.test."},
    });
    const run_apt_system_api_tests = b.addRunArtifact(apt_system_api_tests);

    const apt_system_cli_test_module = b.createModule(.{
        .root_source_file = b.path("src/apt_system_cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    const apt_system_cli_tests = b.addTest(.{
        .root_module = apt_system_cli_test_module,
        .filters = &.{"apt_system_cli.test."},
    });
    const run_apt_system_cli_tests = b.addRunArtifact(apt_system_cli_tests);

    const apt_system_command_test_module = b.createModule(.{
        .root_source_file = b.path("src/apt_system_command.zig"),
        .target = target,
        .optimize = optimize,
    });
    apt_system_command_test_module.addOptions(
        "debz_build_options",
        build_options,
    );
    apt_system_command_test_module.addIncludePath(
        libsolv_dependency.path("src"),
    );
    apt_system_command_test_module.addIncludePath(
        xz_dependency.path("src/liblzma/api"),
    );
    apt_system_command_test_module.addIncludePath(
        zstd_dependency.path("lib"),
    );
    apt_system_command_test_module.addCMacro("LZMA_API_STATIC", "1");
    apt_system_command_test_module.linkLibrary(libsolv);
    apt_system_command_test_module.linkLibrary(liblzma);
    apt_system_command_test_module.linkLibrary(zstd);
    apt_system_command_test_module.link_libc = true;
    const apt_system_command_tests = b.addTest(.{
        .root_module = apt_system_command_test_module,
        .filters = if (require_privileged_orchestration_tests)
            &.{"apt_system_command.test.required_privileged."}
        else
            &.{"apt_system_command.test."},
    });
    const run_apt_system_command_tests = b.addRunArtifact(
        apt_system_command_tests,
    );

    const apt_system_state_test_module = b.createModule(.{
        .root_source_file = b.path("src/apt_system_state.zig"),
        .target = target,
        .optimize = optimize,
    });
    const apt_system_state_tests = b.addTest(.{
        .root_module = apt_system_state_test_module,
        .filters = &.{"apt_system_state.test."},
    });
    const run_apt_system_state_tests = b.addRunArtifact(apt_system_state_tests);

    const apt_system_orchestrator_test_module = b.createModule(.{
        .root_source_file = b.path("src/apt_system_orchestrator.zig"),
        .target = target,
        .optimize = optimize,
    });
    apt_system_orchestrator_test_module.addOptions(
        "debz_build_options",
        build_options,
    );
    apt_system_orchestrator_test_module.addIncludePath(
        libsolv_dependency.path("src"),
    );
    apt_system_orchestrator_test_module.addIncludePath(
        xz_dependency.path("src/liblzma/api"),
    );
    apt_system_orchestrator_test_module.addIncludePath(
        zstd_dependency.path("lib"),
    );
    apt_system_orchestrator_test_module.addCMacro("LZMA_API_STATIC", "1");
    apt_system_orchestrator_test_module.linkLibrary(libsolv);
    apt_system_orchestrator_test_module.linkLibrary(liblzma);
    apt_system_orchestrator_test_module.linkLibrary(zstd);
    apt_system_orchestrator_test_module.link_libc = true;
    const apt_system_orchestrator_tests = b.addTest(.{
        .root_module = apt_system_orchestrator_test_module,
        .filters = if (require_privileged_orchestration_tests)
            &.{"apt_system_orchestrator.test.required_privileged."}
        else
            &.{ "apt_system_orchestrator.test.", "apt_system_lower_ownership_token.test." },
    });
    const run_apt_system_orchestrator_tests = b.addRunArtifact(
        apt_system_orchestrator_tests,
    );
    const required_orchestrator_security_tests = b.addTest(.{
        .root_module = apt_system_orchestrator_test_module,
        .filters = &.{"apt_system_orchestrator.test.required_security."},
    });
    const run_required_orchestrator_security_tests = b.addRunArtifact(
        required_orchestrator_security_tests,
    );

    const apt_system_test_step = b.step(
        "test-apt-system",
        "Run trusted profile, apt/system contract, and orchestration tests",
    );
    apt_system_test_step.dependOn(&run_system_profile_tests.step);
    apt_system_test_step.dependOn(&run_apt_system_api_tests.step);
    apt_system_test_step.dependOn(&run_apt_system_cli_tests.step);
    apt_system_test_step.dependOn(&run_apt_system_command_tests.step);
    apt_system_test_step.dependOn(&run_apt_system_state_tests.step);
    apt_system_test_step.dependOn(&run_apt_system_orchestrator_tests.step);
    workload_apt_system.dependOn(&run_system_profile_tests.step);
    workload_apt_system.dependOn(&run_apt_system_api_tests.step);
    workload_apt_system.dependOn(&run_apt_system_cli_tests.step);
    workload_apt_system.dependOn(&run_apt_system_command_tests.step);
    workload_apt_system.dependOn(&run_apt_system_state_tests.step);
    workload_apt_system.dependOn(&run_apt_system_orchestrator_tests.step);
    const required_security_test_step = b.step(
        "test-required-security",
        "Run mandatory production ownership and restart security tests",
    );
    required_security_test_step.dependOn(
        &run_required_production_security_tests.step,
    );
    required_security_test_step.dependOn(
        &run_required_orchestrator_security_tests.step,
    );
    workload_production.dependOn(&run_required_production_security_tests.step);
    workload_apt_system.dependOn(&run_required_orchestrator_security_tests.step);

    const native_program_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "native_authorization.test.",
            "native_program.test.",
            "native_preparation.test.",
            "installed_baseline_component.test.",
            "transaction_engine.test.",
        },
    });
    const run_native_program_tests = b.addRunArtifact(native_program_tests);
    const native_program_corpus_tests = b.addTest(.{
        .root_module = fuzz_tests.root_module,
        .filters = &.{
            "fuzz.corpus ",
            "fuzz.new native state corpus",
            "fuzz.the mutation progress corpus",
            "fuzz.the mutation journal corpus",
        },
    });
    const run_native_program_corpus_tests = b.addRunArtifact(native_program_corpus_tests);
    const native_program_step = b.step(
        "test-native-program",
        "Run native authorization, program compiler, and canonical corpus tests",
    );
    native_program_step.dependOn(&run_native_program_tests.step);
    native_program_step.dependOn(&run_native_program_corpus_tests.step);
    const native_baseline_tests = b.addTest(.{
        .root_module = production_backend_tests.root_module,
        .filters = &.{
            "production native baseline",
            "production workflow external native fixture",
            "production workflow signed SHA256 archive binding is a per-repository native opt-in",
            "production package family native resolution binds an opted-in signed SHA256 repository",
        },
    });
    b.step("test-native-baseline", "Run genuine signed native installed-baseline workflows in owned roots")
        .dependOn(&b.addRunArtifact(native_baseline_tests).step);
    const product_result_module = b.createModule(.{
        .root_source_file = b.path("src/product_api.zig"),
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });
    product_result_module.addOptions("debz_build_options", build_options);
    product_result_module.addIncludePath(libsolv_dependency.path("src"));
    product_result_module.addIncludePath(xz_dependency.path("src/liblzma/api"));
    product_result_module.addIncludePath(zstd_dependency.path("lib"));
    product_result_module.addCMacro("LZMA_API_STATIC", "1");
    product_result_module.linkLibrary(libsolv);
    product_result_module.linkLibrary(liblzma);
    product_result_module.linkLibrary(zstd);
    const product_result_tests = b.addTest(.{
        .root_module = product_result_module,
        .filters = &.{ "product_api.test.", "canonical result JSON", "command JSON", "facade" },
    });
    b.step("test-product-results", "Run product command result encoding, decoding, and historical byte contracts")
        .dependOn(&b.addRunArtifact(product_result_tests).step);
    workload_native.dependOn(&run_native_program_corpus_tests.step);

    const root_operation_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "live_root.test.",
            "root_operation.test.",
            "root_operation_completion.test.",
            "root_fs.test.",
        },
    });
    const root_mutation_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"root_mutation.test."},
    });
    const run_root_mutation_tests = b.addRunArtifact(root_mutation_tests);
    b.step("test-root-mutation", "Run crash-safe root mutation layer tests")
        .dependOn(&run_root_mutation_tests.step);
    const run_root_operation_tests = b.addRunArtifact(root_operation_tests);
    b.step("test-root-operation", "Run live-root, root operation, and root filesystem tests")
        .dependOn(&run_root_operation_tests.step);
    const live_root_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"live_root.test."},
    });
    const run_live_root_tests = b.addRunArtifact(live_root_tests);
    b.step("test-live-root", "Run private live-root supervisor tests")
        .dependOn(&run_live_root_tests.step);
    const live_root_integration_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "live_root.test.linux integration when namespace capabilities are available",
        },
    });
    const run_live_root_integration_tests = b.addRunArtifact(live_root_integration_tests);
    b.step("test-live-root-integration", "Run the successful live-root namespace integration")
        .dependOn(&run_live_root_integration_tests.step);
    const live_root_shared_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "live_root.test.shared outer run never receives the live-root mount",
        },
    });
    const run_live_root_shared_tests = b.addRunArtifact(live_root_shared_tests);
    b.step("test-live-root-shared", "Run shared-propagation live-root isolation")
        .dependOn(&run_live_root_shared_tests.step);

    const native_unpack_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"native_unpack.test."},
    });
    const run_native_unpack_tests = b.addRunArtifact(native_unpack_tests);
    b.step("test-native-unpack", "Run native unpack and file ownership tests")
        .dependOn(&run_native_unpack_tests.step);

    const native_alternatives_test_module = b.createModule(.{
        .root_source_file = b.path("src/native_alternatives.zig"),
        .target = target,
        .optimize = optimize,
    });
    native_alternatives_test_module.addOptions(
        "debz_build_options",
        build_options,
    );
    native_alternatives_test_module.addIncludePath(
        libsolv_dependency.path("src"),
    );
    native_alternatives_test_module.addIncludePath(
        xz_dependency.path("src/liblzma/api"),
    );
    native_alternatives_test_module.addIncludePath(
        zstd_dependency.path("lib"),
    );
    native_alternatives_test_module.addCMacro("LZMA_API_STATIC", "1");
    native_alternatives_test_module.linkLibrary(libsolv);
    native_alternatives_test_module.linkLibrary(liblzma);
    native_alternatives_test_module.linkLibrary(zstd);
    native_alternatives_test_module.link_libc = true;
    const native_alternatives_tests = b.addTest(.{
        .root_module = native_alternatives_test_module,
        .filters = &.{"native_alternatives.test."},
    });
    const run_native_alternatives_tests = b.addRunArtifact(
        native_alternatives_tests,
    );
    b.step(
        "test-native-alternatives",
        "Run native alternatives parser, selection, and topology tests",
    ).dependOn(&run_native_alternatives_tests.step);
    workload_native.dependOn(&run_native_alternatives_tests.step);
    const native_alternatives_oracle_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path(
                "src/native_alternatives_oracle_test.zig",
            ),
            .target = target,
            .optimize = optimize,
        }),
    });
    native_alternatives_oracle_tests.root_module.addImport("debz", debz);
    const native_alternatives_oracle_options = b.addOptions();
    native_alternatives_oracle_options.addOption(
        []const u8,
        "path",
        b.pathFromRoot(
            "tools/fixtures/vendor-state/dpkg-alternatives-reference-v1.json",
        ),
    );
    native_alternatives_oracle_options.addOption(
        []const u8,
        "vendor_path",
        b.pathFromRoot(
            "tools/fixtures/vendor-state/reference-v1.json",
        ),
    );
    native_alternatives_oracle_tests.root_module.addOptions(
        "native_alternatives_oracle_options",
        native_alternatives_oracle_options,
    );
    const run_native_alternatives_oracle_tests = b.addRunArtifact(
        native_alternatives_oracle_tests,
    );
    b.step(
        "test-native-alternatives-oracle",
        "Replay native alternatives parsing against admitted amd64/arm64 evidence",
    ).dependOn(&run_native_alternatives_oracle_tests.step);
    workload_native.dependOn(&run_native_alternatives_oracle_tests.step);

    const native_materialization_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"native_unpack.test.materialization external fixture"},
    });
    const native_differential_module = b.createModule(.{
        .root_source_file = b.path("test/native_differential.zig"),
        .target = target,
        .optimize = optimize,
    });
    native_differential_module.addImport("debz", debz);
    const native_snapshot_module = b.createModule(.{
        .root_source_file = b.path("test/native_differential_cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    native_snapshot_module.addImport("debz", debz);
    const native_differential_options = b.addOptions();
    native_differential_options.addOption([]const u8, "repository", b.pathFromRoot("."));
    native_differential_options.addOption(
        []const u8,
        "corpus",
        b.pathFromRoot("test/native-transaction/corpus-v1.json"),
    );
    native_differential_module.addOptions("native_test_options", native_differential_options);
    native_snapshot_module.addOptions("native_test_options", native_differential_options);
    const native_snapshot_cli = b.addExecutable(.{
        .name = "native-differential",
        .root_module = native_snapshot_module,
    });
    b.installArtifact(native_snapshot_cli);
    const native_snapshot_tests = b.addTest(.{ .root_module = native_snapshot_module });
    const run_native_snapshot_tests = b.addRunArtifact(native_snapshot_tests);
    native_differential_step.dependOn(&run_native_snapshot_tests.step);
    workload_native.dependOn(&run_native_snapshot_tests.step);
    const native_differential_zig_tests = b.addTest(.{ .root_module = native_differential_module });
    const run_native_differential_zig_tests = b.addRunArtifact(native_differential_zig_tests);
    const native_differential_zig = b.addExecutable(.{
        .name = "native-differential-acceptance",
        .root_module = native_differential_module,
    });
    const run_native_differential_zig = b.addRunArtifact(native_differential_zig);
    run_native_differential_zig.addArtifactArg(native_materialization_tests);
    run_native_differential_zig.step.dependOn(&run_native_differential_zig_tests.step);
    native_differential_step.dependOn(&run_native_differential_zig.step);
    workload_native.dependOn(&run_native_differential_zig_tests.step);
    const native_fixture_module = b.createModule(.{
        .root_source_file = b.path("test/native_materialization.zig"),
        .target = target,
        .optimize = optimize,
    });
    native_fixture_module.addImport("debz", debz);
    const native_fixture_options = b.addOptions();
    native_fixture_options.addOption([]const u8, "repository", b.pathFromRoot("."));
    native_fixture_module.addOptions("native_test_options", native_fixture_options);
    const native_fixture_tests = b.addTest(.{ .root_module = native_fixture_module });
    const run_native_fixture_tests = b.addRunArtifact(native_fixture_tests);
    const native_fixture = b.addExecutable(.{
        .name = "native-materialization-acceptance",
        .root_module = native_fixture_module,
    });
    const run_native_fixture = b.addRunArtifact(native_fixture);
    run_native_fixture.addArtifactArg(native_materialization_tests);
    run_native_fixture.step.dependOn(&run_native_fixture_tests.step);
    workload_native.dependOn(&run_native_fixture_tests.step);
    const native_materialization_step = b.step(
        "test-native-materialization",
        "Compare real native data-only unpack with dpkg",
    );
    native_materialization_step.dependOn(&run_native_fixture.step);

    const native_conffile_module = b.createModule(.{
        .root_source_file = b.path("test/native_conffiles.zig"),
        .target = target,
        .optimize = optimize,
    });
    native_conffile_module.addImport("debz", debz);
    native_conffile_module.addOptions("native_test_options", native_fixture_options);
    const native_conffile_zig_tests = b.addTest(.{ .root_module = native_conffile_module });
    const run_native_conffile_zig_tests = b.addRunArtifact(native_conffile_zig_tests);
    const native_conffile_zig = b.addExecutable(.{
        .name = "native-conffile-acceptance",
        .root_module = native_conffile_module,
    });
    const run_native_conffile_zig = b.addRunArtifact(native_conffile_zig);
    run_native_conffile_zig.addArtifactArg(native_materialization_tests);
    run_native_conffile_zig.step.dependOn(&run_native_conffile_zig_tests.step);
    workload_native.dependOn(&run_native_conffile_zig_tests.step);
    const native_conffile_step = b.step(
        "test-native-conffiles",
        "Compare native conffile and remove/purge phases with dpkg",
    );
    native_conffile_step.dependOn(&run_native_conffile_zig.step);

    const dpkg_config_reference = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",     "PYTHONDONTWRITEBYTECODE=1",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}), "python3", "tools/dpkg-config-reference.py",
    });
    const dpkg_config_reference_tests = b.addSystemCommand(
        &.{ "env", "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "unittest", "tools/test_dpkg_config_reference.py" },
    );
    dpkg_config_reference.step.dependOn(&dpkg_config_reference_tests.step);
    workload_native.dependOn(&dpkg_config_reference_tests.step);
    b.step("test-dpkg-config-reference", "Verify pinned-dpkg config control-member behavior")
        .dependOn(&dpkg_config_reference.step);

    const dpkg_alternatives_reference = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",     "PYTHONDONTWRITEBYTECODE=1",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}), "python3", "tools/dpkg-alternatives-reference.py",
    });
    const dpkg_alternatives_reference_tests = b.addSystemCommand(
        &.{ "env", "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "unittest", "tools/test_dpkg_alternatives_reference.py" },
    );
    dpkg_alternatives_reference.step.dependOn(&dpkg_alternatives_reference_tests.step);
    workload_native.dependOn(&dpkg_alternatives_reference_tests.step);
    b.step(
        "test-dpkg-alternatives-reference",
        "Verify pinned dpkg/update-alternatives records, links, lifecycle and recovery",
    ).dependOn(&dpkg_alternatives_reference.step);
    const dpkg_oracle_evidence_tests = b.addSystemCommand(
        &.{ "env", "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "unittest", "tools/test_dpkg_oracle_evidence.py" },
    );
    workload_native.dependOn(&dpkg_oracle_evidence_tests.step);
    const signed_proc_compare_tests = b.addSystemCommand(
        &.{ "env", "PYTHONDONTWRITEBYTECODE=1", "python3", "-m", "unittest", "tools/test_real_snapshot_signed_proc_compare.py" },
    );
    workload_native.dependOn(&signed_proc_compare_tests.step);

    const native_lifecycle_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "native_unpack.test.lifecycle external fixture",
            "production workflow external native fixture",
            "native_transaction_result.test.projected root external fixture",
            "apt_system_orchestrator.test.projected native dispatch external fixture",
            "repository backend native projected caller external fixture",
            "repository backend native execution external fixture",
        },
    });
    const native_lifecycle_step = b.step("test-native-lifecycle", "Compare native lifecycle scripts and package states with dpkg in Zig");

    const native_trigger_helper = b.addExecutable(.{
        .name = "native-trigger-helper",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/native_trigger_helper.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = target.result.cpu.arch,
                .cpu_model = target.query.cpu_model,
                .cpu_features_add = target.query.cpu_features_add,
                .cpu_features_sub = target.query.cpu_features_sub,
                .os_tag = .linux,
                .abi = .musl,
            }),
            .optimize = optimize,
            // Helper bytes are repeatedly authenticated and retained. Keep
            // Debug safety checks without carrying large debugger metadata.
            .strip = !native_helper_debug_info,
            .link_libc = true,
        }),
        .linkage = .static,
        // Zig's self-hosted x86_64 Debug backend ignores `strip` and leaves
        // layout gaps, emitting a 6 MiB helper instead of 1.4 MiB; every
        // digest authentication of those bytes then costs 4.5x more (#307).
        // LLVM is already the default everywhere else, so other helpers are
        // byte-identical.
        .use_llvm = true,
    });
    b.step("native-trigger-helper", "Build the private trigger helper without installing it")
        .dependOn(&native_trigger_helper.step);
    for ([_]*std.Build.Module{
        debz,
        production_backend_test_module,
        apt_system_command_test_module,
        apt_system_orchestrator_test_module,
    }) |module| module.addAnonymousImport("debz_native_trigger_helper", .{
        .root_source_file = native_trigger_helper.getEmittedBin(),
    });
    const sha512_e2e_module = b.createModule(.{
        .root_source_file = b.path("src/sha512_transaction_e2e_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    sha512_e2e_module.addOptions("debz_build_options", build_options);
    sha512_e2e_module.addIncludePath(libsolv_dependency.path("src"));
    sha512_e2e_module.addIncludePath(xz_dependency.path("src/liblzma/api"));
    sha512_e2e_module.addIncludePath(zstd_dependency.path("lib"));
    sha512_e2e_module.addCMacro("LZMA_API_STATIC", "1");
    sha512_e2e_module.linkLibrary(libsolv);
    sha512_e2e_module.linkLibrary(liblzma);
    sha512_e2e_module.linkLibrary(zstd);
    sha512_e2e_module.link_libc = true;
    sha512_e2e_module.addAnonymousImport("debz_native_trigger_helper", .{
        .root_source_file = native_trigger_helper.getEmittedBin(),
    });
    const sha512_e2e_tests = b.addTest(.{
        .root_module = sha512_e2e_module,
        .filters = &.{
            "sha512_e2e.test.hermetic signed SHA512-only transaction verifies recovery and fail-closed identities",
            "native_provenance_binding.test.",
        },
    });
    const run_sha512_e2e_tests = b.addRunArtifact(sha512_e2e_tests);
    const sha512_legacy_compat_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "exact_lock_v2.test.mixed origins canonical roundtrip and tamper rejection",
            "repository_plan.test.canonical executable plan round trips exactly",
            "native_authorization.test.canonical document binds program artifacts and final closure",
            "native_program.test.fresh install compiles a complete deterministic program",
            "native_execution_request.test.helper wrapper preserves v1 bytes and handles allocation failures",
            "native_provenance.test.legacy v1 canonical bytes remain frozen",
            "native_install_result.test.changed installs bind receipts while unchanged installs do not invent them",
        },
    });
    const run_sha512_legacy_compat_tests = b.addRunArtifact(sha512_legacy_compat_tests);
    const sha512_e2e_step = b.step(
        "test-sha512-e2e",
        "Run the hermetic signed SHA512-only transaction recovery proof",
    );
    sha512_e2e_step.dependOn(&run_sha512_e2e_tests.step);
    sha512_e2e_step.dependOn(&run_sha512_legacy_compat_tests.step);
    workload_native.dependOn(&run_sha512_e2e_tests.step);
    const native_trigger_queue_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/native_trigger.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
        .filters = &.{"native_trigger "},
    });
    const run_native_trigger_queue_tests = b.addRunArtifact(native_trigger_queue_tests);
    b.step("test-native-trigger-helper", "Run private native trigger queue and helper tests")
        .dependOn(&run_native_trigger_queue_tests.step);
    workload_native.dependOn(&run_native_trigger_queue_tests.step);
    const native_triggers_step = b.step("test-native-triggers", "Compare native trigger activation and processing with dpkg in Zig");
    native_triggers_step.dependOn(&run_native_trigger_queue_tests.step);

    const lifecycle_zig_module = b.createModule(.{
        .root_source_file = b.path("test/native_lifecycle_acceptance.zig"),
        .target = target,
        .optimize = optimize,
    });
    lifecycle_zig_module.addImport("debz", debz);
    lifecycle_zig_module.addOptions("native_test_options", native_fixture_options);
    const lifecycle_zig_tests = b.addTest(.{ .root_module = lifecycle_zig_module });
    const run_lifecycle_zig_tests = b.addRunArtifact(lifecycle_zig_tests);
    workload_native.dependOn(&run_lifecycle_zig_tests.step);
    b.step("test-native-lifecycle-zig-unit", "Run unprivileged Zig lifecycle oracle regressions")
        .dependOn(&run_lifecycle_zig_tests.step);
    const lifecycle_zig_executable = b.addExecutable(.{
        .name = "native-lifecycle-zig-acceptance",
        .root_module = lifecycle_zig_module,
    });
    const lifecycle_zig = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    lifecycle_zig.addArtifactArg(lifecycle_zig_executable);
    lifecycle_zig.addArtifactArg(native_lifecycle_tests);
    lifecycle_zig.step.dependOn(&run_lifecycle_zig_tests.step);
    native_lifecycle_step.dependOn(&lifecycle_zig.step);
    b.step("test-native-lifecycle-zig", "Run Zig-owned lifecycle and diversion acceptance against dpkg")
        .dependOn(&lifecycle_zig.step);
    const root_import_module = b.createModule(.{
        .root_source_file = b.path("test/native_root_import.zig"),
        .target = target,
        .optimize = optimize,
    });
    root_import_module.addImport("debz", debz);
    root_import_module.addOptions("native_test_options", native_fixture_options);
    const root_import_tests = b.addTest(.{ .root_module = root_import_module });
    const run_root_import_tests = b.addRunArtifact(root_import_tests);
    const root_import_capture_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "native_unpack.test.live database",
            "native_unpack.test.imported live database",
        },
    });
    const run_root_import_capture_tests = b.addRunArtifact(root_import_capture_tests);
    const root_import_executable = b.addExecutable(.{
        .name = "native-root-import-acceptance",
        .root_module = root_import_module,
    });
    const root_import = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    root_import.addArtifactArg(root_import_executable);
    root_import.addArtifactArg(native_lifecycle_tests);
    root_import.step.dependOn(&run_root_import_tests.step);
    root_import.step.dependOn(&run_root_import_capture_tests.step);
    b.step("test-native-root-import", "Compare healthy pinned-dpkg root import and copied-root refusals")
        .dependOn(&root_import.step);
    const lifecycle_oracle_zig = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    lifecycle_oracle_zig.addArtifactArg(lifecycle_zig_executable);
    lifecycle_oracle_zig.addArg("--oracle-only");
    lifecycle_oracle_zig.step.dependOn(&run_lifecycle_zig_tests.step);
    b.step("test-native-lifecycle-zig-oracle", "Run two guarded dpkg roots for every lifecycle and diversion reference scenario")
        .dependOn(&lifecycle_oracle_zig.step);

    const trigger_zig_module = b.createModule(.{
        .root_source_file = b.path("test/native_trigger_acceptance.zig"),
        .target = target,
        .optimize = optimize,
    });
    trigger_zig_module.addImport("debz", debz);
    trigger_zig_module.addOptions("native_test_options", native_fixture_options);
    const trigger_zig_tests = b.addTest(.{ .root_module = trigger_zig_module });
    const run_trigger_zig_tests = b.addRunArtifact(trigger_zig_tests);
    workload_native.dependOn(&run_trigger_zig_tests.step);
    b.step("test-native-triggers-zig-unit", "Run unprivileged Zig trigger oracle regressions")
        .dependOn(&run_trigger_zig_tests.step);
    const trigger_zig_executable = b.addExecutable(.{
        .name = "native-trigger-zig-acceptance",
        .root_module = trigger_zig_module,
    });
    const trigger_zig = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    trigger_zig.addArtifactArg(trigger_zig_executable);
    trigger_zig.addArtifactArg(native_lifecycle_tests);
    trigger_zig.addArg("--native-helper");
    trigger_zig.addArtifactArg(native_trigger_helper);
    trigger_zig.step.dependOn(&run_trigger_zig_tests.step);
    native_triggers_step.dependOn(&trigger_zig.step);
    b.step("test-native-triggers-zig", "Run Zig-owned trigger and helper acceptance against dpkg")
        .dependOn(&trigger_zig.step);
    const trigger_oracle_zig = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    trigger_oracle_zig.addArtifactArg(trigger_zig_executable);
    trigger_oracle_zig.addArg("--oracle-only");
    trigger_oracle_zig.step.dependOn(&run_trigger_zig_tests.step);
    b.step("test-native-triggers-zig-oracle", "Run trigger and settlement reference scenarios in two guarded dpkg roots")
        .dependOn(&trigger_oracle_zig.step);
    const settlement_oracle_zig = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    settlement_oracle_zig.addArtifactArg(trigger_zig_executable);
    settlement_oracle_zig.addArgs(&.{ "--oracle-only", "--diversion-settlement-reference-only" });
    settlement_oracle_zig.step.dependOn(&run_trigger_zig_tests.step);
    b.step("test-native-triggers-zig-settlement-reference", "Run only 24 upgrades and 16 follow-ups against two pinned dpkg roots")
        .dependOn(&settlement_oracle_zig.step);
    const install_acceptance = b.step("build-native-acceptance-zig", "Install lifecycle/trigger selectors and the focused fixture driver");
    install_acceptance.dependOn(&b.addInstallArtifact(lifecycle_zig_executable, .{}).step);
    install_acceptance.dependOn(&b.addInstallArtifact(native_lifecycle_tests, .{ .dest_sub_path = "native-lifecycle-fixture-driver" }).step);
    install_acceptance.dependOn(&b.addInstallArtifact(trigger_zig_executable, .{}).step);

    const settlement_module = b.createModule(.{
        .root_source_file = b.path("test/native_diversion_settlement.zig"),
        .target = target,
        .optimize = optimize,
    });
    settlement_module.addImport("debz", debz);
    settlement_module.addOptions("native_test_options", native_fixture_options);
    const settlement_tests = b.addTest(.{ .root_module = settlement_module });
    const run_settlement_tests = b.addRunArtifact(settlement_tests);
    const settlement_lowering_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"native_unpack.test.success route settlement lowers every reference profile"},
    });
    const run_settlement_lowering_tests = b.addRunArtifact(settlement_lowering_tests);
    workload_native.dependOn(&run_settlement_tests.step);
    const settlement_unit_step = b.step("test-native-diversion-settlement-zig-unit", "Run Zig settlement oracle mutation and production lowering tests");
    settlement_unit_step.dependOn(&run_settlement_tests.step);
    settlement_unit_step.dependOn(&run_settlement_lowering_tests.step);
    const settlement_executable = b.addExecutable(.{
        .name = "native-diversion-settlement-zig-acceptance",
        .root_module = settlement_module,
    });
    const settlement = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    settlement.addArtifactArg(settlement_executable);
    settlement.addArtifactArg(native_lifecycle_tests);
    settlement.addArg("--native-helper");
    settlement.addArtifactArg(native_trigger_helper);
    settlement.step.dependOn(&run_settlement_tests.step);
    b.step("test-native-diversion-settlement-zig", "Compare 24 Zig settlement upgrades and 16 follow-ups with pinned dpkg")
        .dependOn(&settlement.step);

    const native_recovery_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "native_recovery.test.",                                                      "native_provenance.test.",                                                           "native_execution_request.test.",
            "native_helper.test.",                                                        "native_transaction_result.test.",                                                   "native_install_result.test.",
            "root_operation_completion.test.store publishes atomically and idempotently", "root_operation_completion.test.store refuses a symbolic link at the document path",
        },
    });
    const run_native_recovery_tests = b.addRunArtifact(native_recovery_tests);
    const recovery_unit_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_unit.zig"),
        .target = target,
        .optimize = optimize,
    });
    recovery_unit_module.addImport("debz", debz);
    recovery_unit_module.addOptions("native_test_options", native_fixture_options);
    const recovery_unit_tests = b.addTest(.{ .root_module = recovery_unit_module });
    const run_recovery_unit_tests = b.addRunArtifact(recovery_unit_tests);
    const recovery_unit_step = b.step("test-native-recovery-unit", "Run native execution journal, provenance and Zig oracle tests");
    recovery_unit_step.dependOn(&run_native_recovery_tests.step);
    recovery_unit_step.dependOn(&run_recovery_unit_tests.step);
    b.step("test-native-recovery-zig-unit", "Run unprivileged Zig recovery negative oracles")
        .dependOn(&run_recovery_unit_tests.step);
    workload_native.dependOn(&run_recovery_unit_tests.step);
    workload_native.dependOn(&run_native_recovery_tests.step);
    const native_recovery = b.step("test-native-recovery", "Run the complete Zig recovery unit and pinned-dpkg acceptance workload");
    const native_core_only = b.option(bool, "native-core-recovery-only", "Select core native completion/recovery cases") orelse false;
    const native_deadline_only = b.option(bool, "native-deadline-only", "Select native execution deadline acceptance cases") orelse false;
    const native_parity_only = b.option(bool, "native-consumer-parity-only", "Select family and public core parity across signed fixture suites") orelse false;
    const native_helper_only = b.option(bool, "native-fresh-helper-only", "Select authenticated fresh-root helper bootstrap cases") orelse false;
    const native_diversions_only = b.option(bool, "native-diversions-only", "Select numbered diversion recovery fixtures") orelse false;
    const native_script_failure_only = b.option(bool, "native-script-failure-only", "Select known native postinst failure/restart boundaries") orelse false;
    const repository_projection_only = b.option(bool, "native-repository-projection-only", "Select native repository private-root authority cases") orelse false;
    const repository_execution_only = b.option(bool, "native-repository-execution-only", "Select typed native repository execution and recovery cases") orelse false;
    const repository_cli_only = b.option(bool, "native-repository-cli-only", "Select public supervised native repository CLI cases") orelse false;

    const recovery_zig_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_acceptance.zig"),
        .target = target,
        .optimize = optimize,
    });
    recovery_zig_module.addImport("debz", debz);
    recovery_zig_module.addOptions("native_test_options", native_fixture_options);
    const recovery_zig_executable = b.addExecutable(.{
        .name = "native-recovery-zig-acceptance",
        .root_module = recovery_zig_module,
    });
    const recovery_zig = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    recovery_zig.addArtifactArg(recovery_zig_executable);
    recovery_zig.addArtifactArg(native_lifecycle_tests);
    const zig_core_only = b.option(bool, "native-zig-recovery-core-only", "Select Zig core completion acceptance") orelse false;
    const zig_deadline_only = b.option(bool, "native-zig-recovery-deadline-only", "Select Zig deadline acceptance") orelse false;
    if (native_core_only or zig_core_only) recovery_zig.addArg("--core-only");
    if (native_deadline_only or zig_deadline_only) recovery_zig.addArg("--deadline-only");
    if ((native_core_only or zig_core_only) and (native_deadline_only or zig_deadline_only)) {
        const invalid = b.addFail("core and deadline recovery selectors are mutually exclusive");
        recovery_zig.step.dependOn(&invalid.step);
    }
    b.step("test-native-recovery-zig", "Run Zig-owned real-process core and deadline recovery acceptance")
        .dependOn(&recovery_zig.step);

    const recovery_family_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_family.zig"),
        .target = target,
        .optimize = optimize,
    });
    recovery_family_module.addImport("debz", debz);
    recovery_family_module.addOptions("native_test_options", native_fixture_options);
    const recovery_family_executable = b.addExecutable(.{
        .name = "native-recovery-zig-family",
        .root_module = recovery_family_module,
    });
    const recovery_family = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    recovery_family.addArtifactArg(recovery_family_executable);
    recovery_family.addArtifactArg(native_lifecycle_tests);
    recovery_family.addArg("--self");
    recovery_family.addArtifactArg(recovery_family_executable);
    recovery_family.addArg("--native-helper");
    recovery_family.addArtifactArg(native_trigger_helper);
    recovery_family.addArg("--cli");
    recovery_family.addArtifactArg(cli);
    if (repository_projection_only) recovery_family.addArg("--projection-only");
    if (b.option([]const u8, "native-zig-recovery-family-fixture-python", "Python interpreter for the existing signed-archive fixture builder")) |path|
        recovery_family.addArgs(&.{ "--fixture-python", path });
    const family_executed_only = b.option(bool, "native-zig-recovery-family-executed-only", "Select archive-backed FAMILY execution and active inspection") orelse false;
    if (family_executed_only)
        recovery_family.addArg("--executed-only");
    b.step("test-native-recovery-zig-family", "Run Zig-owned private-root family request/result transport and inspection")
        .dependOn(&recovery_family.step);

    const recovery_parity_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_parity.zig"),
        .target = target,
        .optimize = optimize,
    });
    recovery_parity_module.addImport("debz", debz);
    recovery_parity_module.addOptions("native_test_options", native_fixture_options);
    const recovery_parity_executable = b.addExecutable(.{
        .name = "native-recovery-zig-parity",
        .root_module = recovery_parity_module,
    });
    const recovery_parity = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    recovery_parity.addArtifactArg(recovery_parity_executable);
    recovery_parity.addArtifactArg(native_lifecycle_tests);
    recovery_parity.addArtifactArg(cli);
    recovery_parity.addArtifactArg(native_trigger_helper);
    if (b.option([]const u8, "native-zig-recovery-parity-fixture-python", "Python interpreter for signed-archive fixture generation")) |path|
        recovery_parity.addArgs(&.{ "--fixture-python", path });
    const parity_case = b.option([]const u8, "native-zig-recovery-parity-case", "Run one suite/case for signed consumer parity debugging");
    if (parity_case) |case|
        recovery_parity.addArgs(&.{ "--case", case });
    b.step("test-native-recovery-zig-parity", "Run 30 signed cases and 2 signed FIFO closures through real core, FAMILY, and dpkg consumers")
        .dependOn(&recovery_parity.step);

    const recovery_helper_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_helper.zig"),
        .target = target,
        .optimize = optimize,
    });
    recovery_helper_module.addImport("debz", debz);
    recovery_helper_module.addOptions("native_test_options", native_fixture_options);
    const recovery_helper_executable = b.addExecutable(.{
        .name = "native-recovery-helper-zig-acceptance",
        .root_module = recovery_helper_module,
    });
    const recovery_helper = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    recovery_helper.addArtifactArg(recovery_helper_executable);
    recovery_helper.addArtifactArg(native_lifecycle_tests);
    if (native_script_failure_only or native_core_only) recovery_helper.addArg("--script-failure-only");
    b.step("test-native-recovery-helper-zig", "Run Zig-owned real-process crash and helper acceptance")
        .dependOn(&recovery_helper.step);

    const final_gaps_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_final_gaps.zig"),
        .target = target,
        .optimize = optimize,
    });
    final_gaps_module.addImport("debz", debz);
    final_gaps_module.addOptions("native_test_options", native_fixture_options);
    const final_gaps_executable = b.addExecutable(.{
        .name = "native-recovery-zig-final-gaps",
        .root_module = final_gaps_module,
    });
    const final_gaps = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    final_gaps.addArtifactArg(final_gaps_executable);
    final_gaps.addArtifactArg(native_lifecycle_tests);
    b.step("test-native-recovery-zig-final-gaps", "Exercise bounded rollback/deadline transport guards and real recovery")
        .dependOn(&final_gaps.step);

    const recovery_bootstrap_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_bootstrap.zig"),
        .target = target,
        .optimize = optimize,
    });
    recovery_bootstrap_module.addImport("debz", debz);
    recovery_bootstrap_module.addOptions("native_test_options", native_fixture_options);
    const recovery_bootstrap_executable = b.addExecutable(.{
        .name = "native-recovery-bootstrap-zig-acceptance",
        .root_module = recovery_bootstrap_module,
    });
    const recovery_bootstrap = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    recovery_bootstrap.addArtifactArg(recovery_bootstrap_executable);
    recovery_bootstrap.addArtifactArg(native_lifecycle_tests);
    recovery_bootstrap.addArtifactArg(native_trigger_helper);
    const bootstrap_case = b.option([]const u8, "native-zig-bootstrap-case", "Run one real fresh-helper bootstrap case");
    if (bootstrap_case) |case|
        recovery_bootstrap.addArgs(&.{ "--case", case });
    b.step("test-native-recovery-zig-bootstrap", "Run real fresh-root helper publication and recovery with pinned dpkg")
        .dependOn(&recovery_bootstrap.step);

    const repository_recovery_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_repository.zig"),
        .target = target,
        .optimize = optimize,
    });
    repository_recovery_module.addImport("debz", debz);
    repository_recovery_module.addOptions("native_test_options", native_fixture_options);
    const repository_recovery_unit = b.addTest(.{ .root_module = repository_recovery_module });
    const run_repository_recovery_unit = b.addRunArtifact(repository_recovery_unit);
    const repository_fixture_parent = b.addSystemCommand(&.{ "mkdir", "-p", b.pathFromRoot(".tmp") });
    run_repository_recovery_unit.step.dependOn(&repository_fixture_parent.step);
    const repository_recovery_executable = b.addExecutable(.{
        .name = "native-recovery-zig-repository",
        .root_module = repository_recovery_module,
    });
    const repository_recovery = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    repository_recovery.addArtifactArg(repository_recovery_executable);
    repository_recovery.addArtifactArg(native_lifecycle_tests);
    repository_recovery.addArtifactArg(cli);
    if (b.option([]const u8, "native-repository-fixture-python", "Python with signed-repository fixture generator dependencies")) |python|
        repository_recovery.addArgs(&.{ "--fixture-python", python });
    const repository_case = b.option([]const u8, "native-zig-repository-case", "Run one Zig repository CLI scenario");
    if (repository_case) |case|
        repository_recovery.addArgs(&.{ "--cli-scenario", case });
    if (repository_projection_only) repository_recovery.addArg("--projection-only");
    if (repository_execution_only) repository_recovery.addArg("--execution-only");
    if (repository_cli_only) repository_recovery.addArg("--cli-only");
    repository_recovery.step.dependOn(&repository_fixture_parent.step);
    const repository_recovery_step = b.step("test-native-recovery-zig-repository", "Run Zig-owned private-root repository transport and CLI acceptance");
    repository_recovery_step.dependOn(&run_repository_recovery_unit.step);
    repository_recovery_step.dependOn(&repository_recovery.step);
    workload_native.dependOn(&run_repository_recovery_unit.step);

    const rollback_clock_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_rollback_clock.zig"),
        .target = target,
        .optimize = optimize,
    });
    rollback_clock_module.addImport("debz", debz);
    rollback_clock_module.addOptions("native_test_options", native_fixture_options);
    const rollback_clock_executable = b.addExecutable(.{
        .name = "native-recovery-zig-rollback-clock",
        .root_module = rollback_clock_module,
    });
    const rollback_clock = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    rollback_clock.addArtifactArg(rollback_clock_executable);
    rollback_clock.addArtifactArg(native_lifecycle_tests);
    b.step("test-native-recovery-zig-rollback-clock", "Compare real failed-upgrade rollback clocks with pinned dpkg")
        .dependOn(&rollback_clock.step);

    const scriptless_recovery_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_scriptless.zig"),
        .target = target,
        .optimize = optimize,
    });
    scriptless_recovery_module.addImport("debz", debz);
    scriptless_recovery_module.addOptions("native_test_options", native_fixture_options);
    const scriptless_recovery_executable = b.addExecutable(.{
        .name = "native-recovery-zig-scriptless",
        .root_module = scriptless_recovery_module,
    });
    const scriptless_recovery = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    scriptless_recovery.addArtifactArg(scriptless_recovery_executable);
    scriptless_recovery.addArtifactArg(native_lifecycle_tests);
    b.step("test-native-recovery-zig-scriptless", "Run six real scriptless trigger crash/recovery cases")
        .dependOn(&scriptless_recovery.step);

    const statoverride_recovery_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_statoverride.zig"),
        .target = target,
        .optimize = optimize,
    });
    statoverride_recovery_module.addImport("debz", debz);
    statoverride_recovery_module.addOptions("native_test_options", native_fixture_options);
    const statoverride_recovery_executable = b.addExecutable(.{
        .name = "native-recovery-zig-statoverride",
        .root_module = statoverride_recovery_module,
    });
    const statoverride_recovery = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    statoverride_recovery.addArtifactArg(statoverride_recovery_executable);
    statoverride_recovery.addArtifactArg(native_lifecycle_tests);
    b.step("test-native-recovery-zig-statoverride", "Run 30 real statoverride crash/recovery cases")
        .dependOn(&statoverride_recovery.step);

    const literal_recovery_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_literal.zig"),
        .target = target,
        .optimize = optimize,
    });
    literal_recovery_module.addImport("debz", debz);
    literal_recovery_module.addOptions("native_test_options", native_fixture_options);
    const literal_recovery_executable = b.addExecutable(.{
        .name = "native-recovery-zig-literal",
        .root_module = literal_recovery_module,
    });
    const literal_recovery = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    literal_recovery.addArtifactArg(literal_recovery_executable);
    literal_recovery.addArtifactArg(native_lifecycle_tests);
    b.step("test-native-recovery-zig-literal", "Run five real literal-path crash/recovery cases")
        .dependOn(&literal_recovery.step);

    const metadata_recovery_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_metadata.zig"),
        .target = target,
        .optimize = optimize,
    });
    metadata_recovery_module.addImport("debz", debz);
    metadata_recovery_module.addOptions("native_test_options", native_fixture_options);
    const metadata_recovery_executable = b.addExecutable(.{
        .name = "native-recovery-zig-metadata",
        .root_module = metadata_recovery_module,
    });
    const metadata_recovery = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    metadata_recovery.addArtifactArg(metadata_recovery_executable);
    metadata_recovery.addArtifactArg(native_lifecycle_tests);
    b.step("test-native-recovery-zig-metadata", "Run eleven real retained-metadata crash/recovery cases")
        .dependOn(&metadata_recovery.step);

    const mutation_boundaries_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_mutation_boundaries.zig"),
        .target = target,
        .optimize = optimize,
    });
    mutation_boundaries_module.addImport("debz", debz);
    mutation_boundaries_module.addOptions("native_test_options", native_fixture_options);
    const mutation_boundaries_executable = b.addExecutable(.{
        .name = "native-recovery-zig-mutation-boundaries",
        .root_module = mutation_boundaries_module,
    });
    const mutation_boundaries = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    mutation_boundaries.addArtifactArg(mutation_boundaries_executable);
    mutation_boundaries.addArtifactArg(native_lifecycle_tests);
    const mutation_boundary_case = b.option([]const u8, "native-zig-recovery-mutation-boundary-case", "Run the regular and FIFO cases bound to one named root-mutation crash boundary");
    if (mutation_boundary_case) |boundary|
        mutation_boundaries.addArgs(&.{ "--case", boundary });
    b.step("test-native-recovery-zig-mutation-boundaries", "Run thirteen real native root-mutation journal/staging crash boundaries and 18 FIFO publication kills")
        .dependOn(&mutation_boundaries.step);

    const publication_recovery_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_publication.zig"),
        .target = target,
        .optimize = optimize,
    });
    publication_recovery_module.addImport("debz", debz);
    publication_recovery_module.addOptions("native_test_options", native_fixture_options);
    const publication_recovery_executable = b.addExecutable(.{
        .name = "native-recovery-zig-publication",
        .root_module = publication_recovery_module,
    });
    const publication_recovery = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    publication_recovery.addArtifactArg(publication_recovery_executable);
    publication_recovery.addArtifactArg(native_lifecycle_tests);
    b.step("test-native-recovery-zig-publication", "Run 14 named mutation syscall crashes, rollback release and three refusals")
        .dependOn(&publication_recovery.step);

    const conffile_recovery_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_conffile.zig"),
        .target = target,
        .optimize = optimize,
    });
    conffile_recovery_module.addImport("debz", debz);
    conffile_recovery_module.addOptions("native_test_options", native_fixture_options);
    const conffile_recovery_executable = b.addExecutable(.{
        .name = "native-recovery-zig-conffile",
        .root_module = conffile_recovery_module,
    });
    const conffile_recovery = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    conffile_recovery.addArtifactArg(conffile_recovery_executable);
    conffile_recovery.addArtifactArg(native_lifecycle_tests);
    b.step("test-native-recovery-zig-conffile", "Run twenty real conffile lifecycle crash/recovery cases")
        .dependOn(&conffile_recovery.step);

    const recovery_diversions_module = b.createModule(.{
        .root_source_file = b.path("test/native_recovery_diversions.zig"),
        .target = target,
        .optimize = optimize,
    });
    recovery_diversions_module.addImport("debz", debz);
    recovery_diversions_module.addOptions("native_test_options", native_fixture_options);
    const recovery_diversions_executable = b.addExecutable(.{
        .name = "native-recovery-zig-diversions",
        .root_module = recovery_diversions_module,
    });
    const recovery_diversions = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    recovery_diversions.addArtifactArg(recovery_diversions_executable);
    recovery_diversions.addArtifactArg(native_lifecycle_tests);
    const diversion_case = b.option([]const u8, "native-zig-recovery-diversion-case", "Run one numbered Python diversion recovery case");
    if (diversion_case) |number|
        recovery_diversions.addArgs(&.{ "--case", number });
    const route_case = b.option([]const u8, "native-zig-recovery-diversion-route-case", "Run one named diversion postrm crash transition and its drift controls");
    if (route_case) |name|
        recovery_diversions.addArgs(&.{ "--route-case", name });
    const diversion_shard = b.option([]const u8, "native-zig-recovery-diversion-shard", "Run one of four complete numbered diversion shards; shard 4 also runs both named routes");
    if (diversion_shard) |shard|
        recovery_diversions.addArgs(&.{ "--shard", shard });
    b.step("test-native-recovery-zig-diversions", "Run counted real-process diversion crash/recovery cases against pinned dpkg")
        .dependOn(&recovery_diversions.step);

    if (native_diversions_only) {
        for ([_]*std.Build.Step.Run{ lifecycle_zig, trigger_zig, lifecycle_oracle_zig, trigger_oracle_zig }) |runner|
            runner.addArg("--diversions-only");
    }
    if (b.option(bool, "native-statoverrides-only", "Select genuine-tool and metadata statoverride lifecycle oracles") orelse false) {
        for ([_]*std.Build.Step.Run{ lifecycle_zig, lifecycle_oracle_zig }) |runner|
            runner.addArg("--statoverrides-only");
    }
    const selectors = [_]bool{
        native_core_only,           native_deadline_only,      native_script_failure_only,
        repository_projection_only, repository_execution_only, repository_cli_only,
        native_parity_only,         native_helper_only,        native_diversions_only,
    };
    var selected: usize = 0;
    for (selectors) |enabled| {
        if (enabled) selected += 1;
    }
    const focused = zig_core_only or zig_deadline_only or family_executed_only or
        parity_case != null or bootstrap_case != null or repository_case != null or
        diversion_case != null or route_case != null or diversion_shard != null or mutation_boundary_case != null;
    if (selected > 1 or focused) {
        const invalid = b.addFail(if (selected > 1)
            "native recovery workload selectors are mutually exclusive"
        else
            "focused Zig case options cannot narrow the complete test-native-recovery gate; use a focused Zig target");
        native_recovery.dependOn(&invalid.step);
    } else {
        native_recovery.dependOn(&run_native_recovery_tests.step);
        native_recovery.dependOn(&run_recovery_unit_tests.step);
        native_recovery.dependOn(&run_repository_recovery_unit.step);
        if (native_deadline_only) {
            native_recovery.dependOn(&recovery_zig.step);
        } else if (native_script_failure_only) {
            native_recovery.dependOn(&recovery_helper.step);
        } else if (native_helper_only) {
            native_recovery.dependOn(&recovery_bootstrap.step);
        } else if (native_diversions_only) {
            native_recovery.dependOn(&recovery_diversions.step);
        } else if (repository_projection_only) {
            native_recovery.dependOn(&recovery_family.step);
            native_recovery.dependOn(&repository_recovery.step);
        } else if (repository_execution_only or repository_cli_only) {
            native_recovery.dependOn(&repository_recovery.step);
        } else if (native_parity_only) {
            for ([_]*std.Build.Step.Run{
                recovery_parity,   recovery_diversions, statoverride_recovery, conffile_recovery,
                metadata_recovery, literal_recovery,    scriptless_recovery,   publication_recovery,
            }) |runner| native_recovery.dependOn(&runner.step);
        } else if (native_core_only) {
            for ([_]*std.Build.Step.Run{
                recovery_zig,        recovery_helper,       recovery_bootstrap,   recovery_family,
                recovery_diversions, statoverride_recovery, conffile_recovery,    metadata_recovery,
                literal_recovery,    mutation_boundaries,   publication_recovery,
            }) |runner| native_recovery.dependOn(&runner.step);
        } else {
            for ([_]*std.Build.Step.Run{
                recovery_zig,         recovery_family,     recovery_parity,   recovery_helper,     final_gaps,
                recovery_bootstrap,   repository_recovery, rollback_clock,    scriptless_recovery, statoverride_recovery,
                literal_recovery,     metadata_recovery,   conffile_recovery, recovery_diversions, mutation_boundaries,
                publication_recovery,
            }) |runner| native_recovery.dependOn(&runner.step);
        }
    }
    if (b.option([]const u8, "native-reference-dpkg", "Absolute path to the pinned private dpkg fixture reference")) |path| {
        root_import.addArgs(&.{ "--reference-dpkg", path });
        run_native_fixture.addArgs(&.{ "--reference-dpkg", path });
        run_native_conffile_zig.addArgs(&.{ "--reference-dpkg", path });
        run_native_differential_zig.addArgs(&.{ "--reference-dpkg", path });
        for ([_]*std.Build.Step.Run{ dpkg_config_reference, dpkg_alternatives_reference }) |runner|
            runner.addArgs(&.{ "--reference-dpkg", path });
        for ([_]*std.Build.Step.Run{ lifecycle_zig, trigger_zig, settlement, lifecycle_oracle_zig, trigger_oracle_zig, settlement_oracle_zig }) |runner|
            runner.addArgs(&.{ "--reference-dpkg", path });
        for ([_]*std.Build.Step.Run{
            recovery_zig,         recovery_family,     recovery_parity,   recovery_helper,     final_gaps,
            recovery_bootstrap,   repository_recovery, rollback_clock,    scriptless_recovery, statoverride_recovery,
            literal_recovery,     metadata_recovery,   conffile_recovery, recovery_diversions, mutation_boundaries,
            publication_recovery,
        }) |runner| runner.addArgs(&.{ "--reference-dpkg", path });
    }
    if (b.option(
        []const u8,
        "native-reference-architecture",
        "Explicit architecture for pinned dpkg reference oracles",
    )) |architecture| {
        for ([_]*std.Build.Step.Run{
            dpkg_config_reference, dpkg_alternatives_reference,
        }) |runner| runner.addArgs(&.{ "--architecture", architecture });
    }
    if (b.option(
        []const u8,
        "native-reference-update-alternatives",
        "Absolute path to the pinned private update-alternatives fixture reference",
    )) |path| {
        dpkg_alternatives_reference.addArgs(
            &.{ "--reference-update-alternatives", path },
        );
    }

    const package_database_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "package_path.test.",
            "package_database.test.",
            "package_database_changes.test.",
        },
    });
    const run_package_database_tests = b.addRunArtifact(package_database_tests);
    b.step("test-package-database", "Run native package database model and change-set tests")
        .dependOn(&run_package_database_tests.step);

    const refresh_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"repository_refresh.test."},
    });
    const run_refresh_tests = b.addRunArtifact(refresh_tests);
    b.step("test-refresh", "Run repository refresh tests").dependOn(&run_refresh_tests.step);

    const acquisition_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"repository_acquisition.test."},
    });
    const run_acquisition_tests = b.addRunArtifact(acquisition_tests);
    b.step("test-repository-acquisition", "Run repository byte acquisition tests")
        .dependOn(&run_acquisition_tests.step);

    const package_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"package_acquisition.test."},
    });
    const run_package_tests = b.addRunArtifact(package_tests);
    b.step("test-package-acquisition", "Run verified package acquisition tests")
        .dependOn(&run_package_tests.step);

    const package_cache_test_module = b.createModule(.{
        .root_source_file = b.path("src/package_cache_workflow.zig"),
        .target = target,
        .optimize = optimize,
    });
    package_cache_test_module.addIncludePath(libsolv_dependency.path("src"));
    package_cache_test_module.addIncludePath(xz_dependency.path("src/liblzma/api"));
    package_cache_test_module.addIncludePath(zstd_dependency.path("lib"));
    package_cache_test_module.addCMacro("LZMA_API_STATIC", "1");
    package_cache_test_module.linkLibrary(libsolv);
    package_cache_test_module.linkLibrary(liblzma);
    package_cache_test_module.linkLibrary(zstd);
    package_cache_test_module.link_libc = true;
    const package_cache_tests = b.addTest(.{
        .root_module = package_cache_test_module,
        .filters = &.{"package_cache_workflow.test."},
    });
    const run_package_cache_tests = b.addRunArtifact(package_cache_tests);
    const package_cache_archive_test_module = b.createModule(.{
        .root_source_file = b.path("src/package_cache_archive.zig"),
        .target = target,
        .optimize = optimize,
    });
    package_cache_archive_test_module.addIncludePath(libsolv_dependency.path("src"));
    package_cache_archive_test_module.addIncludePath(xz_dependency.path("src/liblzma/api"));
    package_cache_archive_test_module.addIncludePath(zstd_dependency.path("lib"));
    package_cache_archive_test_module.addCMacro("LZMA_API_STATIC", "1");
    package_cache_archive_test_module.linkLibrary(libsolv);
    package_cache_archive_test_module.linkLibrary(liblzma);
    package_cache_archive_test_module.linkLibrary(zstd);
    package_cache_archive_test_module.link_libc = true;
    const package_cache_archive_tests = b.addTest(.{
        .root_module = package_cache_archive_test_module,
        .filters = &.{"package_cache_archive.test."},
    });
    const run_package_cache_archive_tests = b.addRunArtifact(package_cache_archive_tests);
    const package_cache_test_step = b.step(
        "test-package-cache",
        "Run exact-lock package cache workflow and archive tests",
    );
    package_cache_test_step.dependOn(&run_package_cache_tests.step);
    package_cache_test_step.dependOn(&run_package_cache_archive_tests.step);
    workload_native.dependOn(&run_package_cache_archive_tests.step);

    const policy_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"repository_policy.test."},
    });
    const run_policy_tests = b.addRunArtifact(policy_tests);
    b.step("test-repository-policy", "Run multi-repository policy tests")
        .dependOn(&run_policy_tests.step);

    const target_apt_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{ "target_apt_config.test.", "system_product_context.test." },
    });
    const run_target_apt_tests = b.addRunArtifact(target_apt_tests);
    b.step("test-target-apt-config", "Run target-root APT configuration import tests")
        .dependOn(&run_target_apt_tests.step);

    const transaction_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"transaction_executor.test."},
    });
    const run_transaction_tests = b.addRunArtifact(transaction_tests);
    b.step("test-transaction-executor", "Run dpkg transaction executor tests")
        .dependOn(&run_transaction_tests.step);

    const maintainer_script_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"maintainer_script.test."},
    });
    const run_maintainer_script_tests = b.addRunArtifact(maintainer_script_tests);
    b.step("test-maintainer-script", "Run audited maintainer-script runner tests")
        .dependOn(&run_maintainer_script_tests.step);
    const native_helper_namespace_tests = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env", "DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE=1",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
    });
    native_helper_namespace_tests.addArtifactArg(maintainer_script_tests);
    b.step("test-native-helper-namespace", "Require private helper mounts without changing package-owned files")
        .dependOn(&native_helper_namespace_tests.step);

    const signed_proc_step = b.step(
        "test-native-signed-proc",
        "Require real signed systemd, udev, and sudo replay in separately supplied protected amd64 roots",
    );
    const systemd_root = b.option([]const u8, "signed-systemd-proc-root", "Fresh protected pre-systemd root");
    const udev_root = b.option([]const u8, "signed-udev-proc-root", "Fresh protected pre-udev root");
    const sudo_root = b.option([]const u8, "signed-sudo-proc-root", "Fresh protected pre-sudo root");
    if (systemd_root != null and udev_root != null and sudo_root != null) {
        const roots = [_][]const u8{ systemd_root.?, udev_root.?, sudo_root.? };
        if (@import("builtin").cpu.arch != .x86_64 or target.result.cpu.arch != .x86_64) {
            signed_proc_step.dependOn(&b.addFail(
                "the existing exact signed systemd/udev/sudo proc profiles are amd64-only; do not run them as arm64 scripts",
            ).step);
        } else if (!std.fs.path.isAbsolute(roots[0]) or
            !std.fs.path.isAbsolute(roots[1]) or
            !std.fs.path.isAbsolute(roots[2]) or
            std.mem.eql(u8, roots[0], roots[1]) or
            std.mem.eql(u8, roots[0], roots[2]) or
            std.mem.eql(u8, roots[1], roots[2]))
        {
            signed_proc_step.dependOn(&b.addFail(
                "signed proc replay requires three distinct absolute disposable root paths",
            ).step);
        } else {
            const signed_proc_tests = b.addTest(.{
                .root_module = debz,
                .filters = &.{
                    "maintainer_script.test.signed systemd postinst uses scoped masked proc",
                    "maintainer_script.test.signed udev postinst uses only PID proc",
                    "maintainer_script.test.signed sudo postinst repairs only pinned alternatives",
                },
            });
            const signed_proc_run = b.addSystemCommand(&.{
                "sudo",
                "-n",
                "env",
                "DEBZ_REQUIRE_NATIVE_HELPER_NAMESPACE=1",
                "DEBZ_REQUIRE_SIGNED_PROC_ROOTS=1",
                b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}),
                b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}),
                b.fmt("DEBZ_REQUIRE_SIGNED_SYSTEMD_PROC_ROOT={s}", .{roots[0]}),
                b.fmt("DEBZ_REQUIRE_SIGNED_UDEV_PROC_ROOT={s}", .{roots[1]}),
                b.fmt("DEBZ_REQUIRE_SIGNED_SUDO_PROC_ROOT={s}", .{roots[2]}),
            });
            signed_proc_run.addArtifactArg(signed_proc_tests);
            signed_proc_step.dependOn(&signed_proc_run.step);
        }
    } else {
        signed_proc_step.dependOn(&b.addFail(
            "signed proc replay requires -Dsigned-systemd-proc-root, -Dsigned-udev-proc-root, and -Dsigned-sudo-proc-root",
        ).step);
    }

    const archive_application_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"archive_application.test."},
    });
    const run_archive_application_tests = b.addRunArtifact(archive_application_tests);
    b.step("test-archive-application", "Run native archive application model tests")
        .dependOn(&run_archive_application_tests.step);

    const lock_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{ "exact_lock.test.", "exact_lock_v2.test.", "exact_lock_v3.test." },
    });
    const run_lock_tests = b.addRunArtifact(lock_tests);
    b.step("test-exact-lock", "Run exact solved-closure lock tests")
        .dependOn(&run_lock_tests.step);

    const provenance_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{ "transaction_provenance.test.", "transaction_provenance_v2.test." },
    });
    const run_provenance_tests = b.addRunArtifact(provenance_tests);
    b.step("test-transaction-provenance", "Run transaction provenance tests")
        .dependOn(&run_provenance_tests.step);

    const legacy_compat_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "legacy_compat.test.",
            "system_profile.test.legacy compatibility",
            "transaction_recovery.test.legacy compatibility",
            "root_operation.test.legacy compatibility",
            "production legacy compatibility",
            "repository_backend.test.legacy compatibility",
        },
    });
    const run_legacy_compat_tests = b.addRunArtifact(legacy_compat_tests);
    b.step(
        "test-legacy-compat",
        "Run legacy artifact, profile, journal, and active-operation policy tests",
    ).dependOn(&run_legacy_compat_tests.step);

    const native_only_rehearsal = b.step(
        "test-native-only-rehearsal",
        "Rehearse opt-in CLI selection and pre-mutation root refusal without changing release defaults",
    );
    const rehearsal_backend_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "root_operation.test.native-only rehearsal",
            "production native-only rehearsal",
            "repository backend native-only rehearsal",
            "legacy_compat.test.active legacy evidence requires",
            "legacy_compat.test.capability evidence binds",
            "transaction result summary binds successful canonical evidence",
        },
    });
    native_only_rehearsal.dependOn(&b.addRunArtifact(rehearsal_backend_tests).step);
    const rehearsal_cli_tests = b.addTest(.{
        .root_module = repository_cli,
        .filters = &.{
            "cli_backend_policy.test.",
            "repo add parser rehearses native-only",
        },
    });
    native_only_rehearsal.dependOn(&b.addRunArtifact(rehearsal_cli_tests).step);
    const rehearsal_options = b.addOptions();
    rehearsal_options.addOption(bool, "native_only", true);
    const rehearsal_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    rehearsal_module.addImport("debz", debz);
    rehearsal_module.addImport("repository_cli", repository_cli);
    rehearsal_module.addImport("cli_backend_policy", cli_backend_policy);
    rehearsal_module.addOptions("cli_rehearsal_options", rehearsal_options);
    const rehearsal_cli = b.addExecutable(.{
        .name = "debz-native-only-rehearsal",
        .root_module = rehearsal_module,
    });
    const rehearsal_cli_cases = b.addSystemCommand(&.{
        "sh", "tools/test-native-only-rehearsal.sh",
    });
    rehearsal_cli_cases.addArtifactArg(rehearsal_cli);
    native_only_rehearsal.dependOn(&rehearsal_cli_cases.step);
    workload_release.dependOn(native_only_rehearsal);

    const production_customize_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/production_backend_customize_test.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    production_customize_tests.root_module.addImport("debz", debz);
    const run_production_customize_tests = b.addRunArtifact(production_customize_tests);
    b.step(
        "test-production-customize",
        "Run production customize lock-root and diagnostics regression tests",
    ).dependOn(&run_production_customize_tests.step);
    workload_production.dependOn(&run_production_customize_tests.step);

    const version_oracle = b.addExecutable(.{
        .name = "version-oracle",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/version_oracle.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    version_oracle.root_module.addImport("debz", debz);

    const dpkg_oracle = b.addSystemCommand(&.{ "sh", "tools/test-version-dpkg.sh" });
    dpkg_oracle.addArtifactArg(version_oracle);
    b.step("test-dpkg", "Compare version ordering with dpkg when available")
        .dependOn(&dpkg_oracle.step);
}

fn addHelpFlagTests(
    b: *std.Build,
    step: *std.Build.Step,
    cli: *std.Build.Step.Compile,
    args: []const []const u8,
    usage: []const u8,
) void {
    for ([_][]const u8{ "-h", "--help" }) |flag| {
        const help = b.addRunArtifact(cli);
        help.addArgs(args);
        help.addArg(flag);
        help.expectExitCode(0);
        help.expectStdOutMatch(usage);
        help.expectStdErrEqual("");
        step.dependOn(&help.step);
    }
}

fn installReleaseFiles(
    b: *std.Build,
    install_cli: *std.Build.Step.InstallArtifact,
    release_install: *std.Build.Step,
    target: std.Build.ResolvedTarget,
) void {
    const docs = [_][]const u8{
        "README.md",
        "apt-system-facade.md",
        "archive-application-model.md",
        "authenticated-refresh.md",
        "deb-payload-validation.md",
        "dpkg-alternatives-reference.md",
        "debian-stable-readiness.md",
        "exact-locks-and-provenance.md",
        "github-actions.md",
        "integration-roots.md",
        "legacy-compatibility.md",
        "maintainer-script-runner.md",
        "multi-repository-policy.md",
        "native-conffiles.md",
        "native-lifecycle.md",
        "native-recovery.md",
        "native-transaction-engine-v1.md",
        "native-transaction-program.md",
        "native-triggers.md",
        "native-unpack.md",
        "openpgp-verifier.md",
        "package-acquisition.md",
        "package-database.md",
        "product-api.md",
        "project-status.md",
        "real-snapshot-stable-series.md",
        "real-snapshot-repin.md",
        "repository-management.md",
        "release-installation.md",
        "release-tooling.md",
        "releasing.md",
        "root-filesystem.md",
        "root-mutation.md",
        "root-operation.md",
        "safety-ci.md",
        "solver-planning.md",
        "threat-model.md",
        "transaction-executor.md",
        "transaction-recovery.md",
        "target-apt-config.md",
        "tooling-test-inventory.md",
        "zvmi-package-family.md",
    };
    const schemas = [_][]const u8{
        "active-repository-config-v1.json",
        "apt-config-snapshot-v1.json",
        "apt-config-snapshot-v2.json",
        "apt-system-cli-diagnostic-v1.json",
        "apt-system-execution-completion-v1.json",
        "apt-system-operation-state-v1.json",
        "apt-system-request-v1.json",
        "apt-system-result-v1.json",
        "apt-system-result-v2.json",
        "apt-system-result-v3.json",
        "command-result-v1.json",
        "command-result-v2.json",
        "native-baseline-download-v1.json",
        "exact-closure-lock-v1.json",
        "exact-closure-lock-v2.json",
        "exact-closure-lock-v3.json",
        "exact-closure-lock-v4.json",
        "installed-baseline-component-v1.json",
        "legacy-capability-evidence-v1.json",
        "legacy-compatibility-policy-v1.json",
        "native-execution-intent-v1.json",
        "native-execution-intent-v2.json",
        "native-execution-progress-v1.json",
        "native-execution-progress-v2.json",
        "native-execution-progress-v3.json",
        "native-execution-progress-v4.json",
        "native-execution-request-v1.json",
        "native-execution-request-v2.json",
        "native-execution-request-v3.json",
        "native-execution-request-v4.json",
        "native-installed-baseline-noop-v1.json",
        "native-managed-state-v1.json",
        "native-repository-unchanged-v1.json",
        "native-diversion-cache-v1.json",
        "native-unpack-diversion-v1.json",
        "native-unpack-route-settlement-v1.json",
        "native-script-outcome-v1.json",
        "native-transaction-authorization-v1.json",
        "native-transaction-authorization-v2.json",
        "native-transaction-authorization-v3.json",
        "native-transaction-program-v1.json",
        "native-transaction-program-v2.json",
        "native-transaction-program-v3.json",
        "native-transaction-provenance-v1.json",
        "native-transaction-provenance-v2.json",
        "native-trigger-events-v1.json",
        "package-cache-error-v1.json",
        "package-cache-fingerprint-v1.json",
        "package-cache-fingerprint-v2.json",
        "package-cache-fingerprint-v3.json",
        "package-cache-fingerprint-v4.json",
        "package-cache-fingerprint-v5.json",
        "package-cache-fingerprint-v6.json",
        "package-cache-result-v1.json",
        "package-cache-result-v2.json",
        "package-cache-result-v3.json",
        "package-cache-result-v4.json",
        "package-cache-result-v5.json",
        "package-cache-result-v6.json",
        "repository-add-state-v1.json",
        "repository-operation-result-v1.json",
        "root-operation-completion-v1.json",
        "root-operation-completion-v2.json",
        "root-operation-record-v1.json",
        "root-mutation-journal-v1.json",
        "system-profile-v1.json",
        "system-profile-v2.json",
        "transaction-plan-v1.json",
        "transaction-plan-v2.json",
        "transaction-plan-v3.json",
        "transaction-plan-v4.json",
        "transaction-result-v1.json",
        "transaction-result-v2.json",
        "transaction-result-v3.json",
        "transaction-result-summary-v1.json",
        "transaction-result-summary-v2.json",
        "transaction-result-capability-v1.json",
        "native-install-capability-v1.json",
        "native-install-result-v1.json",
        "dpkg-alternatives-reference-v1.json",
        "dpkg-config-reference-v1.json",
        "dpkg-oracle-execution-evidence-v1.json",
        "native-dpkg-reference-receipt-v1.json",
        "vendor-state-inventory-v1.json",
        "vendor-state-reference-v1.json",
    };
    const regular_files = [_]struct { source: []const u8, destination: []const u8 }{
        .{ .source = "README.md", .destination = "share/doc/debz/README.md" },
        .{ .source = "LICENSE", .destination = "share/doc/debz/LICENSE" },
        .{ .source = "THIRD_PARTY_NOTICES", .destination = "share/doc/debz/THIRD_PARTY_NOTICES" },
        .{ .source = "security/digest-cutover-policy.json", .destination = "share/debz/digest-cutover-policy.json" },
        .{ .source = "security/digest-cutover-policy.json", .destination = "share/doc/debz/digest-cutover-policy.json" },
        .{ .source = "security/digest-inventory-v1.tsv", .destination = "share/debz/digest-inventory-v1.tsv" },
        .{ .source = "security/digest-inventory-v1.tsv", .destination = "share/doc/debz/digest-inventory-v1.tsv" },
        .{ .source = "security/digest-semantic-allowlist-v1.tsv", .destination = "share/debz/digest-semantic-allowlist-v1.tsv" },
        .{ .source = "security/digest-semantic-allowlist-v1.tsv", .destination = "share/doc/debz/digest-semantic-allowlist-v1.tsv" },
        .{ .source = "security/legacy-cutover-policy.json", .destination = "share/debz/legacy-cutover-policy.json" },
        .{ .source = "security/legacy-cutover-policy.json", .destination = "share/doc/debz/legacy-cutover-policy.json" },
    };

    const regular_modes = b.addSystemCommand(&.{ "chmod", "0644" });
    for (regular_files) |file| {
        const install = b.addInstallFile(b.path(file.source), file.destination);
        b.getInstallStep().dependOn(&install.step);
        regular_modes.step.dependOn(&install.step);
        regular_modes.addArg(b.getInstallPath(.prefix, file.destination));
    }
    for (docs) |name| {
        const destination = b.fmt("share/doc/debz/doc/{s}", .{name});
        const install = b.addInstallFile(b.path(b.fmt("doc/{s}", .{name})), destination);
        b.getInstallStep().dependOn(&install.step);
        regular_modes.step.dependOn(&install.step);
        regular_modes.addArg(b.getInstallPath(.prefix, destination));
    }
    for (schemas) |name| {
        const source = b.path(b.fmt("schema/{s}", .{name}));
        for ([_][]const u8{ "share/debz/schema", "share/doc/debz/schema" }) |directory| {
            const destination = b.fmt("{s}/{s}", .{ directory, name });
            const install = b.addInstallFile(source, destination);
            b.getInstallStep().dependOn(&install.step);
            regular_modes.step.dependOn(&install.step);
            regular_modes.addArg(b.getInstallPath(.prefix, destination));
        }
    }
    b.getInstallStep().dependOn(&regular_modes.step);

    const executable_mode = b.addSystemCommand(&.{ "chmod", "0755" });
    executable_mode.step.dependOn(&install_cli.step);
    executable_mode.addArg(b.getInstallPath(.bin, "debz"));
    b.getInstallStep().dependOn(&executable_mode.step);

    const runtime_metadata = b.addInstallFile(
        b.path("security/runtime-dependencies.json"),
        "share/debz/runtime-dependencies.json",
    );
    if (target.result.os.tag != .linux or target.result.abi != .musl) {
        const unsupported_target = b.addFail(
            "release-install requires a Linux musl target; use ordinary install for other targets",
        );
        runtime_metadata.step.dependOn(&unsupported_target.step);
    }
    const runtime_metadata_mode = b.addSystemCommand(&.{ "chmod", "0644" });
    runtime_metadata_mode.step.dependOn(&runtime_metadata.step);
    runtime_metadata_mode.addArg(b.getInstallPath(.prefix, "share/debz/runtime-dependencies.json"));
    release_install.dependOn(&runtime_metadata_mode.step);
}
