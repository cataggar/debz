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

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);

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

    const repository_cli = b.createModule(.{
        .root_source_file = b.path("src/repository_cli.zig"),
        .target = target,
        .optimize = optimize,
    });
    repository_cli.addImport("debz", debz);

    const cli_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_module.addImport("debz", debz);
    cli_module.addImport("repository_cli", repository_cli);

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
    test_step.dependOn(&run_tests.step);

    const repository_cli_tests = b.addTest(.{ .root_module = repository_cli });
    const run_repository_cli_tests = b.addRunArtifact(repository_cli_tests);
    test_step.dependOn(&run_repository_cli_tests.step);

    const cli_tests = b.addSystemCommand(&.{ "sh", "tools/test-cli.sh" });
    cli_tests.addArtifactArg(cli);
    cli_tests.addArg(version);
    test_step.dependOn(&cli_tests.step);

    const help_cases = [_]struct {
        args: []const []const u8,
        usage: []const u8,
    }{
        .{ .args = &.{}, .usage = "debz <command> [options] [packages...]" },
        .{ .args = &.{"repo"}, .usage = "debz repo <command> [options]" },
        .{ .args = &.{ "repo", "add" }, .usage = "debz repo add --url URL [options]" },
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
    };
    for (help_cases) |case| {
        addHelpFlagTests(b, test_step, cli, case.args, case.usage);
    }

    const no_args_help = b.addRunArtifact(cli);
    no_args_help.expectExitCode(0);
    no_args_help.expectStdOutMatch("debz <command> [options] [packages...]");
    no_args_help.expectStdErrEqual("");
    test_step.dependOn(&no_args_help.step);

    const positional_help = b.addRunArtifact(cli);
    positional_help.addArg("help");
    positional_help.expectExitCode(2);
    positional_help.expectStdOutEqual("");
    positional_help.expectStdErrMatch("debz: unknown command 'help'");
    test_step.dependOn(&positional_help.step);

    const removed_version_flag = b.addRunArtifact(cli);
    removed_version_flag.addArg("--version");
    removed_version_flag.expectExitCode(2);
    removed_version_flag.expectStdOutEqual("");
    removed_version_flag.expectStdErrMatch("debz: unknown command '--version'");
    test_step.dependOn(&removed_version_flag.step);

    const consumer_tests = b.addSystemCommand(&.{
        b.graph.zig_exe,
        "build",
        "--cache-dir",
        "../../.zig-cache/public-consumer",
    });
    consumer_tests.setCwd(b.path("test/consumer"));
    test_step.dependOn(&consumer_tests.step);

    const integration_tests = b.addSystemCommand(&.{ "sh", "tools/test-integration-roots.sh" });
    integration_tests.addArtifactArg(cli);
    b.step("test-integration", "Run hermetic signed-repository integration roots")
        .dependOn(&integration_tests.step);

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
    test_step.dependOn(&repository_add_tests.step);

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
    const audit_tests = b.addSystemCommand(
        &.{ "python3", "-m", "unittest", "tools/test_security_audit.py" },
    );
    audit_step.dependOn(&audit_tests.step);

    const release_test_step = b.step("test-release", "Run deterministic release packaging and audit tests");
    const release_tests = b.addSystemCommand(&.{ "python3", "-m", "unittest", "tools/test_release.py" });
    release_test_step.dependOn(&release_tests.step);
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

    const policy_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"repository_policy.test."},
    });
    const run_policy_tests = b.addRunArtifact(policy_tests);
    b.step("test-repository-policy", "Run multi-repository policy tests")
        .dependOn(&run_policy_tests.step);

    const target_apt_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"target_apt_config.test."},
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

    const lock_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "exact_lock.test.",
            "exact_lock_v2.test.",
            "system_operation_lock.test.",
        },
    });
    const run_lock_tests = b.addRunArtifact(lock_tests);
    b.step("test-exact-lock", "Run exact solved-closure lock tests")
        .dependOn(&run_lock_tests.step);

    const system_workflow_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "production_backend.test.system operation replay",
            "production_backend.test.journal probe",
            "production_backend.test.persistent directory",
            "production_backend.test.system operation guard",
            "production_backend.test.pre-journal",
            "production_backend.test.cleanup failure",
            "production_backend.test.tampered system intent",
            "production_backend.test.system recovery",
            "production_backend.test.successful system recovery",
            "production_backend.test.identical system operations",
            "production_backend.test.retained freshness",
            "system_product.test.system active configuration guard",
            "repository_backend.test.repository add acquires",
        },
    });
    const run_system_workflow_tests = b.addRunArtifact(
        system_workflow_tests,
    );
    const system_workflow_step = b.step(
        "test-system-workflow",
        "Run standalone system transaction and recovery tests",
    );
    system_workflow_step.dependOn(&run_system_workflow_tests.step);
    test_step.dependOn(&run_system_workflow_tests.step);

    const provenance_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "transaction_provenance.test.",
            "transaction_provenance_v2.test.",
            "transaction_provenance_v3.test.",
        },
    });
    const run_provenance_tests = b.addRunArtifact(provenance_tests);
    b.step("test-transaction-provenance", "Run transaction provenance tests")
        .dependOn(&run_provenance_tests.step);

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
    test_step.dependOn(&run_production_customize_tests.step);

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
    test_step: *std.Build.Step,
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
        test_step.dependOn(&help.step);
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
        "authenticated-refresh.md",
        "deb-payload-validation.md",
        "exact-locks-and-provenance.md",
        "integration-roots.md",
        "multi-repository-policy.md",
        "openpgp-verifier.md",
        "package-acquisition.md",
        "product-api.md",
        "project-status.md",
        "repository-management.md",
        "release-installation.md",
        "release-tooling.md",
        "releasing.md",
        "safety-ci.md",
        "solver-planning.md",
        "threat-model.md",
        "transaction-executor.md",
        "transaction-recovery.md",
        "target-apt-config.md",
        "zvmi-package-family.md",
    };
    const schemas = [_][]const u8{
        "apt-config-snapshot-v1.json",
        "apt-config-snapshot-v2.json",
        "command-result-v1.json",
        "exact-closure-lock-v1.json",
        "exact-closure-lock-v2.json",
        "repository-add-state-v1.json",
        "repository-operation-result-v1.json",
        "system-operation-lock-v2.json",
        "transaction-plan-v1.json",
        "transaction-plan-v2.json",
        "transaction-plan-v3.json",
        "transaction-result-v1.json",
        "transaction-result-v2.json",
        "transaction-result-v3.json",
    };
    const regular_files = [_]struct { source: []const u8, destination: []const u8 }{
        .{ .source = "README.md", .destination = "share/doc/debz/README.md" },
        .{ .source = "LICENSE", .destination = "share/doc/debz/LICENSE" },
        .{ .source = "THIRD_PARTY_NOTICES", .destination = "share/doc/debz/THIRD_PARTY_NOTICES" },
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
