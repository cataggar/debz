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
    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);
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
        .{ .args = &.{"package-cache"}, .usage = "debz package-cache <command> [options]" },
        .{ .args = &.{ "package-cache", "fingerprint" }, .usage = "debz package-cache fingerprint --lock-input PATH" },
        .{ .args = &.{ "package-cache", "prepare" }, .usage = "debz package-cache prepare --lock-input PATH" },
        .{ .args = &.{"transaction-result"}, .usage = "debz transaction-result verify --state-path PATH" },
        .{ .args = &.{ "transaction-result", "verify" }, .usage = "debz transaction-result verify --state-path PATH" },
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

    const apt_system_acceptance = b.addSystemCommand(
        &.{ "python3", "tools/test-apt-system-acceptance.py" },
    );
    apt_system_acceptance.addArtifactArg(cli);
    b.step("test-apt-system-acceptance", "Run real apt facade and dpkg in a disposable root (requires root)")
        .dependOn(&apt_system_acceptance.step);

    const native_differential_tests = b.addSystemCommand(
        &.{ "python3", "-m", "unittest", "tools/test_native_differential.py" },
    );
    const native_differential_step = b.step(
        "test-native-differential",
        "Validate the native transaction compatibility corpus and comparator",
    );
    native_differential_step.dependOn(&native_differential_tests.step);
    test_step.dependOn(&native_differential_tests.step);

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
    const apt_system_schema_tests = b.addSystemCommand(
        &.{ "python3", "-m", "unittest", "tools/test_apt_system_schema.py" },
    );
    release_test_step.dependOn(&apt_system_schema_tests.step);
    test_step.dependOn(&apt_system_schema_tests.step);
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
        .filters = &.{"production workflow"},
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
        "Run production backend workflow and exact-lock tests",
    );
    production_backend_test_step.dependOn(&run_production_backend_tests.step);
    production_backend_test_step.dependOn(
        &run_required_production_security_tests.step,
    );
    test_step.dependOn(&run_production_backend_tests.step);

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
            &.{"apt_system_orchestrator.test."},
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
    test_step.dependOn(&run_system_profile_tests.step);
    test_step.dependOn(&run_apt_system_api_tests.step);
    test_step.dependOn(&run_apt_system_cli_tests.step);
    test_step.dependOn(&run_apt_system_command_tests.step);
    test_step.dependOn(&run_apt_system_state_tests.step);
    test_step.dependOn(&run_apt_system_orchestrator_tests.step);
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
    test_step.dependOn(&run_required_production_security_tests.step);
    test_step.dependOn(&run_required_orchestrator_security_tests.step);

    const native_program_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
            "native_authorization.test.",
            "native_program.test.",
            "transaction_engine.test.",
        },
    });
    const run_native_program_tests = b.addRunArtifact(native_program_tests);
    const native_program_corpus_tests = b.addTest(.{
        .root_module = fuzz_tests.root_module,
        .filters = &.{"fuzz.corpus native transaction program seeds stay canonical"},
    });
    const run_native_program_corpus_tests = b.addRunArtifact(native_program_corpus_tests);
    const native_program_step = b.step(
        "test-native-program",
        "Run native authorization, program compiler, and canonical corpus tests",
    );
    native_program_step.dependOn(&run_native_program_tests.step);
    native_program_step.dependOn(&run_native_program_corpus_tests.step);

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

    const native_materialization_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"native_unpack.test.materialization external fixture"},
    });
    const native_materialization = b.addSystemCommand(
        &.{ "python3", "tools/test-native-materialization.py" },
    );
    native_materialization.addArtifactArg(native_materialization_tests);
    const native_materialization_oracle_tests = b.addSystemCommand(
        &.{ "python3", "-m", "unittest", "tools/test_native_materialization.py" },
    );
    native_materialization.step.dependOn(&native_materialization_oracle_tests.step);
    test_step.dependOn(&native_materialization_oracle_tests.step);
    b.step("test-native-materialization", "Compare real native data-only unpack with dpkg")
        .dependOn(&native_materialization.step);

    const native_conffiles = b.addSystemCommand(
        &.{ "python3", "tools/test-native-conffiles.py" },
    );
    native_conffiles.addArtifactArg(native_materialization_tests);
    const native_conffile_oracle_tests = b.addSystemCommand(
        &.{ "python3", "-m", "unittest", "tools/test_native_conffiles.py" },
    );
    native_conffiles.step.dependOn(&native_conffile_oracle_tests.step);
    test_step.dependOn(&native_conffile_oracle_tests.step);
    b.step("test-native-conffiles", "Compare native conffile and remove/purge phases with dpkg")
        .dependOn(&native_conffiles.step);

    const native_lifecycle_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"native_unpack.test.lifecycle external fixture"},
    });
    const native_lifecycle = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",     "PYTHONDONTWRITEBYTECODE=1",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}), "python3", "tools/test-native-lifecycle.py",
    });
    native_lifecycle.addArtifactArg(native_lifecycle_tests);
    const native_lifecycle_oracle_tests = b.addSystemCommand(
        &.{ "python3", "-m", "unittest", "tools/test_native_lifecycle.py" },
    );
    native_lifecycle.step.dependOn(&native_lifecycle_oracle_tests.step);
    test_step.dependOn(&native_lifecycle_oracle_tests.step);
    b.step("test-native-lifecycle", "Compare native lifecycle scripts and package states with dpkg")
        .dependOn(&native_lifecycle.step);

    const native_trigger_helper = b.addExecutable(.{
        .name = "native-trigger-helper",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/native_trigger_helper.zig"),
            .target = b.resolveTargetQuery(.{
                .cpu_arch = target.result.cpu.arch,
                .os_tag = .linux,
                .abi = .musl,
            }),
            .optimize = optimize,
            .link_libc = true,
        }),
        .linkage = .static,
    });
    b.step("native-trigger-helper", "Build the private trigger helper without installing it")
        .dependOn(&native_trigger_helper.step);
    const native_trigger_queue_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/native_trigger.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        }),
    });
    const run_native_trigger_queue_tests = b.addRunArtifact(native_trigger_queue_tests);
    b.step("test-native-trigger-helper", "Run private native trigger queue and helper tests")
        .dependOn(&run_native_trigger_queue_tests.step);
    test_step.dependOn(&run_native_trigger_queue_tests.step);
    const native_triggers = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",     "PYTHONDONTWRITEBYTECODE=1",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}), "python3", "tools/test-native-triggers.py",
    });
    native_triggers.addArtifactArg(native_lifecycle_tests);
    native_triggers.addArg("--native-helper");
    native_triggers.addArtifactArg(native_trigger_helper);
    const native_trigger_oracle_tests = b.addSystemCommand(
        &.{ "python3", "-m", "unittest", "tools/test_native_triggers.py" },
    );
    native_triggers.step.dependOn(&native_trigger_oracle_tests.step);
    native_triggers.step.dependOn(&run_native_trigger_queue_tests.step);
    test_step.dependOn(&native_trigger_oracle_tests.step);
    b.step("test-native-triggers", "Compare native trigger activation and processing with dpkg")
        .dependOn(&native_triggers.step);

    const native_recovery_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{ "native_recovery.test.", "native_provenance.test." },
    });
    const run_native_recovery_tests = b.addRunArtifact(native_recovery_tests);
    b.step("test-native-recovery-unit", "Run native execution journal and provenance tests")
        .dependOn(&run_native_recovery_tests.step);
    test_step.dependOn(&run_native_recovery_tests.step);
    const native_recovery = b.addSystemCommand(&.{
        "sudo",                                         "-n",                                                     "env",     "PYTHONDONTWRITEBYTECODE=1",
        b.fmt("TMPDIR={s}", .{b.pathFromRoot(".tmp")}), b.fmt("XDG_CACHE_HOME={s}", .{b.pathFromRoot(".cache")}), "python3", "tools/test-native-recovery.py",
    });
    native_recovery.addArtifactArg(native_lifecycle_tests);
    native_recovery.addArg("--native-helper");
    native_recovery.addArtifactArg(native_trigger_helper);
    const native_recovery_oracle_tests = b.addSystemCommand(
        &.{ "python3", "-m", "unittest", "tools/test_native_recovery.py" },
    );
    native_recovery.step.dependOn(&native_recovery_oracle_tests.step);
    native_recovery.step.dependOn(&run_native_recovery_tests.step);
    test_step.dependOn(&native_recovery_oracle_tests.step);
    b.step("test-native-recovery", "Compare real native crash recovery with dpkg and bound provenance")
        .dependOn(&native_recovery.step);

    const package_database_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{
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
    test_step.dependOn(&run_package_cache_archive_tests.step);

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

    const archive_application_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"archive_application.test."},
    });
    const run_archive_application_tests = b.addRunArtifact(archive_application_tests);
    b.step("test-archive-application", "Run native archive application model tests")
        .dependOn(&run_archive_application_tests.step);

    const lock_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{ "exact_lock.test.", "exact_lock_v2.test." },
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
        "apt-system-facade.md",
        "archive-application-model.md",
        "authenticated-refresh.md",
        "deb-payload-validation.md",
        "exact-locks-and-provenance.md",
        "github-actions.md",
        "integration-roots.md",
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
        "zvmi-package-family.md",
    };
    const schemas = [_][]const u8{
        "apt-config-snapshot-v1.json",
        "apt-system-cli-diagnostic-v1.json",
        "apt-system-execution-completion-v1.json",
        "apt-system-operation-state-v1.json",
        "apt-system-request-v1.json",
        "apt-system-result-v1.json",
        "apt-system-result-v2.json",
        "apt-system-result-v3.json",
        "command-result-v1.json",
        "exact-closure-lock-v1.json",
        "exact-closure-lock-v2.json",
        "native-execution-intent-v1.json",
        "native-execution-progress-v1.json",
        "native-managed-state-v1.json",
        "native-script-outcome-v1.json",
        "native-transaction-authorization-v1.json",
        "native-transaction-program-v1.json",
        "native-transaction-provenance-v1.json",
        "native-trigger-events-v1.json",
        "package-cache-error-v1.json",
        "package-cache-fingerprint-v1.json",
        "package-cache-result-v1.json",
        "repository-add-state-v1.json",
        "repository-operation-result-v1.json",
        "root-operation-completion-v1.json",
        "root-operation-record-v1.json",
        "system-profile-v1.json",
        "transaction-plan-v1.json",
        "transaction-plan-v2.json",
        "transaction-plan-v3.json",
        "transaction-result-v1.json",
        "transaction-result-v2.json",
        "transaction-result-summary-v1.json",
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
