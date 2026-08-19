const std = @import("std");

const package_version = "0.1.0";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const version = b.option([]const u8, "version", "Release version (SemVer)") orelse package_version;
    _ = std.SemanticVersion.parse(version) catch {
        std.debug.panic("invalid -Dversion '{s}': expected SemVer (for example 0.1.0 or 1.2.3-rc.1)", .{version});
    };

    const build_options = b.addOptions();
    build_options.addOption([]const u8, "version", version);

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
    debz.linkLibrary(libsolv);
    debz.link_libc = true;
    debz.linkSystemLibrary("lzma", .{});
    debz.linkSystemLibrary("zstd", .{});

    const cli_module = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    cli_module.addImport("debz", debz);

    const cli = b.addExecutable(.{
        .name = "debz",
        .root_module = cli_module,
    });
    const install_cli = b.addInstallArtifact(cli, .{});
    b.getInstallStep().dependOn(&install_cli.step);
    installReleaseFiles(b, install_cli);
    b.step("release-install", "Install the complete release tree for packaging")
        .dependOn(b.getInstallStep());

    const run_cli = b.addRunArtifact(cli);
    run_cli.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cli.addArgs(args);
    b.step("run", "Run the debz CLI").dependOn(&run_cli.step);

    const tests = b.addTest(.{ .root_module = debz });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run unit and CLI integration tests");
    test_step.dependOn(&run_tests.step);

    const cli_tests = b.addSystemCommand(&.{ "sh", "tools/test-cli.sh" });
    cli_tests.addArtifactArg(cli);
    cli_tests.addArg(version);
    test_step.dependOn(&cli_tests.step);

    const integration_tests = b.addSystemCommand(&.{ "sh", "tools/test-integration-roots.sh" });
    integration_tests.addArtifactArg(cli);
    b.step("test-integration", "Run hermetic signed-repository integration roots")
        .dependOn(&integration_tests.step);

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

    const audit = b.addSystemCommand(&.{ "python3", "tools/security-audit.py" });
    b.step("security-audit", "Run hermeticity, dependency-policy, license, secret, and docs gates")
        .dependOn(&audit.step);

    const release_tests = b.addSystemCommand(&.{ "python3", "-m", "unittest", "tools/test_release.py" });
    b.step("test-release", "Run deterministic release packaging and audit tests")
        .dependOn(&release_tests.step);

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

    const transaction_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"transaction_executor.test."},
    });
    const run_transaction_tests = b.addRunArtifact(transaction_tests);
    b.step("test-transaction-executor", "Run dpkg transaction executor tests")
        .dependOn(&run_transaction_tests.step);

    const lock_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"exact_lock.test."},
    });
    const run_lock_tests = b.addRunArtifact(lock_tests);
    b.step("test-exact-lock", "Run exact solved-closure lock tests")
        .dependOn(&run_lock_tests.step);

    const provenance_tests = b.addTest(.{
        .root_module = debz,
        .filters = &.{"transaction_provenance.test."},
    });
    const run_provenance_tests = b.addRunArtifact(provenance_tests);
    b.step("test-transaction-provenance", "Run transaction provenance tests")
        .dependOn(&run_provenance_tests.step);

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

fn installReleaseFiles(b: *std.Build, install_cli: *std.Build.Step.InstallArtifact) void {
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
        "release-installation.md",
        "release-tooling.md",
        "releasing.md",
        "safety-ci.md",
        "solver-planning.md",
        "threat-model.md",
        "transaction-executor.md",
        "transaction-recovery.md",
        "zvmi-package-family.md",
    };
    const schemas = [_][]const u8{
        "command-result-v1.json",
        "exact-closure-lock-v1.json",
        "transaction-plan-v1.json",
        "transaction-plan-v2.json",
        "transaction-result-v1.json",
    };
    const regular_files = [_]struct { source: []const u8, destination: []const u8 }{
        .{ .source = "README.md", .destination = "share/doc/debz/README.md" },
        .{ .source = "LICENSE", .destination = "share/doc/debz/LICENSE" },
        .{ .source = "THIRD_PARTY_NOTICES", .destination = "share/doc/debz/THIRD_PARTY_NOTICES" },
        .{ .source = "security/runtime-dependencies.json", .destination = "share/debz/runtime-dependencies.json" },
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
}
