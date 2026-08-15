const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

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
    debz.linkLibrary(libsolv);
    debz.link_libc = true;
    debz.linkSystemLibrary("lzma", .{});

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
    b.installArtifact(cli);

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
    test_step.dependOn(&cli_tests.step);

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
