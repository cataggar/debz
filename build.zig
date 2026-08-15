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
    b.step("test", "Run unit tests").dependOn(&run_tests.step);

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
