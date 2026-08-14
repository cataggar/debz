const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const debz = b.addModule("debz", .{
        .root_source_file = b.path("src/debz.zig"),
        .target = target,
        .optimize = optimize,
    });

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
