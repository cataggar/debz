const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const debz = b.dependency("debz", .{
        .target = target,
        .optimize = optimize,
    });

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/consumer.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.root_module.addImport("debz", debz.module("debz"));

    const run_tests = b.addRunArtifact(tests);
    b.getInstallStep().dependOn(&run_tests.step);
}
