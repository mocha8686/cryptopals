const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addSharedLibrary(.{
        .name = "cryptopals",
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(lib);

    const lib_unit_tests = b.addTest(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const challenge_unit_tests = b.addTest(.{ .root_source_file = b.path("src/challenges.zig"), .target = target, .optimize = optimize });
    const run_challenge_unit_tests = b.addRunArtifact(challenge_unit_tests);

    const slow_challenge_unit_tests = b.addTest(.{ .root_source_file = b.path("src/challenges_slow.zig"), .target = target, .optimize = optimize });
    const run_slow_challenge_unit_tests = b.addRunArtifact(slow_challenge_unit_tests);

    const test_step = b.step("test", "Run unit tests.");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_challenge_unit_tests.step);

    if (b.option(bool, "slow", "Include slow unit tests") orelse false) {
        test_step.dependOn(&run_slow_challenge_unit_tests.step);
    }

    const clap = b.dependency("clap", .{});

    const zxor = b.addExecutable(.{
        .name = "zxor",
        .root_source_file = b.path("src/bin/zxor.zig"),
        .target = target,
        .optimize = optimize,
    });
    zxor.root_module.addImport("cryptopals", &lib.root_module);
    zxor.root_module.addImport("clap", clap.module("clap"));

    b.installArtifact(zxor);

    const run_zxor = b.addRunArtifact(zxor);
    run_zxor.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_zxor.addArgs(args);
    }

    const run_step = b.step("run", "Run the applicaiton.");
    run_step.dependOn(&run_zxor.step);
}
