const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const test_step = b.step("test", "Run unit tests.");
    const run_step = b.step("run", "Run the applicaiton.");
    const debug_step = b.step("debug", "Print the paths to the challenge test executables.");

    // Root module

    const cryptopals_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Challenges

    const slow = b.option(u3, "slow", "Max slow level of test to include [0,3]") orelse 0;
    const options = b.addOptions();
    options.addOption(u3, "slow", slow);

    for ([_][]const u8{
        "src/challenges/set1.zig",
        "src/challenges/set2.zig",
    }) |challenge_path| {
        const challenge_unit_tests = b.addTest(.{
            .root_source_file = b.path(challenge_path),
            .target = target,
            .optimize = optimize,
        });
        challenge_unit_tests.root_module.addOptions("config", options);
        challenge_unit_tests.root_module.addImport("cryptopals", cryptopals_mod);
        const run_challenge_unit_tests = b.addRunArtifact(challenge_unit_tests);
        test_step.dependOn(&run_challenge_unit_tests.step);
    }

    const clap = b.dependency("clap", .{});

    // Library

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
    test_step.dependOn(&run_lib_unit_tests.step);

    // Executables

    const zxor = b.addExecutable(.{
        .name = "zxor",
        .root_source_file = b.path("src/bin/zxor.zig"),
        .target = target,
        .optimize = optimize,
    });
    zxor.root_module.addImport("cryptopals", cryptopals_mod);
    zxor.root_module.addImport("clap", clap.module("clap"));

    b.installArtifact(zxor);

    const run_zxor = b.addRunArtifact(zxor);
    run_zxor.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_zxor.addArgs(args);
    }

    run_step.dependOn(&run_zxor.step);
}
