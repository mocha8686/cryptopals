const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const test_step = b.step("test", "Run unit tests.");
    const run_step = b.step("run", "Run the applicaiton.");
    const debug_step = b.step("debug", "Print the paths to the challenge test executables.");

    const slow = b.option(u3, "slow", "Max slow level of test to include [0,3]") orelse 0;
    const set = b.option(u8, "set", "The set to test.");

    const options = b.addOptions();
    options.addOption(u3, "slow", slow);

    // Root module

    const cryptopals_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Challenges

    for ([_][]const u8{
        "src/challenges/set1.zig",
        "src/challenges/set2.zig",
        "src/challenges/set3.zig",
    }, 0..) |challenge_path, i| {
        if (set) |n| {
            if (n != i + 1) continue;
        }

        const set_file = std.fs.path.basename(challenge_path);
        const set_name = set_file[0 .. set_file.len - 4];

        const challenge_unit_tests = b.addTest(.{
            .name = set_name,
            .root_source_file = b.path(challenge_path),
            .target = target,
            .optimize = optimize,
        });
        challenge_unit_tests.root_module.addOptions("config", options);
        challenge_unit_tests.root_module.addImport("cryptopals", cryptopals_mod);
        const run_challenge_unit_tests = b.addRunArtifact(challenge_unit_tests);
        test_step.dependOn(&run_challenge_unit_tests.step);

        const echo = b.addSystemCommand(&.{"echo"});
        echo.addArtifactArg(challenge_unit_tests);
        debug_step.dependOn(&echo.step);
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
