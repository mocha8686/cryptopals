const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const clap = b.dependency("clap", .{});

    const mod = b.addModule("cryptopals", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });

    const options = b.addOptions();

    const slow = b.option(u3, "slow", "Max slowness class of tests to run. (0 = instant, 5 = very slow)") orelse 0;
    options.addOption(u3, "slow", slow);

    const zxor = b.addExecutable(.{
        .name = "zxor",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bin/zxor.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "cryptopals", .module = mod },
                .{ .name = "clap", .module = clap.module("clap") },
            },
        }),
    });
    b.installArtifact(zxor);

    const zxor_run_step = b.step("zxor", "Run the app");
    const zxor_run_cmd = b.addRunArtifact(zxor);
    zxor_run_step.dependOn(&zxor_run_cmd.step);
    zxor_run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        zxor_run_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });
    mod_tests.root_module.addOptions("config", options);
    const run_mod_tests = b.addRunArtifact(mod_tests);

    const zxor_tests = b.addTest(.{
        .root_module = zxor.root_module,
    });
    const run_zxor_tests = b.addRunArtifact(zxor_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_zxor_tests.step);
}
