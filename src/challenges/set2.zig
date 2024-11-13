const std = @import("std");
const config = @import("config");
const cryptopals = @import("cryptopals");
const blackbox = @import("set2/blackbox.zig");

const aesEcbOrCbc = blackbox.aesEcbOrCbc;
const Data = cryptopals.Data;
const oracle = cryptopals.oracle;
const allocator = std.testing.allocator;

test "challenge 9" {
    var data = try Data.new(allocator, "YELLOW SUBMARINE");
    defer data.deinit();

    try data.pad(20);
    try std.testing.expectEqualStrings("YELLOW SUBMARINE\x04\x04\x04\x04", data.buf);
}

test "challenge 10" {
    const challenge_text = @embedFile("data/2/10.txt");
    const ciphertext = try std.mem.replaceOwned(u8, allocator, challenge_text, "\n", "");
    defer allocator.free(ciphertext);

    var data = try Data.fromBase64(allocator, ciphertext);
    defer data.deinit();

    try data.decrypt(.{ .aes_128_cbc = .{ .key = "YELLOW SUBMARINE".*, .iv = "\x00".* ** 16 } });

    try std.testing.expectEqualStrings(@embedFile("data/2/10-sol.txt"), data.buf);
}

test "challenge 11" {
    for (0..10) |_| {
        const data = try aesEcbOrCbc(allocator, .ecb);
        defer data.deinit();

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.ecb, res);
    }

    for (0..10) |_| {
        const data = try aesEcbOrCbc(allocator, .cbc);
        defer data.deinit();

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.cbc, res);
    }
}

test "[slow] challenge 11 x100" {
    if (!config.slow) return;

    for (0..100) |_| {
        const data = try aesEcbOrCbc(allocator, .ecb);
        defer data.deinit();

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.ecb, res);
    }

    for (0..100) |_| {
        const data = try aesEcbOrCbc(allocator, .cbc);
        defer data.deinit();

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.cbc, res);
    }
}

