const std = @import("std");
const config = @import("config");
const cryptopals = @import("cryptopals");

const AesEcbOrCbc = @import("set2/AesEcbOrCbc.zig");
const AesPrefix = @import("set2/AesPrefix.zig");
const AesProfile = @import("set2/AesProfile.zig");

const allocator = std.testing.allocator;

const Data = cryptopals.Data;
const Profile = cryptopals.attack.Profile;
const attack = cryptopals.attack;
const oracle = cryptopals.oracle;

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
    const plaintext = @embedFile("data/funky.txt");

    var ecb = try AesEcbOrCbc.init(.ecb);
    for (0..10) |_| {
        var data = try Data.new(allocator, plaintext);
        defer data.deinit();
        try ecb.encrypt(&data);

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.ecb, res);
    }

    var cbc = try AesEcbOrCbc.init(.cbc);
    for (0..10) |_| {
        var data = try Data.new(allocator, plaintext);
        defer data.deinit();
        try cbc.encrypt(&data);

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.cbc, res);
    }
}

test "[S1] challenge 11 x100" {
    if (config.slow < 1) return;

    const plaintext = @embedFile("data/funky.txt");

    var ecb = try AesEcbOrCbc.init(.ecb);
    for (0..100) |_| {
        var data = try Data.new(allocator, plaintext);
        defer data.deinit();
        try ecb.encrypt(&data);

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.ecb, res);
    }

    var cbc = try AesEcbOrCbc.init(.cbc);
    for (0..100) |_| {
        var data = try Data.new(allocator, plaintext);
        defer data.deinit();
        try cbc.encrypt(&data);

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.cbc, res);
    }
}

test "challenge 12" {
    var prefix_blackbox = try AesPrefix.new();
    const res = try attack.aesEcbPrefix(allocator, prefix_blackbox.encrypter());
    defer res.deinit();

    try std.testing.expectEqualStrings(
        @embedFile("data/2/12-sol.txt"),
        res.buf,
    );
}

test "challenge 13" {
    // TODO: test with random key
    var profile_blackbox = try AesProfile.withKey("YELLOW SUBMARINE".*);
    const profile = try attack.aesProfileCutPaste(allocator, profile_blackbox.encDec());
    defer profile.deinit();
    try std.testing.expectEqualStrings("admin", profile.role);
}
