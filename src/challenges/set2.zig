const std = @import("std");
const config = @import("config");
const cryptopals = @import("cryptopals");

const AesEcbOrCbc = @import("set2/AesEcbOrCbc.zig");
const AesInfix = @import("set2/AesInfix.zig");
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

test "[S1] challenge 12" {
    if (config.slow < 1) return;

    var prefix_blackbox = try AesPrefix.new();

    const res = try attack.aesEcbDecipherPostfix(allocator, prefix_blackbox.encrypter());
    defer res.deinit();

    try std.testing.expectEqualStrings(
        @embedFile("data/2/12-sol.txt"),
        res.buf,
    );
}

test "challenge 13" {
    var profile_blackbox = try AesProfile.withKey("YELLOW SUBMARINE".*);
    const profile = try attack.aesProfileCutPaste(allocator, profile_blackbox.encDec());
    defer profile.deinit();
    try std.testing.expectEqualStrings("admin", profile.role);
}

test "challenge 13 x100" {
    for (0..100) |_| {
        var profile_blackbox = try AesProfile.init();
        const profile = try attack.aesProfileCutPaste(allocator, profile_blackbox.encDec());
        defer profile.deinit();
        try std.testing.expectEqualStrings("admin", profile.role);
    }
}

fn testAesEcbDecipherPostfix(prefix_len: ?u8) !void {
    var infix_blackbox = try AesInfix.new(allocator, prefix_len);
    defer infix_blackbox.deinit();

    const res = try attack.aesEcbDecipherPostfix(allocator, infix_blackbox.encrypter());
    defer res.deinit();

    try std.testing.expectEqualStrings(
        @embedFile("data/2/14-sol.txt"),
        res.buf,
    );
}

test "[S2] challenge 14 block-aligned prefix len" {
    if (config.slow < 2) return;

    try testAesEcbDecipherPostfix(16);
    try testAesEcbDecipherPostfix(32);
}

test "[S2] challenge 14 misaligned prefix len" {
    if (config.slow < 2) return;

    try testAesEcbDecipherPostfix(12);
    try testAesEcbDecipherPostfix(24);
}

test "[S3] challenge 14 random prefix len x10" {
    if (config.slow < 3) return;

    for (0..10) |_| {
        var infix_blackbox = try AesInfix.new(allocator, null);
        defer infix_blackbox.deinit();

        const res = try attack.aesEcbDecipherPostfix(allocator, infix_blackbox.encrypter());
        defer res.deinit();

        try std.testing.expectEqualStrings(
            @embedFile("data/2/14-sol.txt"),
            res.buf,
        );
    }
}
