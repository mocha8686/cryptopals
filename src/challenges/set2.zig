const std = @import("std");
const config = @import("config");
const cryptopals = @import("cryptopals");

const Data = cryptopals.Data;
const EcbOrCbc = cryptopals.oracle.EcbOrCbc;
const cipherLib = cryptopals.cipher;
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
        const data = try aesEcbOrCbc(.ecb);
        defer data.deinit();

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.ecb, res);
    }

    for (0..10) |_| {
        const data = try aesEcbOrCbc(.cbc);
        defer data.deinit();

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.cbc, res);
    }
}

test "[slow] challenge 11 x100" {
    if (!config.slow) return;

    for (0..100) |_| {
        const data = try aesEcbOrCbc(.ecb);
        defer data.deinit();

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.ecb, res);
    }

    for (0..100) |_| {
        const data = try aesEcbOrCbc(.cbc);
        defer data.deinit();

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.cbc, res);
    }
}

pub fn aesEcbOrCbc(maybe_cipher_type: ?EcbOrCbc) !Data {
    var seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&seed));
    var prng = std.rand.DefaultPrng.init(seed);
    const rand = prng.random();

    var key: [16]u8 = undefined;
    var iv: [16]u8 = undefined;

    rand.bytes(&key);
    rand.bytes(&iv);

    const cipher_type: cipherLib.Cipher = if (maybe_cipher_type) |c|
        switch (c) {
            .ecb => .{ .aes_128_ecb = .{ .key = key } },
            .cbc => .{ .aes_128_cbc = .{ .key = key, .iv = iv } },
        }
    else if (rand.boolean())
        .{ .aes_128_ecb = .{ .key = key } }
    else
        .{ .aes_128_cbc = .{ .key = key, .iv = iv } };

    const n_bytes_before = rand.intRangeAtMost(usize, 5, 10);
    const n_bytes_after = rand.intRangeAtMost(usize, 5, 10);
    const plaintext = @embedFile("data/funky.txt");

    var buf = try allocator.alloc(u8, n_bytes_before + plaintext.len + n_bytes_after);

    rand.bytes(buf[0..n_bytes_before]);
    rand.bytes(buf[n_bytes_before + plaintext.len ..]);
    @memcpy(buf[n_bytes_before .. n_bytes_before + plaintext.len], plaintext);

    var data = Data.init(allocator, buf);
    errdefer data.deinit();
    try data.pad(16);
    try data.encrypt(cipher_type);
    return data;
}
