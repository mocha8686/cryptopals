const std = @import("std");
const Data = @import("Data.zig");
const cipherLib = @import("cipher.zig");

const Allocator = std.mem.Allocator;

pub const EcbOrCbc = enum {
    ecb,
    cbc,
};

pub fn aesEcbOrCbc(allocator: Allocator, maybe_cipher_type: ?EcbOrCbc) !Data {
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
