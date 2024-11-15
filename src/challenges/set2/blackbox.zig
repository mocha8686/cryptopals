const std = @import("std");
const cryptopals = @import("cryptopals");

const Allocator = std.mem.Allocator;
const DefaultPrng = std.rand.DefaultPrng;

const Blackbox = cryptopals.Blackbox;
const Data = cryptopals.Data;
const EcbOrCbc = cryptopals.oracle.EcbOrCbc;
const cipherLib = cryptopals.cipher;

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
    const plaintext = @embedFile("../data/funky.txt");

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

pub const AesPrefix = struct {
    key: [16]u8,

    const hidden_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    const Self = @This();

    pub fn new() !Self {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        var prng = std.rand.DefaultPrng.init(seed);
        const rand = prng.random();

        var key: [16]u8 = undefined;
        rand.bytes(&key);

        return Self{
            .key = key,
        };
    }

    pub fn encrypt(self: Self, data: *Data) !void {
        const allocator = data.allocator;

        const hidden_plaintext = try Data.fromBase64(allocator, hidden_string);
        defer hidden_plaintext.deinit();

        const len = data.buf.len + hidden_plaintext.buf.len;
        const plaintext = try allocator.alloc(u8, len);

        @memcpy(plaintext[0..data.buf.len], data.buf);
        @memcpy(plaintext[data.buf.len..], hidden_plaintext.buf);

        data.deinit();
        data.buf = plaintext;

        try data.pad(16);
        try data.encrypt(.{ .aes_128_ecb = .{ .key = self.key } });
    }

    pub fn blackbox(self: *Self) Blackbox {
        return Blackbox.init(self);
    }
};
