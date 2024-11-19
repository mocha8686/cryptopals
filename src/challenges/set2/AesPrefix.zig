const std = @import("std");
const cryptopals = @import("cryptopals");

const Blackbox = cryptopals.Blackbox;
const Data = cryptopals.Data;

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

    return .{
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

    data.reinit(plaintext);
    try data.pad(16);
    try data.encrypt(.{ .aes_128_ecb = .{ .key = self.key } });
}

pub fn blackbox(self: *Self) Blackbox {
    return Blackbox.init(self);
}
