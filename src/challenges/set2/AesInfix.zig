const std = @import("std");
const cryptopals = @import("cryptopals");

const Allocator = std.mem.Allocator;
const Encrypter = cryptopals.blackbox.Encrypter;
const Data = cryptopals.Data;

key: [16]u8,
prefix: []const u8,
allocator: Allocator,

const hidden_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

const Self = @This();

pub fn new(allocator: Allocator, prefix_length: ?u8) !Self {
    var seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&seed));
    var prng = std.rand.DefaultPrng.init(seed);
    const rand = prng.random();

    var key: [16]u8 = undefined;
    rand.bytes(&key);

    const prefix = try allocator.alloc(u8, prefix_length orelse rand.uintAtMost(usize, 64));
    rand.bytes(prefix);

    return .{
        .key = key,
        .prefix = prefix,
        .allocator = allocator,
    };
}

pub fn encrypt(self: *Self, data: *Data) !void {
    const allocator = data.allocator;

    const hidden_plaintext = try Data.fromBase64(allocator, hidden_string);
    defer hidden_plaintext.deinit();

    const len = self.prefix.len + data.buf.len + hidden_plaintext.buf.len;
    const plaintext = try allocator.alloc(u8, len);

    const a = self.prefix.len;
    const b = a + data.buf.len;

    @memcpy(plaintext[0..a], self.prefix);
    @memcpy(plaintext[a..b], data.buf);
    @memcpy(plaintext[b..], hidden_plaintext.buf);

    data.reinit(plaintext);
    try data.pad(16);
    try data.encrypt(.{ .aes_128_ecb = .{ .key = self.key } });
}

pub fn encrypter(self: *Self) Encrypter {
    return Encrypter.init(self);
}

pub fn deinit(self: *Self) void {
    self.allocator.free(self.prefix);
}
