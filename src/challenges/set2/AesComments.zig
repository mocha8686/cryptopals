const std = @import("std");
const cryptopals = @import("cryptopals");

const Allocator = std.mem.Allocator;
const Encrypter = cryptopals.blackbox.Encrypter;
const Decrypter = cryptopals.blackbox.Decrypter;
const EncDec = cryptopals.blackbox.EncDec;
const Data = cryptopals.Data;

key: [16]u8,
iv: [16]u8,
prefix: []const u8 = "comment1=cooking%20MCs;userdata=",
postfix: []const u8 = ";comment2=%20like%20a%20pound%20of%20bacon",

const Self = @This();

pub fn new() !Self {
    var seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&seed));
    var prng = std.rand.DefaultPrng.init(seed);
    const rand = prng.random();

    var key: [16]u8 = undefined;
    rand.bytes(&key);

    var iv: [16]u8 = undefined;
    rand.bytes(&iv);

    return .{
        .key = key,
        .iv = iv,
    };
}

pub fn encrypt(self: *Self, data: *Data) !void {
    const allocator = data.allocator;

    const len = self.prefix.len + data.len + self.postfix.len;
    const buf = try allocator.alloc(u8, len);

    const a = self.prefix.len;
    const b = a + data.len;

    @memcpy(buf[0..a], self.prefix);
    @memcpy(buf[a..b], data.buf);
    @memcpy(buf[b..], self.postfix);

    data.reinit(buf);
    try data.pad(16);
    try data.encrypt(.{ .aes_128_cbc = .{ .key = self.key, .iv = self.iv } });
}

pub fn decrypt(self: *Self, data: *Data) !void {
    try data.decrypt(.{ .aes_128_cbc = .{ .key = self.key, .iv = self.iv } });
    try data.unpad();
}

pub fn encrypter(self: *Self) Encrypter {
    return Encrypter.init(self);
}

pub fn decrypter(self: *Self) Decrypter {
    return Decrypter.init(self);
}

pub fn encDec(self: *Self) EncDec {
    return EncDec.init(self);
}
