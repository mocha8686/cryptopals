const std = @import("std");
const cryptopals = @import("cryptopals");

const DefaultPrng = std.Random.DefaultPrng;

const Encrypter = cryptopals.blackbox.Encrypter;
const Data = cryptopals.Data;
const EcbOrCbc = cryptopals.oracle.EcbOrCbc;
const cipherLib = cryptopals.cipher;

cipher_type: cipherLib.Cipher,
prng: DefaultPrng,

const Self = @This();

pub fn init(maybe_cipher_type: ?EcbOrCbc) !Self {
    var seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&seed));
    var prng = DefaultPrng.init(seed);
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

    return .{
        .cipher_type = cipher_type,
        .prng = prng,
    };
}

pub fn encrypt(self: *Self, data: *Data) !void {
    const rand = self.prng.random();
    const allocator = data.allocator;

    const n_bytes_before = rand.intRangeAtMost(u32, 5, 10);
    const n_bytes_after = rand.intRangeAtMost(u32, 5, 10);

    var buf = try allocator.alloc(u8, n_bytes_before + data.len + n_bytes_after);

    rand.bytes(buf[0..n_bytes_before]);
    rand.bytes(buf[n_bytes_before + data.len ..]);
    @memcpy(buf[n_bytes_before .. n_bytes_before + data.len], data.buf);

    data.reinit(buf);
    try data.pad(16);
    try data.encrypt(self.cipher_type);
}

pub fn encrypter(self: *Self) Encrypter {
    return Encrypter.init(self);
}