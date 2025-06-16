const std = @import("std");
const cryptopals = @import("cryptopals");

const Allocator = std.mem.Allocator;
const Encrypter = cryptopals.blackbox.Encrypter;
const PaddingOracle = cryptopals.blackbox.PaddingOracle;
const Data = cryptopals.Data;

key: [16]u8,
secret_base64: []const u8,

const Self = @This();

pub fn new(secret_base64: []const u8) !Self {
    var seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&seed));
    var prng = std.Random.DefaultPrng.init(seed);
    const rand = prng.random();

    var key: [16]u8 = undefined;
    rand.bytes(&key);

    return .{
        .key = key,
        .secret_base64 = secret_base64,
    };
}

pub fn encrypt(self: *Self, data: *Data) !void {
    const allocator = data.allocator;

    const iv = blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        var prng = std.Random.DefaultPrng.init(seed);
        const rand = prng.random();
        var iv: [16]u8 = undefined;
        rand.bytes(&iv);
        break :blk iv;
    };

    var secret = try Data.fromBase64(allocator, self.secret_base64);
    defer secret.deinit();
    try secret.pad(16);
    try secret.encrypt(.{ .aes_128_cbc = .{ .key = self.key, .iv = iv } });

    const buf = try allocator.alloc(u8, secret.len + 16);
    @memcpy(buf[0..16], &iv);
    @memcpy(buf[16..], secret.buf);

    data.reinit(buf);
}

pub fn hasValidPadding(self: *Self, data: Data) !bool {
    const allocator = data.allocator;
    const iv = data.buf[0..16];
    var secret = try Data.copy(allocator, data.buf[16..]);
    defer secret.deinit();
    try secret.decrypt(.{ .aes_128_cbc = .{ .key = self.key, .iv = iv.* } });
    secret.unpad() catch |err| {
        if (err == error.InvalidPadding) return false;
        return err;
    };
    return true;
}

pub fn encrypter(self: *Self) Encrypter {
    return Encrypter.init(self);
}

pub fn paddingOracle(self: *Self) PaddingOracle {
    return PaddingOracle.init(self);
}
