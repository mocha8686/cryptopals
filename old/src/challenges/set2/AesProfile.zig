const std = @import("std");
const cryptopals = @import("cryptopals");

const DefaultPrng = std.Random.DefaultPrng;

const Encrypter = cryptopals.blackbox.Encrypter;
const Decrypter = cryptopals.blackbox.Decrypter;
const EncDec = cryptopals.blackbox.EncDec;
const Data = cryptopals.Data;
const EcbOrCbc = cryptopals.oracle.EcbOrCbc;
const Profile = cryptopals.attack.Profile;
const cipherLib = cryptopals.cipher;

cipher_type: cipherLib.Cipher,
prng: DefaultPrng,

const Self = @This();

pub fn init() !Self {
    var seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&seed));
    var prng = DefaultPrng.init(seed);
    const rand = prng.random();

    var key: [16]u8 = undefined;
    rand.bytes(&key);

    return .{
        .cipher_type = .{ .aes_128_ecb = .{ .key = key } },
        .prng = prng,
    };
}

pub fn withKey(key: [16]u8) !Self {
    var seed: u64 = undefined;
    try std.posix.getrandom(std.mem.asBytes(&seed));
    const prng = DefaultPrng.init(seed);

    return .{
        .cipher_type = .{ .aes_128_ecb = .{ .key = key } },
        .prng = prng,
    };
}

pub fn encrypt(self: *Self, data: *Data) !void {
    const allocator = data.allocator;

    const profile = try Profile.profileFor(allocator, data.buf);
    defer profile.deinit();

    const profile_str = try profile.toString();
    data.reinit(profile_str);
    try data.pad(16);
    try data.encrypt(self.cipher_type);
}

pub fn decrypt(self: *Self, data: *Data) !void {
    try data.decrypt(self.cipher_type);
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