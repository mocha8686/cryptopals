const std = @import("std");
const config = @import("config");
const cryptopals = @import("cryptopals");

const AesToken = @import("set3/AesToken.zig");

const allocator = std.testing.allocator;

const Data = cryptopals.Data;
const Profile = cryptopals.attack.Profile;
const attack = cryptopals.attack;
const oracle = cryptopals.oracle;

test "challenge 17" {
    const secret_base64 = blk: {
        var seed: u64 = undefined;
        try std.posix.getrandom(std.mem.asBytes(&seed));
        var prng = std.Random.DefaultPrng.init(seed);
        const rand = prng.random();

        const hidden_strings = @embedFile("data/3/17.txt");
        const n_hidden_strings = std.mem.count(u8, hidden_strings, "\n") + 1;
        const n = rand.uintLessThan(u8, @intCast(n_hidden_strings));

        var strings = std.mem.splitScalar(u8, hidden_strings, '\n');
        var string: []const u8 = undefined;
        for (0..n + 1) |_| {
            string = strings.next() orelse return error.InvalidString;
        }

        break :blk string;
    };

    var token_blackbox = try AesToken.new(secret_base64);
    const res = try attack.aesCbcPaddingOracle(allocator, token_blackbox.encrypter(), token_blackbox.paddingOracle());
    defer res.deinit();

    try std.testing.expectEqualStrings(
        "",
        res.buf,
    );
}