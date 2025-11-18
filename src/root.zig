const std = @import("std");

pub const Data = @import("Data.zig");

pub const cipher = @import("cipher.zig");
pub const attack = @import("attack.zig");

test "set 1 challenge 1" {
    const allocator = std.testing.allocator;

    var data = try Data.fromHex(
        allocator,
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
    );
    defer data.deinit();

    const base64 = cipher.Base64{};
    try data.encode(base64);

    try std.testing.expectEqualStrings(
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
        data.bytes,
    );
}

test "set 1 challenge 2" {
    const allocator = std.testing.allocator;

    var lhs = try Data.fromHex(
        allocator,
        "1c0111001f010100061a024b53535009181c",
    );
    defer lhs.deinit();

    const rhs = try Data.fromHex(
        allocator,
        "686974207468652062756c6c277320657965",
    );
    defer rhs.deinit();

    const xor = cipher.XOR{
        .key = rhs,
    };
    try lhs.decode(xor);

    const hex = cipher.Hex{};
    try lhs.encode(hex);

    try std.testing.expectEqualStrings(
        "746865206b696420646f6e277420706c6179",
        lhs.bytes,
    );
}

test "submodule tests" {
    std.testing.refAllDeclsRecursive(@This());
}
