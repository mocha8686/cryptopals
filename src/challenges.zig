const std = @import("std");
const dataLib = @import("data.zig");

const allocator = std.testing.allocator;
const Data = dataLib.Data;

test "challenge 1" {
    const hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    const hex_to_base64 = try Data.fromHex(allocator, hex);
    const test_base64 = try hex_to_base64.base64();

    defer hex_to_base64.deinit();
    defer test_base64.deinit();

    try std.testing.expectEqualStrings(base64, test_base64.data);

    const base64_to_hex = try Data.fromBase64(allocator, base64);
    const test_hex = try base64_to_hex.hex();

    defer base64_to_hex.deinit();
    defer test_hex.deinit();

    try std.testing.expectEqualStrings(hex, test_hex.data);
}

test "challenge 2" {
    const lhs = try Data.fromHex(allocator, "1c0111001f010100061a024b53535009181c");
    const rhs = try Data.fromHex(allocator, "686974207468652062756c6c277320657965");

    defer lhs.deinit();
    defer rhs.deinit();

    const res = try lhs.xor(&rhs);
    const res_str = try res.hex();

    defer res.deinit();
    defer res_str.deinit();

    try std.testing.expectEqualStrings("746865206b696420646f6e277420706c6179", res_str.data);
}

test "challenge 3" {
    const data = try Data.fromHex(allocator, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    defer data.deinit();

    const res = try data.guess_repeating_key_xor();
    defer res.deinit();

    try std.testing.expectEqualStrings("Cooking MC's like a pound of bacon", res.data);
}
