const std = @import("std");
const Data = @import("Data.zig");

const aes = std.crypto.core.aes;

const allocator = std.testing.allocator;

test "set 1 challenge 1" {
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

test "set 1 challenge 2" {
    var lhs = try Data.fromHex(allocator, "1c0111001f010100061a024b53535009181c");
    const rhs = try Data.fromHex(allocator, "686974207468652062756c6c277320657965");

    defer lhs.deinit();
    defer rhs.deinit();

    try lhs.xor(rhs);

    const res = try lhs.hex();
    defer res.deinit();

    try std.testing.expectEqualStrings("746865206b696420646f6e277420706c6179", res.data);
}

test "set 1 challenge 3" {
    const data = try Data.fromHex(allocator, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    defer data.deinit();

    const res = try data.guessSingleByteXor();
    defer res.deinit();
    try std.testing.expectEqualStrings("Cooking MC's like a pound of bacon", res.data);
}

test "set 1 challenge 5" {
    const plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const key = "ICE";

    var plaintext_data = try Data.new(allocator, plaintext);
    defer plaintext_data.deinit();

    try plaintext_data.xorBytes(key);

    const hex_str = try plaintext_data.hex();
    defer hex_str.deinit();

    try std.testing.expectEqualStrings(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        hex_str.data,
    );
}

test "set 1 challenge 7" {
    const text = @embedFile("data/1/7.txt");
    const ciphertext = try std.mem.replaceOwned(u8, allocator, text, "\n", "");
    defer allocator.free(ciphertext);

    var data = try Data.fromBase64(allocator, ciphertext);
    defer data.deinit();

    try data.decrypt(.{ .aes_128_ecb = .{ .key = "YELLOW SUBMARINE".* } });

    try std.testing.expectEqualStrings(
        @embedFile("data/1/7-sol.txt"),
        data.data,
    );
}

test "set 1 challenge 8" {
    const challenge_text = @embedFile("data/1/8.txt");
    const trimmed = std.mem.trim(u8, challenge_text, " \n\r\t");
    var iter = std.mem.splitSequence(u8, trimmed, "\n");

    var max_score: usize = 0;
    var best_guess: ?Data = null;

    while (iter.next()) |hex_str| {
        const data = try Data.fromHex(allocator, hex_str);
        const score = try data.aesEcb128Score();

        if (score > max_score) {
            if (best_guess) |old_guess| {
                old_guess.deinit();
            }
            max_score = score;
            best_guess = data;
        } else {
            data.deinit();
        }
    }

    const guess = &best_guess.?;
    defer guess.deinit();

    const hex_str = try guess.hex();
    defer hex_str.deinit();

    try std.testing.expectEqualStrings(
        "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
        hex_str.data,
    );
    try std.testing.expectEqual(
        6,
        max_score,
    );
}

test "set 2 challenge 9" {
    var data = try Data.new(allocator, "YELLOW SUBMARINE");
    defer data.deinit();

    try data.pad(20);
    try std.testing.expectEqualStrings("YELLOW SUBMARINE\x04\x04\x04\x04", data.data);
}
