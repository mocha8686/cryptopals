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

test "challenge 4" {
    const challenge_text = @embedFile("data/1/4.txt");
    const trimmed = std.mem.trim(u8, challenge_text, " \n\r\t");
    var iter = std.mem.splitSequence(u8, trimmed, "\n");

    var max_score: isize = 0;
    var best_guess: ?Data = null;
    while (iter.next()) |hex_str| {
        const data = try Data.fromHex(allocator, hex_str);
        defer data.deinit();

        const guess = try data.guess_repeating_key_xor();
        const score = guess.score();

        if (score > max_score) {
            if (best_guess) |old_guess| {
                old_guess.deinit();
            }

            max_score = score;
            best_guess = guess;
        } else {
            guess.deinit();
        }
    }

    const final_guess = best_guess orelse unreachable;
    defer final_guess.deinit();

    try std.testing.expectEqualStrings("Now that the party is jumping\n", final_guess.data);
}

test "challenge 5" {
    const plaintext = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const key = "ICE";

    const plaintext_data = Data.init(allocator, plaintext);
    const key_data = Data.init(allocator, key);

    const ciphertext_data = try plaintext_data.xor(&key_data);
    defer ciphertext_data.deinit();

    const hex_str = try ciphertext_data.hex();
    defer hex_str.deinit();
    try std.testing.expectEqualStrings(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        hex_str.data,
    );
}
