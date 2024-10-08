const std = @import("std");
const Data = @import("Data.zig");

const allocator = std.testing.allocator;

test "set 1 challenge 4" {
    const challenge_text = @embedFile("data/1/4.txt");
    const trimmed = std.mem.trim(u8, challenge_text, " \n\r\t");
    var iter = std.mem.splitSequence(u8, trimmed, "\n");

    var max_score: isize = 0;
    var best_guess: ?Data = null;
    while (iter.next()) |hex_str| {
        const data = try Data.fromHex(allocator, hex_str);
        defer data.deinit();

        const guess = try data.guessSingleByteXor();
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

test "set 1 challenge 6" {
    const text = @embedFile("data/1/6.txt");
    const ciphertext = try std.mem.replaceOwned(u8, allocator, text, "\n", "");
    defer allocator.free(ciphertext);

    const data = try Data.fromBase64(allocator, ciphertext);
    defer data.deinit();

    const plaintext = try data.breakRepeatingKeyXor();
    defer plaintext.deinit();

    try std.testing.expectEqualStrings(@embedFile("data/1/6-sol.txt"), plaintext.data);
}
