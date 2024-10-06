const std = @import("std");
const dataLib = @import("data.zig");

const allocator = std.testing.allocator;
const Data = dataLib.Data;

test "challenge 4" {
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
