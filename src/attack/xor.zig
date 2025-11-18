const std = @import("std");
const Data = @import("../Data.zig");
const score = @import("score.zig").score;

pub fn singleCharacterXOR(data: *Data) !u8 {
    var bestGuess: Data = blk: {
        var guess = try Data.copy(data.allocator, &.{0});
        errdefer guess.deinit();
        try guess.xor(data.*);
        break :blk guess;
    };
    var bestScore: i32 = score(bestGuess);
    var bestChar: u8 = 0;

    for (0..std.math.maxInt(u8)) |n| {
        const c: u8 = @intCast(n);

        var guess = try Data.copy(data.allocator, &.{c});
        errdefer guess.deinit();

        try guess.xor(data.*);
        const guessScore = score(guess);
        if (guessScore > bestScore) {
            bestGuess.deinit();
            bestScore = guessScore;
            bestGuess = guess;
            bestChar = c;
        } else {
            guess.deinit();
        }
    }

    data.reinit(bestGuess.bytes);
    return bestChar;
}

test "set 1 challenge 3" {
    const allocator = std.testing.allocator;

    var data = try Data.fromHex(
        allocator,
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
    );
    defer data.deinit();

    const byte = try singleCharacterXOR(&data);

    try std.testing.expectEqual('X', byte);
    try std.testing.expectEqualStrings("Cooking MC's like a pound of bacon", data.bytes);
}
