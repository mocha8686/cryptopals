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

pub fn repeatingKeyXOR(data: *Data) !Data {
    const allocator = data.allocator;

    const keysize = guessKeysize(data.*);
    var key = try allocator.alloc(u8, keysize);
    errdefer allocator.free(key);

    const blocks = try partition(data, keysize);
    defer allocator.free(blocks);

    for (blocks, 0..) |block, n| {
        key[n] = try repeatingKeyXOR(block);
    }

    var buf = try allocator.alloc(u8, data.len());
    errdefer allocator.free(buf);

    for (blocks, 0..) |block, i| {
        defer allocator.free(block);
        for (block, 0..) |b, n| {
            buf[keysize * n + i] = b;
        }
    }

    data.reinit(buf);
    return Data.init(allocator, key);
}

fn partition(data: Data, keysize: u32) ![]Data {
    const allocator = data.allocator;
    const lengthPerBlock = data.len() / keysize;
    const remainder = data.len() % keysize;

    var blocks = try allocator.alloc([]u8, keysize);
    errdefer allocator.free(blocks);

    for (0..keysize) |n| {
        const blockLength = lengthPerBlock + (if (n < remainder) 1 else 0);
        blocks[n] = try allocator.alloc(u8, blockLength);
        errdefer allocator.free(blocks[n]);
    }

    const windows = std.mem.window(u8, data.bytes, keysize, keysize);
    var i: usize = 0;
    while (windows.next()) |window| {
        for (window, 0..) |b, n| {
            blocks[n][i] = b;
        }
        i += 1;
    }

    var dataBlocks = try allocator.alloc(Data, keysize);
    errdefer allocator.free(dataBlocks);
    for (0..keysize) |n| {
        dataBlocks[n] = Data.init(allocator, blocks[n]);
    }

    return dataBlocks;
}

fn guessKeysize(data: Data) u32 {
    const allocator = data.allocator;

    var bestScore: u32 = std.math.maxInt(i32);
    var bestKeysize: u32 = 0;

    for (2..40) |size| {
        var sizeScore: u32 = 0;
        var n: u32 = 0;

        const windows = std.mem.window(u8, data.bytes, size, size);
        var prev: ?[]const u8 = null;

        while (windows.next()) |current| {
            if (prev) |previous| {
                const lhs = Data.init(allocator, previous);
                const rhs = Data.init(allocator, current);
                sizeScore += lhs.hammingDistance(rhs) * 100 / size;
                n += 1;
            }
            prev = current;
        }

        sizeScore /= n;

        if (sizeScore < bestScore) {
            bestScore = sizeScore;
            bestKeysize = size;
        }
    }

    return bestKeysize;
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

test "set 1 challenge 4" {
    if (@import("config").slow < 4) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    const text = @embedFile("../data/4.txt");
    var iter = std.mem.splitScalar(u8, text, '\n');

    var bestGuess: ?Data = null;
    var bestScore: i32 = std.math.minInt(i32);
    var bestKey: u8 = undefined;

    defer bestGuess.?.deinit();

    while (iter.next()) |str| {
        var guess = try Data.fromHex(allocator, str);
        errdefer guess.deinit();
        const key = try singleCharacterXOR(&guess);
        const guessScore = score(guess);
        if (guessScore > bestScore) {
            if (bestGuess) |g| {
                g.deinit();
            }
            bestGuess = guess;
            bestScore = guessScore;
            bestKey = key;
        } else {
            guess.deinit();
        }
    }

    try std.testing.expectEqual('5', bestKey);
    try std.testing.expectEqualStrings("Now that the party is jumping\n", bestGuess.?.bytes);
}
