const std = @import("std");
const Data = @import("../Data.zig");
const score = @import("score.zig").score;
const hammingDistance = @import("../hammingDistance.zig").hammingDistance;

pub fn singleCharacterXOR(data: *Data) !u8 {
    var bestScore: i32 = std.math.minInt(i32);
    var bestChar: u8 = 0;

    for (0..std.math.maxInt(u8)) |n| {
        const c: u8 = @intCast(n);

        try data.xor(&.{c});

        const guessScore = score(data.bytes);
        if (guessScore > bestScore) {
            bestScore = guessScore;
            bestChar = c;
        }

        try data.xor(&.{c});
    }

    try data.xor(&.{bestChar});
    return bestChar;
}

pub fn repeatingKeyXOR(data: *Data) !Data {
    const allocator = data.allocator;

    const keysize = guessKeysize(data.bytes);
    var key = try allocator.alloc(u8, keysize);
    errdefer allocator.free(key);

    var blocks = try partition(data.*, keysize);
    defer allocator.free(blocks);

    for (0..keysize) |n| {
        key[n] = try singleCharacterXOR(&blocks[n]);
    }

    const buf = try unpartition(allocator, blocks, keysize, data.len());
    data.reinit(buf);
    return Data.init(allocator, key);
}

fn unpartition(allocator: std.mem.Allocator, blocks: []Data, keysize: u32, len: usize) ![]u8 {
    var buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);

    for (blocks, 0..) |block, i| {
        defer block.deinit();
        for (block.bytes, 0..) |b, n| {
            buf[keysize * n + i] = b;
        }
    }

    return buf;
}

fn partition(data: Data, keysize: u32) ![]Data {
    const allocator = data.allocator;
    const lengthPerBlock = data.len() / keysize;
    const remainder = data.len() % keysize;

    var blocks = try allocator.alloc([]u8, keysize);
    defer allocator.free(blocks);

    for (0..keysize) |n| {
        const blockLength = lengthPerBlock + (if (n < remainder) @as(usize, 1) else @as(usize, 0));
        blocks[n] = try allocator.alloc(u8, blockLength);
        errdefer allocator.free(blocks[n]);
    }

    var windows = std.mem.window(u8, data.bytes, keysize, keysize);
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

fn guessKeysize(bytes: []const u8) u32 {
    var bestScore: u32 = std.math.maxInt(i32);
    var bestKeysize: u32 = 0;

    for (2..41) |keysize| {
        var sizeScore: u32 = 0;
        var n: u32 = 0;

        var windows = std.mem.window(u8, bytes, keysize, keysize);
        var prev: ?[]const u8 = null;

        while (windows.next()) |current| {
            if (prev) |previous| {
                if (previous.len != current.len) break;
                sizeScore += hammingDistance(previous, current);
                n += 1;
            }
            prev = current;
        }

        sizeScore *= 100;
        sizeScore /= n * @as(u32, @intCast(keysize));

        if (sizeScore < bestScore) {
            bestScore = sizeScore;
            bestKeysize = @as(u32, @intCast(keysize));
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

test "partition and unpartition" {
    const allocator = std.testing.allocator;
    const keysize = 20;
    const str = "hello, world! how are you today? i'm doing quite fine myself.";

    var data = try Data.copy(allocator, str);
    defer data.deinit();

    const blocks = try partition(data, keysize);
    defer allocator.free(blocks);

    const buf = try unpartition(allocator, blocks, keysize, data.len());
    data.reinit(buf);

    try std.testing.expectEqualStrings(str, data.bytes);
}

test "set 1 challenge 6" {
    if (@import("config").slow < 2) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    const text = @embedFile("../data/6.txt");
    const size = std.mem.replacementSize(u8, text, "\n", "");
    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    _ = std.mem.replace(u8, text, "\n", "", buf);

    var data = try Data.fromBase64(allocator, buf);
    defer data.deinit();

    const key = try repeatingKeyXOR(&data);
    defer key.deinit();

    try std.testing.expectEqualStrings("Terminator X: Bring the noise", key.bytes);
    try std.testing.expectEqualStrings(
        @embedFile("../data/funky.txt"),
        data.bytes,
    );
}
