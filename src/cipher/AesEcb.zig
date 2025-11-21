const std = @import("std");
const Data = @import("../Data.zig");

const Self = @This();

key: [16]u8,

pub fn decode(self: Self, data: *Data) !void {
    const allocator = data.allocator;
    const blocksize = 16;

    const aes = std.crypto.core.aes.Aes128.initDec(self.key);
    var res = try allocator.alloc(u8, data.len());

    var windows = std.mem.window(u8, data.bytes, blocksize, blocksize);
    var i: u32 = 0;
    while (windows.next()) |block| {
        aes.decrypt(res[i * blocksize .. (i + 1) * blocksize][0..blocksize], block[0..blocksize]);
        i += 1;
    }

    data.reinit(res);
    try data.unpad();
}

pub fn encode(self: Self, data: *Data) !void {
    const allocator = data.allocator;
    const blocksize = 16;

    try data.pad(blocksize);

    const aes = std.crypto.core.aes.Aes128.initEnc(self.key);
    var res = try allocator.alloc(u8, data.len());

    var windows = std.mem.window(u8, data.bytes, blocksize, blocksize);
    var i: u32 = 0;
    while (windows.next()) |block| {
        aes.encrypt(res[i * blocksize .. (i + 1) * blocksize][0..blocksize], block[0..blocksize]);
        i += 1;
    }

    data.reinit(res);
}

test "set 1 challenge 7" {
    const allocator = std.testing.allocator;

    const text = @embedFile("../data/7.txt");
    const size = std.mem.replacementSize(u8, text, "\n", "");
    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    _ = std.mem.replace(u8, text, "\n", "", buf);

    var data = try Data.fromBase64(allocator, buf);
    defer data.deinit();

    const AES = Self{ .key = "YELLOW SUBMARINE".* };
    try data.decode(AES);

    try std.testing.expectEqualStrings(@embedFile("../data/funky.txt"), data.bytes);
}

test "set 1 challenge 8" {
    const allocator = std.testing.allocator;
    const Chunks = std.ArrayList([]const u8);

    const text = @embedFile("../data/8.txt");

    var lines = std.mem.splitScalar(u8, text, '\n');
    var bestGuess: ?[]const u8 = null;
    var bestScore: u32 = std.math.minInt(u32);

    while (lines.next()) |str| {
        var windows = std.mem.window(u8, str, 16, 16);
        var chunks = try Chunks.initCapacity(allocator, (str.len / 16) + 1);
        defer chunks.deinit(allocator);
        var score: u32 = 0;

        while (windows.next()) |current| {
            for (chunks.items) |target| {
                if (std.mem.eql(u8, current, target)) {
                    score += 1;
                }
            }
            try chunks.append(allocator, current);
        }

        if (score > bestScore) {
            bestGuess = str;
            bestScore = score;
        }
    }

    try std.testing.expectEqualStrings(
        "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
        bestGuess.?,
    );
}
