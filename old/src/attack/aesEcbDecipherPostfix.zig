const std = @import("std");
const blackboxLib = @import("../blackbox.zig");
const Data = @import("../Data.zig");
const aes = @import("aes.zig");

const Allocator = std.mem.Allocator;
const Encrypter = blackboxLib.Encrypter;

pub fn aesEcbDecipherPostfix(allocator: Allocator, blackbox: Encrypter) !Data {
    const block_size = try aes.ecb.findBlockSize(allocator, blackbox);
    const prefix_len = try aes.ecb.getPrefixLen(allocator, blackbox, block_size);
    const ciphertext_len = try aes.ecb.getPostfixLen(allocator, blackbox, block_size, prefix_len);
    const buf_len = aes.ecb.paddingToNextBlock(prefix_len, block_size) + aes.ecb.alignToNextBlock(ciphertext_len, block_size);

    var res = try allocator.alloc(u8, ciphertext_len);

    var buf = try allocator.alloc(u8, buf_len);
    defer allocator.free(buf);
    @memset(buf, 'A');

    const b = aes.ecb.alignToNextBlock(prefix_len, block_size) + aes.ecb.alignToNextBlock(ciphertext_len, block_size);
    const a = b - block_size;

    outer: for (0..ciphertext_len) |i| {
        var target = try Data.copy(allocator, buf[0 .. buf.len - i - 1]);
        defer target.deinit();
        try blackbox.encrypt(&target);
        const target_window = target.buf[a..b];

        std.mem.copyForwards(u8, buf[buf.len - i - 1 .. buf.len - 1], buf[buf.len - i ..]);
        for (0..std.math.maxInt(u8)) |n| {
            const c: u8 = @intCast(n);

            buf[buf.len - 1] = c;
            var guess = try Data.copy(allocator, buf);
            defer guess.deinit();
            try blackbox.encrypt(&guess);

            const guess_window = guess.buf[a..b];
            if (std.mem.eql(u8, guess_window, target_window)) {
                res[i] = c;
                continue :outer;
            }
        }

        unreachable;
    }

    return Data.init(allocator, res);
}