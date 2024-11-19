const std = @import("std");
const blackboxLib = @import("../blackbox.zig");
const Data = @import("../Data.zig");
const aes = @import("aes.zig");

const Allocator = std.mem.Allocator;
const Encrypter = blackboxLib.Encrypter;

pub fn aesEcbPrefix(allocator: Allocator, blackbox: Encrypter) !Data {
    const block_size = try aes.ecb.findBlockSize(allocator, blackbox);
    const next_block_len = try getNextBlockLen(allocator, blackbox);
    const ciphertext_len = try getCiphertextLen(allocator, blackbox, block_size, next_block_len);

    var res = try allocator.alloc(u8, ciphertext_len);

    var buf = try allocator.alloc(u8, next_block_len);
    defer allocator.free(buf);
    @memset(buf, 'A');

    const b = ciphertext_len;
    const a = b - block_size;

    outer: for (0..ciphertext_len) |i| {
        var data = try Data.new(allocator, buf[0 .. buf.len - i - 1]);
        defer data.deinit();
        try blackbox.encrypt(&data);
        const target = data.buf[a..b];

        std.mem.copyForwards(u8, buf[buf.len - i - 1 .. buf.len - 1], buf[buf.len - i ..]);
        for (0..std.math.maxInt(u8)) |n| {
            const c: u8 = @intCast(n);

            buf[buf.len - 1] = c;
            var guess = try Data.new(allocator, buf);
            defer guess.deinit();
            try blackbox.encrypt(&guess);

            if (std.mem.eql(u8, guess.buf[a..b], target)) {
                res[i] = c;
                continue :outer;
            }
        }
        unreachable;
    }

    return Data.init(allocator, res);
}

fn getNextBlockLen(allocator: Allocator, blackbox: Encrypter) !usize {
    var zero = try Data.new(allocator, "");
    defer zero.deinit();
    try blackbox.encrypt(&zero);
    return zero.buf.len;
}

fn getCiphertextLen(allocator: Allocator, blackbox: Encrypter, block_size: usize, next_block_len: usize) !usize {
    for (1..block_size + 1) |i| {
        var payload = try allocator.alloc(u8, i);
        defer allocator.free(payload);
        @memset(payload[0..], 'A');

        var data = try Data.new(allocator, payload);
        defer data.deinit();
        try blackbox.encrypt(&data);
        if (data.buf.len != next_block_len) {
            return next_block_len - i;
        }
    }
    unreachable;
}
