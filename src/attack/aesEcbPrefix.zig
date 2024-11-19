const std = @import("std");
const Blackbox = @import("../Blackbox.zig");
const Data = @import("../Data.zig");

const Allocator = std.mem.Allocator;

pub fn aesEcbPrefix(allocator: Allocator, blackbox: Blackbox) !Data {
    const block_size = try findBlockSize(allocator, blackbox);
    const next_block_len, const ciphertext_len = try getCipherInfo(allocator, blackbox, block_size);

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

fn findBlockSize(allocator: Allocator, blackbox: Blackbox) !usize {
    inline for (1..64) |i| {
        const payload = "AA" ** i;
        var data = try Data.new(allocator, payload);
        defer data.deinit();
        try blackbox.encrypt(&data);
        if (std.mem.eql(u8, data.buf[0..i], data.buf[i .. i * 2])) return i;
    }
    std.debug.panic("Could not find block size between 0 and 64.", .{});
}

fn getCipherInfo(allocator: Allocator, blackbox: Blackbox, block_size: usize) !struct { usize, usize } {
    var empty = try Data.new(allocator, "");
    defer empty.deinit();
    try blackbox.encrypt(&empty);
    const next_block_len = empty.buf.len;

    for (1..block_size + 1) |i| {
        var payload = try allocator.alloc(u8, i);
        defer allocator.free(payload);
        @memset(payload[0..], 'A');

        var data = try Data.new(allocator, payload);
        defer data.deinit();
        try blackbox.encrypt(&data);
        if (data.buf.len != next_block_len) {
            return .{
                next_block_len,
                next_block_len - i,
            };
        }
    }
    unreachable;
}
