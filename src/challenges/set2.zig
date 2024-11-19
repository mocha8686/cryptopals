const std = @import("std");
const config = @import("config");
const cryptopals = @import("cryptopals");

const AesEcbOrCbc = @import("set2/AesEcbOrCbc.zig");
const AesPrefix = @import("set2/AesPrefix.zig");

const allocator = std.testing.allocator;

const Data = cryptopals.Data;
const oracle = cryptopals.oracle;

test "challenge 9" {
    var data = try Data.new(allocator, "YELLOW SUBMARINE");
    defer data.deinit();

    try data.pad(20);
    try std.testing.expectEqualStrings("YELLOW SUBMARINE\x04\x04\x04\x04", data.buf);
}

test "challenge 10" {
    const challenge_text = @embedFile("data/2/10.txt");
    const ciphertext = try std.mem.replaceOwned(u8, allocator, challenge_text, "\n", "");
    defer allocator.free(ciphertext);

    var data = try Data.fromBase64(allocator, ciphertext);
    defer data.deinit();

    try data.decrypt(.{ .aes_128_cbc = .{ .key = "YELLOW SUBMARINE".*, .iv = "\x00".* ** 16 } });

    try std.testing.expectEqualStrings(@embedFile("data/2/10-sol.txt"), data.buf);
}

test "challenge 11" {
    const plaintext = @embedFile("data/funky.txt");

    var ecb = try AesEcbOrCbc.init(.ecb);
    for (0..10) |_| {
        var data = try Data.new(allocator, plaintext);
        defer data.deinit();
        try ecb.encrypt(&data);

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.ecb, res);
    }

    var cbc = try AesEcbOrCbc.init(.cbc);
    for (0..10) |_| {
        var data = try Data.new(allocator, plaintext);
        defer data.deinit();
        try cbc.encrypt(&data);

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.cbc, res);
    }
}

test "[S1] challenge 11 x100" {
    if (config.slow < 1) return;

    const plaintext = @embedFile("data/funky.txt");

    var ecb = try AesEcbOrCbc.init(.ecb);
    for (0..100) |_| {
        var data = try Data.new(allocator, plaintext);
        defer data.deinit();
        try ecb.encrypt(&data);

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.ecb, res);
    }

    var cbc = try AesEcbOrCbc.init(.cbc);
    for (0..100) |_| {
        var data = try Data.new(allocator, plaintext);
        defer data.deinit();
        try cbc.encrypt(&data);

        const res = try oracle.aesOracle(data);
        try std.testing.expectEqual(.cbc, res);
    }
}

test "challenge 12" {
    const prefix_blackbox = try AesPrefix.new();

    const block_size = blk: {
        inline for (1..64) |i| {
            const payload = "AA" ** i;
            var data = try Data.new(allocator, payload);
            defer data.deinit();
            try prefix_blackbox.encrypt(&data);
            if (std.mem.eql(u8, data.buf[0..i], data.buf[i .. i * 2])) break :blk i;
        }
        std.debug.panic("Could not find block size between 0 and 64.", .{});
    };

    try std.testing.expectEqual(16, block_size);

    const info = blk: {
        var empty = try Data.new(allocator, "");
        defer empty.deinit();
        try prefix_blackbox.encrypt(&empty);
        const next_block_len = empty.buf.len;

        for (1..block_size + 1) |i| {
            var payload = try allocator.alloc(u8, i);
            defer allocator.free(payload);
            @memset(payload[0..], 'A');

            var data = try Data.new(allocator, payload);
            defer data.deinit();
            try prefix_blackbox.encrypt(&data);
            if (data.buf.len != next_block_len) {
                break :blk .{
                    .next_block_len = next_block_len,
                    .ciphertext_len = next_block_len - i,
                };
            }
        }
        unreachable;
    };
    const next_block_len = info.next_block_len;
    const ciphertext_len = info.ciphertext_len;

    var res = try allocator.alloc(u8, ciphertext_len);
    defer allocator.free(res);

    var buf = try allocator.alloc(u8, next_block_len);
    defer allocator.free(buf);
    @memset(buf, 'A');

    const b = ciphertext_len;
    const a = b - block_size;

    outer: for (0..ciphertext_len) |i| {
        var data = try Data.new(allocator, buf[0 .. buf.len - i - 1]);
        defer data.deinit();
        try prefix_blackbox.encrypt(&data);
        const target = data.buf[a..b];

        std.mem.copyForwards(u8, buf[buf.len - i - 1 .. buf.len - 1], buf[buf.len - i ..]);
        for (0..std.math.maxInt(u8)) |n| {
            const c: u8 = @intCast(n);

            buf[buf.len - 1] = c;
            var guess = try Data.new(allocator, buf);
            defer guess.deinit();
            try prefix_blackbox.encrypt(&guess);

            if (std.mem.eql(u8, guess.buf[a..b], target)) {
                res[i] = c;
                continue :outer;
            }
        }
        unreachable;
    }

    try std.testing.expectEqualStrings(
        @embedFile("data/2/12-sol.txt"),
        res,
    );
}
