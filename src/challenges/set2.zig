const std = @import("std");
const config = @import("config");
const cryptopals = @import("cryptopals");

const AesEcbOrCbc = @import("set2/AesEcbOrCbc.zig");
const AesPrefix = @import("set2/AesPrefix.zig");
const AesProfile = @import("set2/AesProfile.zig");
const Profile = @import("set2/Profile.zig");

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

test "challenge 13" {
    var blackbox = try AesProfile.withKey("YELLOW SUBMARINE".*);

    const bytes_until_next_block = blk: {
        var zero = try Data.new(allocator, "");
        defer zero.deinit();
        try blackbox.encrypt(&zero);
        const zero_len = zero.buf.len;

        inline for (1..16) |i| {
            const payload = "A" ** i;
            var data = try Data.new(allocator, payload);
            defer data.deinit();
            try blackbox.encrypt(&data);
            if (data.buf.len != zero_len) {
                break :blk i;
            }
        }
        unreachable;
    };

    const email_index = blk: {
        const payload = try allocator.alloc(u8, bytes_until_next_block + 32);
        @memset(payload, 'A');

        var data = Data.init(allocator, payload);
        defer data.deinit();
        try blackbox.encrypt(&data);

        for (0..(data.buf.len - 1) / 16) |i| {
            const a = i * 16;
            const b = a + 16;
            const c = b + 16;
            if (std.mem.eql(u8, data.buf[a..b], data.buf[b..c])) {
                break :blk i * 16;
            }
        }
        unreachable;
    };

    var buf = try allocator.alloc(u8, bytes_until_next_block + 16);
    if (bytes_until_next_block > 0) {
        @memset(buf[0..bytes_until_next_block], 'A');
    }
    const admin_payload = "admin";
    _ = try std.fmt.bufPrint(buf[bytes_until_next_block..], "{s}", .{admin_payload});
    @memset(buf[bytes_until_next_block + admin_payload.len ..], 16 - admin_payload.len);

    var data = Data.init(allocator, buf);
    defer data.deinit();
    try blackbox.encrypt(&data);
    const admin_ciphertext = data.buf[email_index .. email_index + 16];

    const final_buf = try allocator.alloc(u8, bytes_until_next_block + 3);
    @memset(final_buf, 'A');

    var final = Data.init(allocator, final_buf);
    defer final.deinit();

    try blackbox.encrypt(&final);

    const tampered_buf = try allocator.alloc(u8, final.buf.len);
    @memcpy(tampered_buf[0 .. tampered_buf.len - 16], final.buf[0 .. final.buf.len - 16]);
    @memcpy(tampered_buf[tampered_buf.len - 16 ..], admin_ciphertext);
    final.reinit(tampered_buf);

    try blackbox.decrypt(&final);
    try final.unpad();

    const profile = try Profile.new(allocator, final.buf);
    defer profile.deinit();

    try std.testing.expectEqualStrings("admin", profile.role);
}
