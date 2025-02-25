const std = @import("std");
const blackboxLib = @import("../blackbox.zig");
const Data = @import("../Data.zig");

const Encrypter = blackboxLib.Encrypter;
const Allocator = std.mem.Allocator;

pub const ecb = struct {
    pub fn findBlockSize(allocator: Allocator, blackbox: Encrypter) !u32 {
        const lower = 16;
        const upper = 32;

        const payload = "AA" ** (upper * 2);
        var data = try Data.new(allocator, payload);
        defer data.deinit();
        try blackbox.encrypt(&data);

        for (lower..upper) |i| {
            var windows = std.mem.window(u8, data.buf, i, i);
            var prev: ?[]const u8 = null;

            while (windows.next()) |window| {
                if (prev) |prev_block| {
                    if (std.mem.eql(u8, window, prev_block)) {
                        return @intCast(i);
                    }
                }
                prev = window;
            }

            prev = null;
        }

        std.debug.panic("Could not find block size between {} and {}.", .{ lower, upper });
    }

    pub fn getPrefixLen(allocator: Allocator, blackbox: Encrypter, block_size: u32) !u32 {
        for (0..block_size) |i| {
            const empty_bytes_guess: u32 = @intCast(i);
            const payload = try allocator.alloc(u8, block_size * 2 + empty_bytes_guess);
            @memset(payload, 'A');

            var data = Data.init(allocator, payload);
            defer data.deinit();
            try blackbox.encrypt(&data);

            var windows = std.mem.window(u8, data.buf, block_size, block_size);
            var prev: ?[]const u8 = null;

            var idx: u32 = 0;
            while (windows.next()) |window| {
                if (prev) |prev_block| {
                    if (std.mem.eql(u8, window, prev_block)) {
                        return (idx - 1) * block_size - empty_bytes_guess;
                    }
                }
                idx += 1;
                prev = window;
            }
        }

        unreachable;
    }

    pub fn getPostfixLen(allocator: Allocator, blackbox: Encrypter, block_size: u32, prefix_len: u32) !u32 {
        const prefix_padding = paddingToNextBlock(prefix_len, block_size);
        const aligned_zero_buf = try allocator.alloc(u8, prefix_padding);
        @memset(aligned_zero_buf, 'A');
        var aligned_zero = Data.init(allocator, aligned_zero_buf);
        defer aligned_zero.deinit();
        try blackbox.encrypt(&aligned_zero);
        const aligned_zero_len = aligned_zero.len;

        for (1..block_size + 1) |i| {
            const empty_bytes_guess: u32 = @intCast(i);
            const payload = try allocator.alloc(u8, prefix_padding + i);
            @memset(payload, 'A');
            var data = Data.init(allocator, payload);
            defer data.deinit();

            try blackbox.encrypt(&data);
            if (data.len != aligned_zero_len) {
                return aligned_zero_len - prefix_len - prefix_padding - empty_bytes_guess;
            }
        }

        unreachable;
    }

    pub fn paddingToNextBlock(n: i33, block_size: i33) u32 {
        const val = @mod(block_size - n, block_size);
        return @intCast(val);
    }

    pub fn alignToNextBlock(n: u32, block_size: u32) u32 {
        return n + paddingToNextBlock(n, block_size);
    }
};
