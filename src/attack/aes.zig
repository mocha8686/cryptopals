const std = @import("std");
const blackboxLib = @import("../blackbox.zig");
const Data = @import("../Data.zig");

const Encrypter = blackboxLib.Encrypter;
const Allocator = std.mem.Allocator;

pub const ecb = struct {
    pub fn findBlockSize(allocator: Allocator, blackbox: Encrypter) !usize {
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
                        return i;
                    }
                }
                prev = window;
            }

            prev = null;
        }

        std.debug.panic("Could not find block size between {} and {}.", .{ lower, upper });
    }

    pub fn getPrefixLen(allocator: Allocator, blackbox: Encrypter, block_size: usize) !usize {
        for (0..block_size) |i| {
            const payload = try allocator.alloc(u8, block_size * 2 + i);
            @memset(payload, 'A');

            var data = Data.init(allocator, payload);
            defer data.deinit();
            try blackbox.encrypt(&data);

            var windows = std.mem.window(u8, data.buf, block_size, block_size);
            var prev: ?[]const u8 = null;

            var idx: usize = 0;
            while (windows.next()) |window| {
                if (prev) |prev_block| {
                    if (std.mem.eql(u8, window, prev_block)) {
                        return (idx - 1) * block_size - i;
                    }
                }
                idx += 1;
                prev = window;
            }
        }

        unreachable;
    }

    pub fn getPostfixLen(allocator: Allocator, blackbox: Encrypter, block_size: usize, prefix_len: usize) !usize {
        const prefix_padding = paddingToNextBlock(prefix_len, block_size);
        const aligned_zero_buf = try allocator.alloc(u8, prefix_padding);
        @memset(aligned_zero_buf, 'A');
        var aligned_zero = Data.init(allocator, aligned_zero_buf);
        defer aligned_zero.deinit();
        try blackbox.encrypt(&aligned_zero);
        const aligned_zero_len = aligned_zero.buf.len;

        for (1..block_size + 1) |i| {
            const payload = try allocator.alloc(u8, prefix_padding + i);
            @memset(payload, 'A');
            var data = Data.init(allocator, payload);
            defer data.deinit();

            try blackbox.encrypt(&data);
            if (data.buf.len != aligned_zero_len) {
                return aligned_zero_len - prefix_len - prefix_padding - i;
            }
        }

        unreachable;
    }

    pub fn paddingToNextBlock(n: i65, block_size: i65) usize {
        const val = @mod(block_size - n, block_size);
        return @intCast(val);
    }

    pub fn alignToNextBlock(n: usize, block_size: usize) usize {
        return n + paddingToNextBlock(n, block_size);
    }
};
