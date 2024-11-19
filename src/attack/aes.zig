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

    pub fn findBytesUntilNextBlock(allocator: Allocator, blackbox: Encrypter, block_size: usize) !usize {
        var zero = try Data.new(allocator, "");
        defer zero.deinit();
        try blackbox.encrypt(&zero);
        const zero_len = zero.buf.len;

        for (1..block_size) |i| {
            const buf = try allocator.alloc(u8, i);
            @memset(buf, 'A');
            var data = Data.init(allocator, buf);
            defer data.deinit();

            try blackbox.encrypt(&data);
            if (data.buf.len != zero_len) {
                return i;
            }
        }

        unreachable;
    }

    pub fn findFirstControllableBlockIndex(allocator: Allocator, blackbox: Encrypter, bytes_until_next_block: usize, block_size: usize) !usize {
        const payload = try allocator.alloc(u8, bytes_until_next_block + block_size * 2);
        @memset(payload, 'A');

        var data = Data.init(allocator, payload);
        defer data.deinit();
        try blackbox.encrypt(&data);

        var windows = std.mem.window(u8, data.buf, block_size, block_size);
        var prev: ?[]const u8 = null;
        var i: usize = 0;

        while (windows.next()) |window| {
            if (prev) |prev_block| {
                if (std.mem.eql(u8, window, prev_block)) {
                    return (i - 1) * 16;
                }
            }
            prev = window;
            i += 1;
        }

        unreachable;
    }
};
