const std = @import("std");
const Allocator = std.mem.Allocator;

const Data = @import("../Data.zig");

pub const Sizes = struct {
    blocksize: usize,
    len: usize,
};

pub fn calculateSizes(allocator: Allocator, blackbox: anytype) !Sizes {
    const zeroLen = try calculateZeroLen(allocator, blackbox);
    return calculateSizesWithZeroLen(allocator, blackbox, zeroLen);
}

pub fn calculateSizesWithZeroLen(allocator: Allocator, blackbox: anytype, zeroLen: usize) !Sizes {
    for (1..std.math.maxInt(usize)) |blocksize| {
        var buf = try allocator.alloc(u8, blocksize);
        errdefer allocator.free(buf);
        @memset(buf[0..], 'A');

        var data = Data.init(allocator, buf);
        defer data.deinit();

        try data.process(blackbox);

        const guess = data.len() - zeroLen;
        if (guess > 0) {
            return Sizes{
                .blocksize = guess,
                .len = zeroLen + 1 - guess,
            };
        }
    }

    return error.BlocksizeNotFound;
}

pub fn calculateZeroLen(allocator: Allocator, blackbox: anytype) !usize {
    var data = try Data.copy(allocator, "");
    defer data.deinit();
    try data.process(blackbox);
    return data.len();
}
