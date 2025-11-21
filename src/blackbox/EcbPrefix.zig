const std = @import("std");
const Allocator = std.mem.Allocator;

const Data = @import("../Data.zig");
const AesEcb = @import("../cipher/AesEcb.zig");
const block = @import("../attack/block.zig");
const determineMode = @import("ecbOrCbc.zig").determineMode;

const Self = @This();

const unknownStr = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

cipher: AesEcb,
allocator: Allocator,
unknown: []const u8,

pub fn init(allocator: Allocator) !Self {
    var rand = std.Random.DefaultPrng.init(std.crypto.random.int(u64));
    var key: [16]u8 = undefined;
    rand.fill(&key);

    const data = try Data.fromBase64(allocator, unknownStr);

    return Self{
        .cipher = .{ .key = key },
        .allocator = allocator,
        .unknown = data.bytes,
    };
}

pub fn process(self: Self, data: *Data) !void {
    const allocator = self.allocator;

    var buf = try allocator.alloc(u8, data.len() + self.unknown.len);
    errdefer allocator.free(buf);

    @memcpy(buf[0..data.len()], data.bytes);
    @memcpy(buf[data.len()..], self.unknown);

    data.reinit(buf);
    try data.encode(self.cipher);
}

pub fn deinit(self: Self) void {
    self.allocator.free(self.unknown);
}

pub fn extractSuffix(allocator: Allocator, blackbox: anytype) !Data {
    const mode = try determineMode(allocator, blackbox);
    if (mode != .Ecb) {
        return error.BlackboxNotEcb;
    }

    const sizes = try block.calculateSizes(allocator, blackbox);

    const bytesUntilNextBlock = sizes.blocksize - (sizes.len % sizes.blocksize);
    const bufferSize = sizes.len + bytesUntilNextBlock;

    var res = try allocator.alloc(u8, sizes.len);
    errdefer allocator.free(res);

    var buffer = try allocator.alloc(u8, bufferSize);
    defer allocator.free(buffer);

    const targetIndex = buffer.len - sizes.blocksize;
    const a = targetIndex;
    const b = a + sizes.blocksize;

    @memset(buffer[0..], 'A');

    outer: for (0..sizes.len) |i| {
        var target = try Data.copy(allocator, buffer[0 .. buffer.len - i - 1]);
        defer target.deinit();
        try target.process(blackbox);

        for (0..std.math.maxInt(u8)) |n| {
            const c: u8 = @intCast(n);
            buffer[buffer.len - 1] = c;
            var data = try Data.copy(allocator, buffer);
            defer data.deinit();
            try data.process(blackbox);

            if (std.mem.eql(u8, target.bytes[a..b], data.bytes[a..b])) {
                res[i] = c;
                @memmove(buffer[0 .. buffer.len - 1], buffer[1..]);
                continue :outer;
            }
        }

        unreachable;
    }

    return Data.init(allocator, res);
}

test "set 2 challenge 12" {
    if (@import("config").slow < 1) {
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;

    var blackbox = try Self.init(allocator);
    defer blackbox.deinit();

    const suffix = try extractSuffix(allocator, blackbox);
    defer suffix.deinit();

    try std.testing.expectEqualStrings(
        "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just ",
        suffix.bytes,
    );
}
