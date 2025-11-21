const std = @import("std");
const Allocator = std.mem.Allocator;

const AesEcb = @import("../cipher/AesEcb.zig");
const AesCbc = @import("../cipher/AesCbc.zig");
const Data = @import("../Data.zig");

const Self = @This();

pub const Mode = enum {
    Ecb,
    Cbc,
};

key: [16]u8,
rand: std.Random,
mode: ?Mode = null,

pub fn init(mode: ?Mode) Self {
    var rand = std.Random.DefaultPrng.init(std.crypto.random.int(u64));
    var key: [16]u8 = undefined;
    rand.fill(&key);

    return Self{
        .key = key,
        .rand = rand.random(),
        .mode = mode,
    };
}

pub fn process(self: Self, data: *Data) !void {
    const allocator = data.allocator;

    const prefixLength = self.rand.intRangeAtMost(u8, 5, 10);
    const postfixLength = self.rand.intRangeAtMost(u8, 5, 10);

    var res = try allocator.alloc(u8, prefixLength + data.len() + postfixLength);
    errdefer allocator.free(res);

    self.rand.bytes(res);
    @memcpy(res[prefixLength .. prefixLength + data.len()], data.bytes);

    data.reinit(res);

    const useEcb = if (self.mode) |mode| switch (mode) {
        .Ecb => true,
        .Cbc => false,
    } else self.rand.boolean();

    if (useEcb) {
        const cipher = AesEcb{ .key = self.key };
        try data.encode(cipher);
    } else {
        var iv: [16]u8 = undefined;
        self.rand.bytes(&iv);
        const cipher = AesCbc{ .key = self.key, .iv = iv };
        try data.encode(cipher);
    }
}

pub fn determineMode(allocator: Allocator, blackbox: anytype) !Mode {
    const blocksize = 16;

    var buf: [blocksize * 3]u8 = undefined;
    @memset(&buf, 'A');

    var data = try Data.copy(allocator, &buf);
    defer data.deinit();

    try data.process(blackbox);

    var windows = std.mem.window(u8, data.bytes, blocksize, blocksize);
    var previous: []const u8 = windows.first();

    while (windows.next()) |current| {
        if (std.mem.eql(u8, previous, current)) return .Ecb;
        previous = current;
    }

    return .Cbc;
}

test "set 2 challenge 11" {
    const allocator = std.testing.allocator;

    {
        const mode = .Ecb;
        const blackbox = Self.init(mode);
        const res = determineMode(allocator, blackbox);
        try std.testing.expectEqual(mode, res);
    }

    {
        const mode = .Cbc;
        const blackbox = Self.init(mode);
        const res = determineMode(allocator, blackbox);
        try std.testing.expectEqual(mode, res);
    }
}

test "set 2 challenge 11 [x100]" {
    const allocator = std.testing.allocator;

    for (0..100) |_| {
        const mode = .Ecb;
        const blackbox = Self.init(mode);
        const res = determineMode(allocator, blackbox);
        try std.testing.expectEqual(mode, res);
    }

    for (0..100) |_| {
        const mode = .Cbc;
        const blackbox = Self.init(mode);
        const res = determineMode(allocator, blackbox);
        try std.testing.expectEqual(mode, res);
    }
}
