const std = @import("std");
const Data = @import("../Data.zig");
const AesEcb = @import("AesEcb.zig");

const Self = @This();

key: [16]u8,
iv: [16]u8,

pub fn decode(self: Self, data: *Data) !void {
    if (data.len() == 0) return;

    const allocator = data.allocator;
    const blocksize = 16;

    var xorTarget = try allocator.alloc(u8, data.len());
    defer allocator.free(xorTarget);
    @memcpy(xorTarget[0..blocksize], &self.iv);
    @memcpy(xorTarget[blocksize..], data.bytes[0..data.len() - blocksize]);

    const ecb = AesEcb{ .key = self.key, .pad = false };
    try data.decode(ecb);
    try data.xor(xorTarget);
    try data.unpad();
}

pub fn encode(self: Self, data: *Data) !void {
    if (data.len() == 0) return;

    const allocator = data.allocator;
    const blocksize = 16;

    try data.pad(blocksize);

    const ecb = AesEcb{ .key = self.key, .pad = false };

    var res = try allocator.alloc(u8, data.len());
    errdefer allocator.free(res);

    var prev: []const u8 = &self.iv;

    var windows = std.mem.window(u8, data.bytes, blocksize, blocksize);
    var i: u32 = 0;
    while (windows.next()) |block| {
        var dataBlock = try Data.copy(allocator, block);
        defer dataBlock.deinit();

        try dataBlock.xor(prev);
        try dataBlock.encode(ecb);
        @memcpy(res[i * blocksize..(i + 1) * blocksize], dataBlock.bytes);

        prev = block;
        i += 1;
    }

    data.reinit(res);
}

test "set 2 challenge 10" {
    const allocator = std.testing.allocator;

    const text = @embedFile("../data/10.txt");
    const size = std.mem.replacementSize(u8, text, "\n", "");
    const buf = try allocator.alloc(u8, size);
    defer allocator.free(buf);
    _ = std.mem.replace(u8, text, "\n", "", buf);

    var data = try Data.fromBase64(allocator, buf);
    defer data.deinit();

    var iv: [16]u8 = undefined;
    @memset(&iv, 0);

    const AES = Self{ .key = "YELLOW SUBMARINE".*, .iv = iv };
    try data.decode(AES);

    try std.testing.expectEqualStrings(@embedFile("../data/funky.txt"), data.bytes);
}
