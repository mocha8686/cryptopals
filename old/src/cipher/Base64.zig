const std = @import("std");

const Data = @import("../Data.zig");

const Self = @This();

pub fn decode(_: Self, data: *Data) !void {
    const res = try Data.fromBase64(data.allocator, data.bytes);
    data.reinit(res.bytes);
}

pub fn encode(_: Self, data: *Data) !void {
    const allocator = data.allocator;

    const encoder = std.base64.standard.Encoder;
    const size = encoder.calcSize(data.len());

    const buf = try allocator.alloc(u8, size);
    errdefer allocator.free(buf);

    _ = encoder.encode(buf, data.bytes);

    data.reinit(buf);
}

test "it works" {
    const allocator = std.testing.allocator;

    var data = try Data.copy(allocator, "hello, world!");
    defer data.deinit();

    const cipher = Self{};
    try data.encode(cipher);
    try data.decode(cipher);

    try std.testing.expectEqualStrings(
        "hello, world!",
        data.bytes,
    );
}
