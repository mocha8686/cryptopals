const std = @import("std");
const Data = @import("../Data.zig");
const Self = @This();

pub fn decode(_: Self, data: *Data) !void {
    const allocator = data.allocator;

    const buf = try allocator.alloc(u8, data.bytes.len / 2);
    errdefer allocator.free(buf);

    _ = try std.fmt.hexToBytes(buf, data.bytes);

    data.reinit(buf);
}

pub fn encode(_: Self, data: *Data) !void {
    const allocator = data.allocator;

    const buf = try allocator.alloc(u8, data.bytes.len * 2);
    errdefer allocator.free(buf);

    _ = try std.fmt.bufPrint(buf, "{x}", .{data.bytes});

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
