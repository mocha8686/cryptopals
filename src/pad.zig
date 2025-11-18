const std = @import("std");
const Data = @import("Data.zig");

pub fn pad(data: *Data, blocksize: u32) !void {
    const allocator = data.allocator;
    const len = data.len();

    const byte: u8 = @as(u8, @intCast(@mod((len % blocksize) - 1, blocksize)));
    var buf = try allocator.alloc(u8, len + byte);
    @memcpy(buf, data.bytes);
    @memset(buf[len..], byte);
    data.reinit(buf);
}

pub fn unpad(data: *Data) !void {
    const allocator = data.allocator;
    const len = data.len();

    const byte = data.bytes[len - 1];
    if (!std.mem.allEqual(u8, data.bytes[len - byte ..], byte)) {
        return error.InvalidPadding;
    }

    const buf = try allocator.alloc(u8, len);
    @memcpy(buf, data.bytes);
    data.reinit(buf);
}
