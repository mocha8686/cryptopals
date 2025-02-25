const std = @import("std");
const blackboxLib = @import("../blackbox.zig");
const Data = @import("../Data.zig");

const Allocator = std.mem.Allocator;
const Encrypter = blackboxLib.Encrypter;

pub fn aesCbcBitflip(allocator: Allocator, blackbox: Encrypter) !Data {
    var data = try Data.copy(allocator, "A" ** 64);
    errdefer data.deinit();
    try blackbox.encrypt(&data);

    var payload = try Data.copy(allocator, "A");
    defer payload.deinit();
    try payload.xorBytes(";admin=true;");

    const index = 48;
    var buf = try allocator.alloc(u8, data.len);
    defer allocator.free(buf);
    @memset(buf, 0);
    @memcpy(buf[index .. index + payload.len], payload.buf);

    try data.xorBytes(buf);

    return data;
}
