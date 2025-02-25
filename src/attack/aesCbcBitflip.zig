const std = @import("std");
const blackboxLib = @import("../blackbox.zig");
const Data = @import("../Data.zig");

const Allocator = std.mem.Allocator;
const Encrypter = blackboxLib.Encrypter;

pub fn aesCbcBitflip(allocator: Allocator, blackbox: Encrypter) !Data {
    const block_size = 16;
    const offset = 3;

    var data = try Data.copy(allocator, "A" ** (block_size * 4));
    errdefer data.deinit();
    try blackbox.encrypt(&data);

    var payload = try Data.copy(allocator, "A");
    defer payload.deinit();
    try payload.xorBytes(";admin=true;");

    const index = block_size * offset;
    var buf = try allocator.alloc(u8, data.len);
    defer allocator.free(buf);
    @memset(buf, 0);
    @memcpy(buf[index .. index + payload.len], payload.buf);

    try data.xorBytes(buf);

    return data;
}
