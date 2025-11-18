const std = @import("std");
const Data = @import("../Data.zig");

const Self = @This();

fn Key(blocksize: comptime_int) type {
    return [blocksize / 8]u8;
}

pub const Mode = union(enum) {
    ECB: struct { key: Key(128) },
};

mode: Mode,

pub fn decode(self: Self, data: *Data) !void {
    switch (self.mode) {
        .ECB => |c| try decodeECB(data, c.key),
    }
}

pub fn encode(self: Self, data: *Data) !void {
    switch (self.mode) {
        .ECB => |c| try encodeECB(data, c.key),
    }
}

fn decodeECB(data: *Data, key: Key(128)) !void {
    const allocator = data.allocator;
    const blocksize = 16;

    const aes = std.crypto.core.aes.Aes128.initDec(key);
    var res = try allocator.alloc(u8, data.len());

    var windows = std.mem.window(u8, data.bytes, blocksize, blocksize);
    var i: u32 = 0;
    while (windows.next()) |block| {
        aes.decrypt(res[i * blocksize .. (i + 1) * blocksize][0..blocksize], block[0..blocksize]);
        i += 1;
    }

    data.reinit(res);
    try data.unpad();
}

fn encodeECB(data: *Data, key: Key(128)) !void {
    const allocator = data.allocator;
    const blocksize = 16;

    try data.pad(blocksize);

    const aes = std.crypto.core.aes.Aes128.initEnc(key);
    var res = try allocator.alloc(u8, data.len());

    var windows = std.mem.window(u8, data.bytes, blocksize, blocksize);
    var i: u32 = 0;
    while (windows.next()) |block| {
        aes.encrypt(res[i * blocksize .. (i + 1) * blocksize][0..blocksize], block[0..blocksize]);
        i += 1;
    }

    data.reinit(res);
}
