const std = @import("std");
const Data = @import("Data.zig");

pub const aes = @import("cipher/aes.zig");

pub const Cipher = union(enum) {
    aes_128_ecb: struct {
        key: [16]u8,
    },
    aes_128_cbc: struct {
        key: [16]u8,
        iv: [16]u8,
    },
};

pub fn decrypt(data: *Data, cipher: Cipher) !void {
    try switch (cipher) {
        .aes_128_ecb => |*aes_info| aes.aes128EcbDecrypt(data, aes_info.key),
        .aes_128_cbc => |*aes_info| aes.aes128CbcDecrypt(data, aes_info.key, aes_info.iv),
    };
}

pub fn encrypt(data: *Data, cipher: Cipher) !void {
    try switch (cipher) {
        .aes_128_ecb => |*aes_info| aes.aes128EcbEncrypt(data, aes_info.key),
        .aes_128_cbc => |*aes_info| aes.aes128CbcEncrypt(data, aes_info.key, aes_info.iv),
    };
}

// PKCS#7 padding scheme.
pub fn pad(data: *Data, block_size: u8) !void {
    const len = data.buf.len;
    const padding_len: u8 = @intCast(block_size - len % block_size);
    if (padding_len == 0) return;

    const allocator = data.allocator;

    var buf = try allocator.alloc(u8, len + padding_len);
    @memcpy(buf[0..len], data.buf);
    @memset(buf[len..], padding_len);

    data.reinit(buf);
}

pub fn unpad(data: *Data) !void {
    const allocator = data.allocator;
    const len = data.buf.len;
    const last_byte = data.buf[len - 1];

    if (len < last_byte or !std.mem.allEqual(u8, data.buf[len - last_byte ..], last_byte)) {
        return error.InvalidPadding;
    }

    const buf = try allocator.alloc(u8, len - last_byte);
    @memcpy(buf, data.buf[0 .. len - last_byte]);
    data.reinit(buf);
}
