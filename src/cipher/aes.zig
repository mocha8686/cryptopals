const std = @import("std");
const Data = @import("../Data.zig");

const aes = std.crypto.core.aes;

pub fn aes128EcbDecrypt(data: *Data, key: [16]u8) !void {
    const len = data.buf.len;
    if (len % 16 != 0) {
        return error.InvalidDataLength;
    }

    const allocator = data.allocator;
    const c = aes.Aes128.initDec(key);
    var res_buf = try allocator.alloc(u8, len);

    for (0..len / 16) |i| {
        const a = i * 16;
        const b = (i + 1) * 16;

        c.decrypt(res_buf[a..b][0..16], data.buf[a..b][0..16]);
    }

    data.reinit(res_buf);
}

pub fn aes128CbcDecrypt(data: *Data, key: [16]u8, iv: [16]u8) !void {
    const len = data.buf.len;
    if (len % 16 != 0) {
        return error.InvalidDataLength;
    }

    const allocator = data.allocator;

    const c = aes.Aes128.initDec(key);
    var res_buf = try allocator.alloc(u8, len);

    for (0..len / 16) |i| {
        const a = i * 16;
        const b = (i + 1) * 16;

        c.decrypt(res_buf[a..b][0..16], data.buf[a..b][0..16]);
    }

    const xor_buf = try allocator.alloc(u8, len);
    defer allocator.free(xor_buf);

    @memcpy(xor_buf[0..16], iv[0..]);
    @memcpy(xor_buf[16..], data.buf[0 .. len - 16]);

    data.reinit(res_buf);
    try data.xorBytes(xor_buf);
}

pub fn aes128EcbEncrypt(data: *Data, key: [16]u8) !void {
    const len = data.buf.len;
    if (len % 16 != 0) {
        return error.InvalidDataLength;
    }

    const allocator = data.allocator;
    const c = aes.Aes128.initEnc(key);
    var res_buf = try allocator.alloc(u8, len);

    for (0..len / 16) |i| {
        const a = i * 16;
        const b = (i + 1) * 16;

        c.encrypt(res_buf[a..b][0..16], data.buf[a..b][0..16]);
    }

    data.reinit(res_buf);
}

pub fn aes128CbcEncrypt(data: *Data, key: [16]u8, iv: [16]u8) !void {
    const len = data.buf.len;
    if (len % 16 != 0) {
        return error.InvalidDataLength;
    }

    const allocator = data.allocator;
    const c = aes.Aes128.initEnc(key);
    const res_buf = try allocator.alloc(u8, len);
    var prev_block = try Data.new(allocator, iv[0..]);

    for (0..len / 16) |i| {
        const a = i * 16;
        const b = (i + 1) * 16;

        try prev_block.xorBytes(data.buf[a..b]);

        c.encrypt(res_buf[a..b][0..16], prev_block.buf[0..16]);

        prev_block.deinit();
        prev_block = try Data.new(allocator, res_buf[a..b]);
    }

    prev_block.deinit();
    data.reinit(res_buf);
}

pub fn aesEcb128Score(data: Data) !usize {
    const len = data.buf.len;
    if (len % 16 != 0) {
        return error.InvalidDataLength;
    }

    const n = len / 16;
    var res: usize = 0;
    for (0..n) |i| {
        const ia = i * 16;
        const ib = (i + 1) * 16;
        for (i + 1..n) |j| {
            const ja = j * 16;
            const jb = (j + 1) * 16;

            if (std.mem.eql(u8, data.buf[ia..ib], data.buf[ja..jb])) {
                res += 1;
            }
        }
    }
    return res;
}
