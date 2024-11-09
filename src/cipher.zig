const std = @import("std");
const Data = @import("Data.zig");

const aes = std.crypto.core.aes;

pub const Cipher = union(enum) {
    aes_128_ecb: struct {
        key: [16]u8,
    },
};

pub fn decrypt(data: *Data, cipher: Cipher) !void {
    const allocator = data.allocator;
    switch (cipher) {
        .aes_128_ecb => |*aes_info| {
            const c = aes.Aes128.initDec(aes_info.key);
            if (data.data.len % 16 != 0) {
                return error.InvalidDataLength;
            }

            var res_buf = try allocator.alloc(u8, data.data.len);

            for (0..data.data.len / 16) |i| {
                const a = i * 16;
                const b = (i + 1) * 16;

                var buf: [16]u8 = undefined;
                var src: [16]u8 = undefined;

                @memcpy(&src, data.data[a..b]);
                c.decrypt(&buf, &src);
                @memcpy(res_buf[a..b], &buf);
            }

            allocator.free(data.data);
            data.data = res_buf;
        },
    }
}

pub fn encrypt(data: *Data, cipher: Cipher) !void {
    const allocator = data.allocator;
    switch (cipher) {
        .aes_128_ecb => |*aes_info| {
            const c = aes.Aes128.initEnc(aes_info.key);
            if (data.data.len % 16 != 0) {
                return error.InvalidDataLength;
            }

            var res_buf = try allocator.alloc(u8, data.data.len);

            for (0..data.data.len / 16) |i| {
                const a = i * 16;
                const b = (i + 1) * 16;

                var buf: [16]u8 = undefined;
                var src: [16]u8 = undefined;

                @memcpy(&src, data.data[a..b]);
                c.encrypt(&buf, &src);
                @memcpy(res_buf[a..b], &buf);
            }

            allocator.free(data.data);
            data.data = res_buf;
        },
        .aes_128_cbc => |*aes_info| {
            if (data.data.len % 16 != 0) {
                return error.InvalidDataLength;
            }

            const c = aes.Aes128.initEnc(aes_info.key);
            const res_buf = try allocator.alloc(u8, data.data.len);
            var prev_block = try Data.new(allocator, aes_info.iv[0..]);

            for (0..data.data.len / 16) |i| {
                const a = i * 16;
                const b = (i + 1) * 16;

                try prev_block.xorBytes(data.data[a..b]);

                var src: [16]u8 = undefined;
                var buf: [16]u8 = undefined;

                @memcpy(&src, prev_block.data);
                c.encrypt(&buf, &src);
                @memcpy(res_buf[a..b], &buf);

                prev_block.deinit();
                prev_block = try Data.new(allocator, &buf);
            }

            prev_block.deinit();

            allocator.free(data.data);
            data.data = res_buf;
        },
    }
}

// PKCS#7 padding scheme.
pub fn pad(data: *Data, block_size: u8) !void {
    const len = data.data.len;
    const padding_len: u8 = @intCast(block_size - len % block_size);
    if (padding_len == 0) return;

    const allocator = data.allocator;

    var buf = try allocator.alloc(u8, len + padding_len);
    @memcpy(buf[0..len], data.data);
    @memset(buf[len..], padding_len);

    allocator.free(data.data);
    data.data = buf;
}

pub fn aesEcb128Score(data: Data) !usize {
    if (data.data.len % 16 != 0) {
        return error.InvalidDataLength;
    }

    const n = data.data.len / 16;
    var res: usize = 0;
    for (0..n) |i| {
        const ia = i * 16;
        const ib = (i + 1) * 16;
        for (i + 1..n) |j| {
            const ja = j * 16;
            const jb = (j + 1) * 16;

            if (std.mem.eql(u8, data.data[ia..ib], data.data[ja..jb])) {
                res += 1;
            }
        }
    }
    return res;
}
