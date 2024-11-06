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
                return error.InvalidPlaintextLength;
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
                return error.InvalidPlaintextLength;
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
    }
}
