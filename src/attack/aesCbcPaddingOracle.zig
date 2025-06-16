const std = @import("std");
const blackboxLib = @import("../Blackbox.zig");
const Data = @import("../Data.zig");

const Allocator = std.mem.Allocator;
const Encrypter = blackboxLib.Encrypter;
const PaddingOracle = blackboxLib.PaddingOracle;

pub fn aesCbcPaddingOracle(allocator: Allocator, blackbox: Encrypter, padding_oracle: PaddingOracle) !Data {
    var data = try Data.copy(allocator, "");
    try blackbox.encrypt(&data);
    defer data.deinit();

    const iv = data.buf[0..16];
    const ciphertext = data.buf[16..];
    const res_buf = try allocator.alloc(u8, ciphertext.len);

    for (0..ciphertext.len / 16) |i| {
        std.debug.print("\nblock {}\n", .{i});
        const a = i * 16;
        const b = a + 16;

        const keyed_block = try crackKeyedBlock(allocator, ciphertext[a..b][0..16].*, padding_oracle);
        @memcpy(res_buf[a..b], &keyed_block);
    }

    const xor_buf = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(xor_buf);
    @memcpy(xor_buf[0..16], iv);
    @memcpy(xor_buf[16..], ciphertext[0 .. ciphertext.len - 16]);

    var res = Data.init(allocator, res_buf);
    try res.xorBytes(xor_buf);
    return res;
}

fn crackKeyedBlock(allocator: Allocator, block: [16]u8, padding_oracle: PaddingOracle) ![16]u8 {
    var zero_iv: [16]u8 = undefined;
    @memset(&zero_iv, 0);

    outer: for (0..16) |i| {
        const padding_byte = i + 1;
        const index = 16 - padding_byte;

        var iv_data = try Data.copy(allocator, &[1]u8{@intCast(padding_byte)});
        try iv_data.xorBytes(&zero_iv);

        var iv: [16]u8 = undefined;
        @memcpy(&iv, iv_data.buf);

        iv_data.deinit();

        inner: for (0..std.math.maxInt(u8)) |n| {
            const c: u8 = @intCast(n);
            iv[index] = c;

            if (try testBlock(allocator, padding_oracle, iv, block)) {
                // Check for false positives
                if (padding_byte != 16) {
                    iv[index - 1] ^= 1;
                    if (!try testBlock(allocator, padding_oracle, iv, block)) {
                        std.debug.print("\nFalse positive\n", .{});
                        continue :inner;
                    }
                }

                std.debug.print("\nFound {}\n", .{padding_byte});
                var zero_iv_data = try Data.copy(allocator, &[1]u8{@intCast(padding_byte)});
                defer zero_iv_data.deinit();
                try zero_iv_data.xorBytes(&iv);
                @memcpy(&zero_iv, zero_iv_data.buf);
                continue :outer;
            }
        }

        unreachable;
    }

    return zero_iv;
}

fn testBlock(allocator: Allocator, padding_oracle: PaddingOracle, iv: [16]u8, block: [16]u8) !bool {
    var buf = try allocator.alloc(u8, 32);
    @memcpy(buf[0..16], &iv);
    @memcpy(buf[16..], &block);

    const data = Data.init(allocator, buf);
    defer data.deinit();

    const hasValidPadding = try padding_oracle.hasValidPadding(data);
    return hasValidPadding;
}
