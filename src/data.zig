const std = @import("std");
const Allocator = std.mem.Allocator;

const Data = struct {
    data: []u8,
    allocator: Allocator,

    const Self = @This();

    fn fromHex(allocator: Allocator, hex_str: []const u8) !Self {
        if (hex_str.len % 2 != 0) {
            return error.BadLength;
        }

        const len = hex_str.len / 2;
        const data = try allocator.alloc(u8, len);
        _ = try std.fmt.hexToBytes(data, hex_str);

        return Self{
            .data = data,
            .allocator = allocator,
        };
    }

    fn fromBase64(allocator: Allocator, base64_str: []const u8) !Self {
        const decoder = std.base64.standard.Decoder;
        const len = try decoder.calcSizeForSlice(base64_str);
        const data = try allocator.alloc(u8, len);
        try decoder.decode(data, base64_str);
        return Self{
            .data = data,
            .allocator = allocator,
        };
    }

    fn hex(self: *const Self) ![]const u8 {
        const len = self.data.len * 2;
        const buf = try self.allocator.alloc(u8, len);
        const charset = "0123456789abcdef";
        for (self.data, 0..) |b, i| {
            buf[i * 2 + 0] = charset[b >> 4];
            buf[i * 2 + 1] = charset[b & 15];
        }
        return buf;
    }

    fn base64(self: *const Self) ![]const u8 {
        const encoder = std.base64.standard.Encoder;
        const len = encoder.calcSize(self.data.len);
        const buf = try self.allocator.alloc(u8, len);
        _ = encoder.encode(buf, self.data);
        return buf;
    }

    fn deinit(self: *const Self) void {
        self.allocator.free(self.data);
    }
};

test "challenge 1" {
    const allocator = std.testing.allocator;
    const hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    const base64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

    const hex_to_base64 = try Data.fromHex(allocator, hex);
    defer hex_to_base64.deinit();
    const test_base64 = try hex_to_base64.base64();
    defer allocator.free(test_base64);
    try std.testing.expectEqualStrings(base64, test_base64);

    const base64_to_hex = try Data.fromBase64(allocator, base64);
    defer base64_to_hex.deinit();
    const test_hex = try base64_to_hex.hex();
    defer allocator.free(test_hex);
    try std.testing.expectEqualStrings(hex, test_hex);
}
