const std = @import("std");
const Allocator = std.mem.Allocator;

const Data = struct {
    data: []u8,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, data: []const u8) Self {
        const buf = try allocator.alloc(u8, data.len);
        std.mem.copyForwards(u8, buf, data);
        return Self{
            .data = buf,
            .allocator = allocator,
        };
    }

    pub fn fromHex(allocator: Allocator, hex_str: []const u8) !Self {
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

    pub fn fromBase64(allocator: Allocator, base64_str: []const u8) !Self {
        const decoder = std.base64.standard.Decoder;
        const len = try decoder.calcSizeForSlice(base64_str);
        const data = try allocator.alloc(u8, len);
        try decoder.decode(data, base64_str);
        return Self{
            .data = data,
            .allocator = allocator,
        };
    }

    pub fn xor(self: *const Self, other: *const Self) !Self {
        if (self.data.len != other.data.len) {
            return error.LengthMismatch;
        }

        const buf = try self.allocator.alloc(u8, self.data.len);
        for (self.data, other.data, 0..) |l, r, i| {
            buf[i] = l ^ r;
        }

        return Self{
            .data = buf,
            .allocator = self.allocator,
        };
    }

    const DataString = struct {
        data: []const u8,
        allocator: Allocator,

        const InnerSelf = @This();

        pub fn deinit(self: *const InnerSelf) void {
            self.allocator.free(self.data);
        }
    };

    fn hex(self: *const Self) !DataString {
        const len = self.data.len * 2;
        const buf = try self.allocator.alloc(u8, len);
        const charset = "0123456789abcdef";
        for (self.data, 0..) |b, i| {
            buf[i * 2 + 0] = charset[b >> 4];
            buf[i * 2 + 1] = charset[b & 15];
        }
        return DataString{
            .data = buf,
            .allocator = self.allocator,
        };
    }

    fn base64(self: *const Self) !DataString {
        const encoder = std.base64.standard.Encoder;
        const len = encoder.calcSize(self.data.len);
        const buf = try self.allocator.alloc(u8, len);
        _ = encoder.encode(buf, self.data);
        return DataString{
            .data = buf,
            .allocator = self.allocator,
        };
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
    const test_base64 = try hex_to_base64.base64();

    defer hex_to_base64.deinit();
    defer test_base64.deinit();

    try std.testing.expectEqualStrings(base64, test_base64.data);

    const base64_to_hex = try Data.fromBase64(allocator, base64);
    const test_hex = try base64_to_hex.hex();

    defer base64_to_hex.deinit();
    defer test_hex.deinit();

    try std.testing.expectEqualStrings(hex, test_hex.data);
}

test "challenge 2" {
    const allocator = std.testing.allocator;

    const lhs = try Data.fromHex(allocator, "1c0111001f010100061a024b53535009181c");
    const rhs = try Data.fromHex(allocator, "686974207468652062756c6c277320657965");

    defer lhs.deinit();
    defer rhs.deinit();

    const res = try lhs.xor(&rhs);
    const res_str = try res.hex();

    defer res.deinit();
    defer res_str.deinit();

    try std.testing.expectEqualStrings("746865206b696420646f6e277420706c6179", res_str.data);
}
