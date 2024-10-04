const std = @import("std");
const xorLib = @import("xor.zig");
const scoreLib = @import("score.zig");

const Allocator = std.mem.Allocator;

pub const Data = struct {
    data: []const u8,
    allocator: Allocator,

    const Self = @This();

    pub fn init(allocator: Allocator, data: []const u8) Self {
        return Self{
            .data = data,
            .allocator = allocator,
        };
    }

    pub fn new(allocator: Allocator, data: []const u8) !Self {
        const buf = try allocator.alloc(data.len);
        @memcpy(buf, data);
        return Self.init(allocator, buf);
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
        return xorLib.xor(self, other);
    }

    pub fn score(self: *const Self) isize {
        return scoreLib.score(self);
    }

    pub fn guess_repeating_key_xor(self: *const Self) !Self {
        return xorLib.guess_repeating_key_xor(self.allocator, self);
    }

    const DataString = struct {
        data: []const u8,
        allocator: Allocator,

        const InnerSelf = @This();

        pub fn deinit(self: *const InnerSelf) void {
            self.allocator.free(self.data);
        }
    };

    pub fn hex(self: *const Self) !DataString {
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

    pub fn base64(self: *const Self) !DataString {
        const encoder = std.base64.standard.Encoder;
        const len = encoder.calcSize(self.data.len);
        const buf = try self.allocator.alloc(u8, len);
        _ = encoder.encode(buf, self.data);
        return DataString{
            .data = buf,
            .allocator = self.allocator,
        };
    }

    pub fn deinit(self: *const Self) void {
        self.allocator.free(self.data);
    }
};
