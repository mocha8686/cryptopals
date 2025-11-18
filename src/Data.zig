const std = @import("std");
const Allocator = std.mem.Allocator;

const padding = @import("pad.zig");

const Self = @This();

allocator: Allocator,
bytes: []u8,

pub fn init(allocator: Allocator, bytes: []u8) Self {
    return Self{
        .allocator = allocator,
        .bytes = bytes,
    };
}

pub fn copy(allocator: Allocator, buf: []const u8) !Self {
    const bytes = try allocator.alloc(u8, buf.len);
    errdefer allocator.free(bytes);

    @memcpy(bytes, buf);
    return Self{
        .allocator = allocator,
        .bytes = bytes,
    };
}

pub fn fromHex(allocator: Allocator, input: []const u8) !Self {
    const bytes = try allocator.alloc(u8, input.len / 2);
    errdefer allocator.free(bytes);
    _ = try std.fmt.hexToBytes(bytes, input);
    return Self{
        .allocator = allocator,
        .bytes = bytes,
    };
}

pub fn fromBase64(allocator: Allocator, input: []const u8) !Self {
    const decoder = std.base64.standard.Decoder;
    const size = try decoder.calcSizeForSlice(input);

    const bytes = try allocator.alloc(u8, size);
    errdefer allocator.free(bytes);

    try decoder.decode(bytes, input);

    return Self{
        .allocator = allocator,
        .bytes = bytes,
    };
}

pub fn reinit(self: *Self, bytes: []u8) void {
    self.deinit();
    self.bytes = bytes;
}

pub fn len(self: Self) usize {
    return self.bytes.len;
}

pub fn pad(self: *Self, blocksize: u32) !void {
    try padding.pad(self, blocksize);
}

pub fn unpad(self: *Self) !void {
    try padding.unpad(self);
}

pub fn hammingDistance(self: Self, other: Self) u32 {
    var res: u32 = 0;
    for (self.bytes, other.bytes) |a, b| {
        res += @popCount(a ^ b);
    }
    return res;
}

pub fn decode(self: *Self, cipher: anytype) !void {
    try cipher.decode(self);
}

pub fn encode(self: *Self, cipher: anytype) !void {
    try cipher.encode(self);
}

pub fn xor(self: *Self, other: Self) !void {
    if (self.len() >= other.len()) {
        const size = self.len();
        for (0..size) |i| {
            const l = other.len();
            self.bytes[i] = self.bytes[i] ^ other.bytes[i % l];
        }
    } else {
        const size = other.len();
        const buf = try self.allocator.alloc(u8, size);
        const l = self.len();
        for (0..size) |i| {
            buf[i] = self.bytes[i % l] ^ other.bytes[i];
        }
        self.reinit(buf);
    }
}

pub fn deinit(self: Self) void {
    self.allocator.free(self.bytes);
}

test "hamming distance" {
    const allocator = std.testing.allocator;

    const lhs = try Self.copy(allocator, "wokka wokka!!!");
    defer lhs.deinit();

    const rhs = try Self.copy(allocator, "this is a test");
    defer rhs.deinit();

    try std.testing.expectEqual(37, lhs.hammingDistance(rhs));
}
