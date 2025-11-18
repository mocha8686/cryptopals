const std = @import("std");
const Allocator = std.mem.Allocator;

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

pub fn encode(self: *Self, cipher: anytype) !void {
    try cipher.encode(self);
}

pub fn decode(self: *Self, cipher: anytype) !void {
    try cipher.decode(self);
}

pub fn xor(self: *Self, other: Self) !void {
    if (self.bytes.len != other.bytes.len) {
        return error.UnequalSizes;
    }

    for (0..self.bytes.len) |i| {
        self.bytes[i] = self.bytes[i] ^ other.bytes[i];
    }
}

pub fn deinit(self: Self) void {
    self.allocator.free(self.bytes);
}
