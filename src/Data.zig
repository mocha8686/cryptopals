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

pub fn reinit(self: *Self, bytes: []u8) void {
    self.deinit();
    self.bytes = bytes;
}

pub fn encode(self: *Self, cipher: anytype) !void {
    try cipher.encode(self);
}

pub fn decode(self: *Self, cipher: anytype) !void {
    try cipher.decode(self);
}

pub fn deinit(self: *Self) void {
    self.allocator.free(self.bytes);
    self.bytes = undefined;
}
