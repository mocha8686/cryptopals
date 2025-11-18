const Data = @import("../Data.zig");

const Self = @This();

key: Data,

pub fn decode(self: Self, data: *Data) !void {
    try data.xor(self.key);
}

pub fn encode(self: Self, data: *Data) !void {
    try self.decode(data);
}
