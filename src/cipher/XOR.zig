const Data = @import("../Data.zig");

const Self = @This();

key: []const u8,

pub fn decode(self: Self, data: *Data) !void {
    try data.xor(self.key);
}

pub fn encode(self: Self, data: *Data) !void {
    try self.decode(data);
}

test "set 1 challenge 2" {
    const std = @import("std");
    const allocator = std.testing.allocator;

    var lhs = try Data.fromHex(
        allocator,
        "1c0111001f010100061a024b53535009181c",
    );
    defer lhs.deinit();

    const rhs = try Data.fromHex(
        allocator,
        "686974207468652062756c6c277320657965",
    );
    defer rhs.deinit();

    try lhs.xor(rhs.bytes);

    const hex = @import("Hex.zig"){};
    try lhs.encode(hex);

    try std.testing.expectEqualStrings(
        "746865206b696420646f6e277420706c6179",
        lhs.bytes,
    );
}

test "set 1 challenge 5" {
    const std = @import("std");
    const allocator = std.testing.allocator;

    var data = try Data.copy(allocator, "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
    defer data.deinit();

    try data.xor("ICE");

    const hex = @import("Hex.zig"){};
    try data.encode(hex);

    try std.testing.expectEqualStrings(
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
        data.bytes,
    );
}
