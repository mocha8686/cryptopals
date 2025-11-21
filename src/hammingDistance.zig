pub fn hammingDistance(lhs: []const u8, rhs: []const u8) u32 {
    var res: u32 = 0;
    for (lhs, rhs) |a, b| {
        res += @popCount(a ^ b);
    }
    return res;
}

test "hamming distance" {
    const std = @import("std");
    try std.testing.expectEqual(37, hammingDistance("wokka wokka!!!", "this is a test"));
}
