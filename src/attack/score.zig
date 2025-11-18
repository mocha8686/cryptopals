const std = @import("std");
const StaticStringMap = std.StaticStringMap;
const Data = @import("../Data.zig");

const Frequencies = StaticStringMap(i32);

const FrequencyKV = struct { []const u8, i32 };
const frequencies: []const FrequencyKV = &.{
    .{ " ", 20000 },
    .{ "e", 12700 },
    .{ "t", 9100 },
    .{ "a", 8200 },
    .{ "o", 7500 },
    .{ "i", 7000 },
    .{ "n", 6700 },
    .{ "s", 6300 },
    .{ "h", 6100 },
    .{ "r", 6000 },
    .{ "d", 4000 },
    .{ "l", 4000 },
    .{ "c", 2000 },
    .{ "u", 2000 },
    .{ "m", 2000 },
    .{ "w", 2000 },
    .{ "f", 2000 },
    .{ "g", 2000 },
    .{ "y", 2000 },
    .{ "p", 1000 },
    .{ "b", 1000 },
    .{ "v", 980 },
    .{ "k", 770 },
    .{ "j", 160 },
    .{ "x", 150 },
    .{ "q", 120 },
    .{ "z", 74 },
};
const map = Frequencies.initComptime(frequencies);

pub fn score(data: Data) i32 {
    var res: i32 = 0;
    for (data.bytes) |b| {
        res += map.get(&.{std.ascii.toLower(b)}) orelse -1000;
    }
    return res;
}
