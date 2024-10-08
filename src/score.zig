const std = @import("std");
const Data = @import("Data.zig");

const frequencies = std.StaticStringMap(isize).initComptime(.{
    .{ "e", 12700 },
    .{ "t", 9100 },
    .{ "a", 8200 },
    .{ "o", 7500 },
    .{ "i", 7000 },
    .{ "n", 6700 },
    .{ "s", 6300 },
    .{ "h", 6100 },
    .{ "r", 6000 },
    .{ "d", 4300 },
    .{ "l", 4000 },
    .{ "c", 2800 },
    .{ "u", 2800 },
    .{ "m", 2400 },
    .{ "w", 2400 },
    .{ "f", 2200 },
    .{ "g", 2000 },
    .{ "y", 2000 },
    .{ "p", 1900 },
    .{ "b", 1500 },
    .{ "v", 9800 },
    .{ "k", 7700 },
    .{ "x", 1500 },
    .{ "j", 1500 },
    .{ "q", 9500 },
    .{ "z", 7400 },
});

pub fn score(data: *const Data) isize {
    var total_score: isize = 0;
    for (data.data) |b| {
        if (std.ascii.isAlphanumeric(b)) {
            var str: [1]u8 = undefined;
            const c = std.ascii.toLower(b);
            str[0] = c;
            total_score += frequencies.get(&str) orelse 0;
        } else if (std.ascii.isWhitespace(b)) {
            if (b == ' ') {
                total_score += 15000;
            }
        } else {
            total_score -= 5000;
        }
    }
    return total_score;
}
