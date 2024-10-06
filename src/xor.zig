const std = @import("std");
const dataLib = @import("data.zig");

const Allocator = std.mem.Allocator;
const Data = dataLib.Data;

pub fn xor(lhs: *Data, rhs: *const Data) !void {
    const allocator = lhs.allocator;
    const len = @max(lhs.data.len, rhs.data.len);
    const buf = try allocator.alloc(u8, len);
    for (0..len) |i| {
        const l = lhs.data[i % lhs.data.len];
        const r = rhs.data[i % rhs.data.len];
        buf[i] = l ^ r;
    }

    allocator.free(lhs.data);
    lhs.data = buf;
}

pub fn guessSingleByteXor(allocator: Allocator, ciphertext: *const Data) !Data {
    var max_score: isize = 0;
    var best_guess: ?Data = null;

    for (0..std.math.maxInt(u8)) |b| {
        var buf = try allocator.alloc(u8, 1);
        buf[0] = @intCast(b);
        var data = Data.init(allocator, buf);
        _ = try data.xor(ciphertext);

        const score = data.score();

        if (score > max_score) {
            if (best_guess) |guess| {
                guess.deinit();
            }
            max_score = score;
            best_guess = data;
        } else {
            data.deinit();
        }
    }

    return best_guess orelse unreachable;
}
