const std = @import("std");
const dataLib = @import("data.zig");

const Allocator = std.mem.Allocator;
const Data = dataLib.Data;

pub fn xor(lhs: *const Data, rhs: *const Data) !Data {
    const allocator = lhs.allocator;
    const len = @max(lhs.data.len, rhs.data.len);
    const buf = try allocator.alloc(u8, len);
    for (0..len) |i| {
        const l = lhs.data[i % lhs.data.len];
        const r = rhs.data[i % rhs.data.len];
        buf[i] = l ^ r;
    }

    return Data.init(allocator, buf);
}

pub fn guess_repeating_key_xor(allocator: Allocator, ciphertext: *const Data) !Data {
    const len = ciphertext.data.len;

    var max_score: isize = 0;
    var best_guess: ?Data = null;

    for (0..std.math.maxInt(u8)) |b| {
        const data = try repeat_byte(allocator, @intCast(b), len);
        defer data.deinit();

        const res = try ciphertext.xor(&data);

        const score = res.score();
        if (score > max_score) {
            if (best_guess) |guess| {
                guess.deinit();
            }
            max_score = score;
            best_guess = res;
        } else {
            res.deinit();
        }
    }

    return best_guess orelse unreachable;
}

pub fn repeat_byte(allocator: Allocator, byte: u8, len: usize) !Data {
    const buf = try allocator.alloc(u8, len);
    @memset(buf, byte);
    return Data.init(allocator, buf);
}