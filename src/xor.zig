const std = @import("std");
const Data = @import("Data.zig");

const Allocator = std.mem.Allocator;

pub fn xor(lhs: *Data, rhs: Data) !void {
    return xorBytes(lhs, rhs.buf);
}

pub fn xorBytes(data: *Data, bytes: []const u8) !void {
    const allocator = data.allocator;
    const len = @max(data.len, bytes.len);
    const buf = try allocator.alloc(u8, len);
    for (0..len) |i| {
        const l = data.buf[i % data.len];
        const r = bytes[i % bytes.len];
        buf[i] = l ^ r;
    }

    data.reinit(buf);
}

pub fn guessSingleByteXor(data: Data) !Data {
    const allocator = data.allocator;
    var max_score: i32 = 0;
    var best_guess: ?Data = null;

    for (0..std.math.maxInt(u8)) |b| {
        var buf = try allocator.alloc(u8, 1);
        buf[0] = @intCast(b);
        var guess = Data.init(allocator, buf);
        try guess.xor(data);

        const score = guess.score();

        if (score > max_score) {
            if (best_guess) |old_guess| {
                old_guess.deinit();
            }
            max_score = score;
            best_guess = guess;
        } else {
            guess.deinit();
        }
    }

    return best_guess orelse unreachable;
}

pub fn breakRepeatingKeyXor(data: Data) !Data {
    const allocator = data.allocator;
    const len = data.len;
    const keysize = try guessKeysize(data);

    var num_plus_ones = len % keysize;
    var n: u32 = 0;
    var blocks = try allocator.alloc(Data, keysize);

    defer allocator.free(blocks);

    for (0..keysize) |i| {
        const num_bytes: u32 = if (num_plus_ones > 0) blk: {
            num_plus_ones -= 1;
            break :blk len / keysize + 1;
        } else len / keysize;

        const buf = try allocator.alloc(u8, num_bytes);

        for (0..num_bytes) |j| {
            buf[j] = data.buf[keysize * j + i];
        }

        blocks[n] = Data.init(allocator, buf);
        n += 1;
    }

    for (blocks, 0..) |block, i| {
        const plaintext_block = try block.guessSingleByteXor();
        block.deinit();
        blocks[i] = plaintext_block;
    }

    var plaintext = try allocator.alloc(u8, len);
    for (blocks, 0..) |block, i| {
        for (block.buf, 0..) |byte, j| {
            plaintext[keysize * j + i] = byte;
        }
        block.deinit();
    }

    return Data.init(allocator, plaintext);
}

fn guessKeysize(data: Data) !u32 {
    const allocator = data.allocator;
    const len = data.len;

    if (len < 4) {
        return error.CiphertextTooSmall;
    }

    var keysize: u32 = undefined;
    var max_hamming_distance: u32 = std.math.maxInt(u32);

    for (2..40) |k| {
        const keysize_guess: u32 = @intCast(k);
        if (len < keysize_guess * 2) break;
        var hamming_distance: u32 = 0;
        var n: u32 = 0;
        for (0..len / keysize_guess - 1) |i| {
            const offset = keysize_guess * i;
            const stride = keysize_guess;
            const lhs = Data.init(allocator, data.buf[offset .. offset + stride]);
            const rhs = Data.init(allocator, data.buf[offset + stride .. offset + (stride * 2)]);
            hamming_distance += lhs.hammingDistance(rhs);
            n += 1;
        }
        hamming_distance /= n * keysize_guess;
        if (hamming_distance < max_hamming_distance) {
            max_hamming_distance = hamming_distance;
            keysize = keysize_guess;
        }
    }

    return keysize;
}
