const std = @import("std");
const Data = @import("Data.zig");

const Allocator = std.mem.Allocator;

pub fn xor(lhs: *Data, rhs: Data) !void {
    return xorBytes(lhs, rhs.data);
}

pub fn xorBytes(data: *Data, bytes: []u8) !void {
    const allocator = data.allocator;
    const len = @max(data.data.len, bytes.len);
    const buf = try allocator.alloc(u8, len);
    for (0..len) |i| {
        const l = data.data[i % data.data.len];
        const r = bytes[i % bytes.len];
        buf[i] = l ^ r;
    }

    allocator.free(data.data);
    data.data = buf;
}

pub fn guessSingleByteXor(allocator: Allocator, ciphertext: Data) !Data {
    var max_score: isize = 0;
    var best_guess: ?Data = null;

    for (0..std.math.maxInt(u8)) |b| {
        var buf = try allocator.alloc(u8, 1);
        buf[0] = @intCast(b);
        var data = Data.init(allocator, buf);
        try data.xor(ciphertext);

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

pub fn breakRepeatingKeyXor(allocator: Allocator, ciphertext: Data) !Data {
    const len = ciphertext.data.len;
    const keysize = try guessKeysize(allocator, ciphertext);

    var num_plus_ones = len % keysize;
    var n: usize = 0;
    var blocks = try allocator.alloc(Data, keysize);

    defer allocator.free(blocks);

    for (0..keysize) |i| {
        const num_bytes: usize = if (num_plus_ones > 0) blk: {
            num_plus_ones -= 1;
            break :blk len / keysize + 1;
        } else len / keysize;

        const buf = try allocator.alloc(u8, num_bytes);

        for (0..num_bytes) |j| {
            buf[j] = ciphertext.data[keysize * j + i];
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
        for (block.data, 0..) |byte, j| {
            plaintext[keysize * j + i] = byte;
        }
        block.deinit();
    }

    return Data.init(allocator, plaintext);
}

fn guessKeysize(allocator: Allocator, ciphertext: Data) !usize {
    const len = ciphertext.data.len;

    if (len < 4) {
        return error.CiphertextTooSmall;
    }

    var keysize: usize = undefined;
    var max_hamming_distance: usize = std.math.maxInt(usize);

    for (2..40) |keysize_guess| {
        if (len < keysize_guess * 2) break;
        var hamming_distance: usize = 0;
        var n: usize = 0;
        for (0..len / keysize_guess - 1) |i| {
            const offset = keysize_guess * i;
            const stride = keysize_guess;
            const lhs = Data.init(allocator, ciphertext.data[offset .. offset + stride]);
            const rhs = Data.init(allocator, ciphertext.data[offset + stride .. offset + (stride * 2)]);
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
