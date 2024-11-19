const std = @import("std");
const xorLib = @import("xor.zig");
const scoreLib = @import("score.zig");
const cipherLib = @import("cipher.zig");

const Allocator = std.mem.Allocator;
const Cipher = cipherLib.Cipher;

buf: []const u8,
allocator: Allocator,

const Self = @This();

pub fn init(allocator: Allocator, buf: []const u8) Self {
    return .{
        .buf = buf,
        .allocator = allocator,
    };
}

pub fn new(allocator: Allocator, buf: []const u8) !Self {
    const new_buf = try allocator.alloc(u8, buf.len);
    @memcpy(new_buf, buf);
    return Self.init(allocator, new_buf);
}

pub fn reinit(self: *Self, buf: []const u8) void {
    self.deinit();
    self.buf = buf;
}

pub fn fromHex(allocator: Allocator, hex_str: []const u8) !Self {
    if (hex_str.len % 2 != 0) {
        return error.BadLength;
    }

    const len = hex_str.len / 2;
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    _ = try std.fmt.hexToBytes(buf, hex_str);

    return .{
        .buf = buf,
        .allocator = allocator,
    };
}

pub fn fromBase64(allocator: Allocator, base64_str: []const u8) !Self {
    const decoder = std.base64.standard.Decoder;
    const len = try decoder.calcSizeForSlice(base64_str);
    const buf = try allocator.alloc(u8, len);
    errdefer allocator.free(buf);
    try decoder.decode(buf, base64_str);
    return .{
        .buf = buf,
        .allocator = allocator,
    };
}

pub fn hammingDistance(self: Self, other: Self) usize {
    if (self.buf.len != other.buf.len) @panic("Cannot get hamming distance of differently-sized data.");

    var distance: usize = 0;
    for (self.buf, other.buf) |l, r| {
        distance += @popCount(l ^ r);
    }
    return distance;
}

pub const decrypt = cipherLib.decrypt;
pub const encrypt = cipherLib.encrypt;
pub const pad = cipherLib.pad;
pub const xor = xorLib.xor;
pub const xorBytes = xorLib.xorBytes;
pub const score = scoreLib.score;
pub const guessSingleByteXor = xorLib.guessSingleByteXor;
pub const breakRepeatingKeyXor = xorLib.breakRepeatingKeyXor;
pub const aesEcb128Score = cipherLib.aes.aesEcb128Score;

const DataString = struct {
    buf: []const u8,
    allocator: Allocator,

    pub fn deinit(self: @This()) void {
        self.allocator.free(self.buf);
    }
};

pub fn hex(self: Self) !DataString {
    const len = self.buf.len * 2;
    const buf = try self.allocator.alloc(u8, len);
    const charset = "0123456789abcdef";
    for (self.buf, 0..) |b, i| {
        buf[i * 2 + 0] = charset[b >> 4];
        buf[i * 2 + 1] = charset[b & 15];
    }
    return DataString{
        .buf = buf,
        .allocator = self.allocator,
    };
}

pub fn base64(self: Self) !DataString {
    const encoder = std.base64.standard.Encoder;
    const len = encoder.calcSize(self.buf.len);
    const buf = try self.allocator.alloc(u8, len);
    _ = encoder.encode(buf, self.buf);
    return DataString{
        .buf = buf,
        .allocator = self.allocator,
    };
}

pub fn deinit(self: Self) void {
    self.allocator.free(self.buf);
}

test "hamming distance" {
    const allocator = std.testing.allocator;

    const lhs = try Self.new(allocator, "this is a test");
    defer lhs.deinit();

    const rhs = try Self.new(allocator, "wokka wokka!!!");
    defer rhs.deinit();

    try std.testing.expectEqual(37, lhs.hammingDistance(rhs));
}
