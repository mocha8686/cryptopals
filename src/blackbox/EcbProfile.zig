const std = @import("std");
const Allocator = std.mem.Allocator;

const Data = @import("../Data.zig");
const AesEcb = @import("../cipher/AesEcb.zig");

const Self = @This();

pub const Profile = std.StringArrayHashMap([]const u8);
const prefix = "email=";
const postfix = "&uid=10&role=user";

cipher: AesEcb,

pub fn init() Self {
    var rand = std.Random.DefaultPrng.init(std.crypto.random.int(u64));
    var key: [16]u8 = undefined;
    rand.fill(&key);

    return Self{
        .cipher = .{ .key = key },
    };
}

pub fn process(self: Self, data: *Data) !void {
    const allocator = data.allocator;

    try sanitize(&data);

    const bufferSize = prefix.len + data.len() + postfix.len;
    const buffer = try allocator.alloc(u8, bufferSize);
    errdefer allocator.free(buffer);

    const a = prefix.len;
    const b = a + data.len();
    @memcpy(buffer[0..a], prefix);
    @memcpy(buffer[a..b], data.bytes[0..]);
    @memcpy(buffer[b..], postfix);

    data.reinit(buffer);
    try data.encode(self.cipher);
}

pub fn isAdmin(self: Self, allocator: Allocator, bytes: []const u8) !bool {
    var res = try Data.copy(allocator, bytes);
    defer res.deinit();
    try res.decode(self.cipher);

    const profile = try parse(allocator, res.bytes);
    defer profile.deinit();

    if (profile.get("role")) |role| {
        return std.mem.eql(u8, role, "admin");
    } else {
        return false;
    }
}

fn parse(allocator: Allocator, input: []const u8) !Profile {
    var profile = Profile.init(allocator);
    errdefer profile.deinit();

    var entries = std.mem.splitScalar(u8, input, '&');
    while (entries.next()) |entry| {
        const delimiterIndex = std.mem.indexOfScalar(u8, entry, '=');
        _ = try profile.getOrPutValue(entry[0..delimiterIndex], entry[delimiterIndex + 1..]);
    }

    return profile;
}

fn sanitize(data: *Data) !void {
    const allocator = data.allocator;

    const sizeWithoutAnd = std.mem.replacementSize(u8, data.bytes, "&", "");
    var withoutAnd = try allocator.alloc(u8, sizeWithoutAnd);
    defer allocator.free(withoutAnd);
    std.mem.replace(u8, data.bytes, "&", "", &withoutAnd);

    const sizeWithoutEqual = std.mem.replacementSize(u8, withoutAnd, "=", "");
    var withoutEqual = try allocator.alloc(u8, sizeWithoutEqual);
    errdefer allocator.free(withoutEqual);
    std.mem.replace(u8, withoutAnd, "=", "", &withoutEqual);
    data.reinit(withoutEqual);
}
