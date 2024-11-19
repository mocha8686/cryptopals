const std = @import("std");
const Data = @import("../Data.zig");

const Allocator = std.mem.Allocator;

allocator: Allocator,
email: []const u8,
uid: u32,
role: []const u8,

const Self = @This();

pub fn new(allocator: Allocator, kvs: []const u8) !Self {
    var email: ?[]u8 = null;
    var uid: ?u32 = null;
    var role: ?[]u8 = null;

    errdefer {
        if (email) |e| allocator.free(e);
        if (role) |r| allocator.free(r);
    }

    var iter = std.mem.tokenizeScalar(u8, kvs, '&');
    while (iter.next()) |kv| {
        const i = std.mem.indexOfScalar(u8, kv, '=').?;
        const key = kv[0..i];
        const val = kv[i + 1 ..];

        if (std.mem.eql(u8, key, "email")) {
            email = try allocator.alloc(u8, val.len);
            @memcpy(email.?, val);
        } else if (std.mem.eql(u8, key, "uid")) {
            uid = try std.fmt.parseInt(u8, val, 10);
        } else if (std.mem.eql(u8, key, "role")) {
            role = try allocator.alloc(u8, val.len);
            @memcpy(role.?, val);
        }
    }

    if (email == null or uid == null or role == null) {
        return error.MissingValues;
    }

    return .{
        .allocator = allocator,
        .email = email.?,
        .uid = uid.?,
        .role = role.?,
    };
}

pub fn profileFor(allocator: Allocator, email: []const u8) !Self {
    const without_eq = try std.mem.replaceOwned(u8, allocator, email, "=", "");
    defer allocator.free(without_eq);

    const without_and = try std.mem.replaceOwned(u8, allocator, without_eq, "&", "");
    defer allocator.free(without_and);

    const kvs = try std.fmt.allocPrint(allocator, "email={s}&uid=10&role=user", .{without_and});
    defer allocator.free(kvs);

    return Self.new(allocator, kvs);
}

pub fn toString(self: Self) ![]u8 {
    return std.fmt.allocPrint(self.allocator, "email={s}&uid={}&role={s}", .{ self.email, self.uid, self.role });
}

pub fn deinit(self: Self) void {
    self.allocator.free(self.email);
    self.allocator.free(self.role);
}
