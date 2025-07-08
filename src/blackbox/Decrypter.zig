const std = @import("std");
const Data = @import("../Data.zig");
const cipherLib = @import("../cipher.zig");

const Allocator = std.mem.Allocator;

ptr: *anyopaque,
decryptPtr: *const fn (ptr: *anyopaque, data: *Data) anyerror!void,

const Self = @This();

pub fn init(ptr: anytype) Self {
    const T = @TypeOf(ptr);
    const type_info = @typeInfo(T);

    if (type_info != .pointer) @compileError("ptr must be a pointer");
    if (type_info.pointer.size != .one) @compileError("ptr must be a single item pointer");

    const gen = struct {
        pub fn decrypt(self_ptr: *anyopaque, data: *Data) anyerror!void {
            const self: T = @ptrCast(@alignCast(self_ptr));
            return @call(.always_inline, type_info.pointer.child.decrypt, .{ self, data });
        }
    };

    return .{
        .ptr = ptr,
        .decryptPtr = gen.decrypt,
    };
}

pub fn decrypt(self: Self, data: *Data) !void {
    return self.decryptPtr(self.ptr, data);
}