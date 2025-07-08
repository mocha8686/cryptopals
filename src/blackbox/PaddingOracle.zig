const std = @import("std");
const Data = @import("../Data.zig");
const cipherLib = @import("../cipher.zig");

const Allocator = std.mem.Allocator;

ptr: *anyopaque,
hasValidPaddingPtr: *const fn (ptr: *anyopaque, data: Data) anyerror!bool,

const Self = @This();

pub fn init(ptr: anytype) Self {
    const T = @TypeOf(ptr);
    const type_info = @typeInfo(T);

    if (type_info != .pointer) @compileError("ptr must be a pointer");
    if (type_info.pointer.size != .one) @compileError("ptr must be a single item pointer");

    const gen = struct {
        pub fn hasValidPadding(self_ptr: *anyopaque, data: Data) anyerror!bool {
            const self: T = @ptrCast(@alignCast(self_ptr));
            return @call(.always_inline, type_info.pointer.child.hasValidPadding, .{ self, data });
        }
    };

    return .{
        .ptr = ptr,
        .hasValidPaddingPtr = gen.hasValidPadding,
    };
}

pub fn hasValidPadding(self: Self, data: Data) !bool {
    return self.hasValidPaddingPtr(self.ptr, data);
}