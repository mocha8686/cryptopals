const std = @import("std");
const Encrypter = @import("Encrypter.zig");
const Decrypter = @import("Decrypter.zig");

const Allocator = std.mem.Allocator;

ptr: *anyopaque,
encrypterPtr: *const fn (ptr: *anyopaque) Encrypter,
decrypterPtr: *const fn (ptr: *anyopaque) Decrypter,

const Self = @This();

pub fn init(ptr: anytype) Self {
    const T = @TypeOf(ptr);
    const type_info = @typeInfo(T);

    if (type_info != .pointer) @compileError("ptr must be a pointer");
    if (type_info.pointer.size != .one) @compileError("ptr must be a single item pointer");

    const gen = struct {
        pub fn encrypter(self_ptr: *anyopaque) Encrypter {
            const self: T = @ptrCast(@alignCast(self_ptr));
            return @call(.always_inline, type_info.pointer.child.encrypter, .{self});
        }

        pub fn decrypter(self_ptr: *anyopaque) Decrypter {
            const self: T = @ptrCast(@alignCast(self_ptr));
            return @call(.always_inline, type_info.pointer.child.decrypter, .{self});
        }
    };

    return .{
        .ptr = ptr,
        .encrypterPtr = gen.encrypter,
        .decrypterPtr = gen.decrypter,
    };
}

pub fn encrypter(self: Self) Encrypter {
    return self.encrypterPtr(self.ptr);
}

pub fn decrypter(self: Self) Decrypter {
    return self.decrypterPtr(self.ptr);
}