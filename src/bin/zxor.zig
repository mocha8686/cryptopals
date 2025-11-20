const std = @import("std");
const clap = @import("clap");

pub fn main() !void {
    const thing = "world";
    std.debug.print("Hello, {s}!\n", .{thing});
}
