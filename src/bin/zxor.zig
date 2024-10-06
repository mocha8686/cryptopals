const std = @import("std");
const cryptopals = @import("cryptopals");
const clap = @import("clap");

const Data = cryptopals.data.Data;
const Allocator = std.mem.Allocator;

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help         Display this help and exit.
        \\-i, --input <file> File to XOR (reads stdin otherwise).
        \\-k, --key <str>    XOR key.
    );

    const parsers = comptime .{
        .file = clap.parsers.string,
        .str = clap.parsers.string,
    };

    var diag = clap.Diagnostic{};
    var res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        diag.report(std.io.getStdErr().writer(), err) catch {};
        return;
    };
    defer res.deinit();

    if (res.args.help != 0 or res.args.key == null) {
        const stderr = std.io.getStdErr().writer();
        var argv = std.process.args();
        const argv1 = argv.next() orelse unreachable;
        const process_name = std.fs.path.basename(argv1);

        var bufwriter = std.io.bufferedWriter(stderr);
        const writer = bufwriter.writer();

        try writer.print("Usage: {s} ", .{process_name});
        try clap.usage(writer, clap.Help, &params);
        try writer.writeAll("\n\nOptions:\n");
        try clap.help(writer, clap.Help, &params, .{});
        try bufwriter.flush();

        return;
    }

    const key_str = res.args.key.?;

    var file: std.fs.File = undefined;
    if (res.args.input) |path| {
        file = try std.fs.cwd().openFile(path, .{});
    } else {
        file = std.io.getStdIn();
    }
    defer file.close();

    const buf = try file.readToEndAlloc(allocator, 1024 * 10);

    var data = Data.init(allocator, buf);
    const key = try Data.new(allocator, key_str);

    try data.xor(&key);

    const stdout = std.io.getStdOut();
    try stdout.writeAll(data.data);
}
