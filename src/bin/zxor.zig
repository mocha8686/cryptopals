const std = @import("std");
const clap = @import("clap");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help       Display this help and exit.
        \\-k, --key <str>  Specify a key to use.
        \\-b, --brute      Brute force a key, based on character frequency analysis.
        \\<str>            The string to XOR, or if omitted, use stdin.
        \\
    );

    var diag = clap.Diagnostic{};
    const res = clap.parse(clap.Help, &params, clap.parsers.default, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        try diag.reportToFile(.stderr(), err);
        return;
    };
    defer res.deinit();

    if (res.args.help != 0) {
        var args = try std.process.argsWithAllocator(allocator);
        defer args.deinit();

        const stderr = std.fs.File.stderr();
        const programName = args.next().?;

        _ = try stderr.write("usage: ");
        _ = try stderr.write(programName);
        _ = try stderr.write(" ");
        try clap.usageToFile(.stdout(), clap.Help, &params);
        _ = try stderr.write("\n");
        try clap.helpToFile(.stderr(), clap.Help, &params, .{});
        return;
    }
}
