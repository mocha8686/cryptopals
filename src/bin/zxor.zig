const std = @import("std");
const clap = @import("clap");
const cryptopals = @import("cryptopals");

const Allocator = std.mem.Allocator;
const Data = cryptopals.Data;

const Format = enum {
    bytes,
    hex,
    base64,
};

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const params = comptime clap.parseParamsComptime(
        \\-h, --help             Display this help and exit.
        \\-b, --brute            Brute force a key, based on character frequency analysis.
        \\-k, --key <str>        Specify a key to use.
        \\-i, --input <format>   Specify the input format ([bytes], hex, base64).
        \\-o, --output <format>  Specify the output format ([bytes], hex, base64).
        \\-0, --no-newline       Omit newline from output.
        \\<str>                  The string to XOR, or if omitted, use stdin.
        \\
    );

    var diag = clap.Diagnostic{};
    const parsers = comptime .{
        .str = clap.parsers.string,
        .format = clap.parsers.enumeration(Format),
    };
    const res = clap.parse(clap.Help, &params, parsers, .{
        .diagnostic = &diag,
        .allocator = allocator,
    }) catch |err| {
        try diag.reportToFile(.stderr(), err);
        return;
    };

    const stderr = std.fs.File.stderr();

    if (res.args.help != 0) {
        var args = try std.process.argsWithAllocator(allocator);

        const programName = args.next().?;

        _ = try stderr.write("usage: ");
        _ = try stderr.write(programName);
        _ = try stderr.write(" ");
        try clap.usageToFile(.stdout(), clap.Help, &params);
        _ = try stderr.write("\n");
        try clap.helpToFile(.stderr(), clap.Help, &params, .{});
        return;
    }

    const stdout = std.fs.File.stdout();
    const inputFormat: Format = res.args.input orelse .bytes;
    const outputFormat: Format = res.args.output orelse .bytes;

    var data = if (res.positionals[0]) |input| blk: {
        const data = try Data.copy(allocator, input);
        break :blk data;
    } else blk: {
        var reader = std.fs.File.stdin().readerStreaming("");
        const input = try reader.interface.allocRemaining(allocator, .unlimited);
        const data = Data.init(allocator, input);
        break :blk data;
    };

    try formatInput(&data, inputFormat);

    if (res.args.key) |key| {
        const cipher = cryptopals.cipher.XOR{ .key = key };

        try data.decode(cipher);
    } else if (res.args.brute != 0) {
        const key = try cryptopals.attack.xor.repeatingKeyXOR(&data);

        _ = try stderr.write("Key: ");
        _ = try stderr.write(key.bytes);
        _ = try stderr.write("\n================\n");
    } else {
        _ = try stderr.write("You must specify either -k or -b.");
        return;
    }

    try formatOutput(&data, outputFormat);
    _ = try stdout.write(data.bytes);

    if (res.args.@"no-newline" == 0) {
        _ = try stdout.write("\n");
    }
}

fn formatInput(data: *Data, format: Format) !void {
    switch (format) {
        .bytes => return,
        .hex => {
            const cipher = cryptopals.cipher.Hex{};
            try data.decode(cipher);
        },
        .base64 => {
            const cipher = cryptopals.cipher.Base64{};
            try data.decode(cipher);
        },
    }
}

fn formatOutput(data: *Data, format: Format) !void {
    switch (format) {
        .bytes => return,
        .hex => {
            const cipher = cryptopals.cipher.Hex{};
            try data.encode(cipher);
        },
        .base64 => {
            const cipher = cryptopals.cipher.Base64{};
            try data.encode(cipher);
        },
    }
}
