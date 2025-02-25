const std = @import("std");
const blackboxLib = @import("../blackbox.zig");
const Data = @import("../Data.zig");
const Profile = @import("Profile.zig");
const aes = @import("aes.zig");

const Allocator = std.mem.Allocator;
const EncDec = blackboxLib.EncDec;
const Encrypter = blackboxLib.Encrypter;

pub fn aesProfileCutPaste(allocator: Allocator, blackbox: EncDec) !Profile {
    const enc = blackbox.encrypter();
    const dec = blackbox.decrypter();

    const block_size = try aes.ecb.findBlockSize(allocator, enc);
    const prefix_len = try aes.ecb.getPrefixLen(allocator, enc, block_size);

    const bytes_until_next_block = aes.ecb.paddingToNextBlock(prefix_len, block_size);
    const email_index = aes.ecb.alignToNextBlock(prefix_len, block_size);

    const admin = try getAdminCiphertext(allocator, enc, bytes_until_next_block, block_size, email_index);
    defer admin.deinit();

    const buf = try allocator.alloc(u8, bytes_until_next_block + 3);
    @memset(buf, 'A');

    var data = Data.init(allocator, buf);
    defer data.deinit();

    try enc.encrypt(&data);

    const tampered_buf = try allocator.alloc(u8, data.buf.len);
    @memcpy(tampered_buf[0 .. tampered_buf.len - 16], data.buf[0 .. data.buf.len - 16]);
    @memcpy(tampered_buf[tampered_buf.len - 16 ..], admin.buf);
    data.reinit(tampered_buf);

    try dec.decrypt(&data);
    try data.unpad();

    const profile = try Profile.new(allocator, data.buf);
    return profile;
}

fn getAdminCiphertext(allocator: Allocator, blackbox: Encrypter, bytes_until_next_block: usize, block_size: usize, email_index: usize) !Data {
    var buf = try allocator.alloc(u8, bytes_until_next_block + block_size);
    @memset(buf[0..bytes_until_next_block], 'A');
    const admin_payload = "admin";
    _ = try std.fmt.bufPrint(buf[bytes_until_next_block..], "{s}", .{admin_payload});
    @memset(buf[bytes_until_next_block + admin_payload.len ..], @intCast(block_size - admin_payload.len));

    var data = Data.init(allocator, buf);
    defer data.deinit();
    try blackbox.encrypt(&data);

    const admin_ciphertext = data.buf[email_index .. email_index + block_size];
    return Data.new(allocator, admin_ciphertext);
}
