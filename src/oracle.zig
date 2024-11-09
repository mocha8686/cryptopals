const std = @import("std");
const Data = @import("Data.zig");
const blackbox = @import("blackbox.zig");

pub fn aesOracle(data: Data) !blackbox.EcbOrCbc {
    const ecb_score = try data.aesEcb128Score();
    return if (ecb_score > 0)
        .ecb
    else
        .cbc;
}
