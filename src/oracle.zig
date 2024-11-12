const std = @import("std");
const Data = @import("Data.zig");

pub const EcbOrCbc = enum {
    ecb,
    cbc,
};

pub fn aesOracle(data: Data) !EcbOrCbc {
    const ecb_score = try data.aesEcb128Score();
    return if (ecb_score > 0)
        .ecb
    else
        .cbc;
}
