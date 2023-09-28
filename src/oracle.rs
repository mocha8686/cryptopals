#[cfg(test)]
mod challenge11;

use itertools::Itertools;

use crate::data::Data;

pub fn count_repeating_blocks(data: &Data, block_size: usize) -> usize {
    data.bytes()
        .into_iter()
        .chunks(block_size)
        .into_iter()
        .map(|chunk| chunk.collect::<Box<_>>())
        .counts()
        .into_values()
        .map(|count| count - 1)
        .sum::<usize>()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EcbOrCbc {
    Ecb,
    Cbc,
}

pub fn ecb_or_cbc(data: &Data) -> EcbOrCbc {
    if count_repeating_blocks(&data, 16) > 0 {
        EcbOrCbc::Ecb
    } else {
        EcbOrCbc::Cbc
    }
}
