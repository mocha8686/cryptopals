use itertools::Itertools;

use crate::{Data, Error, Result};

#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    reason = "larger blocksizes will be very rare"
)]
#[must_use]
pub fn pad(data: &Data, blocksize: usize) -> Data {
    let blocksize = blocksize as i32;
    let len = data.len() as i32;
    let padding = (blocksize - (len % blocksize) - 1).rem_euclid(blocksize) as u8;

    let mut bytes = data.to_vec();
    bytes.extend((0..padding).map(|_| padding));
    Data::from(bytes)
}

pub fn unpad(data: &Data) -> Result<Data> {
    let Some(&padding) = data.last() else {
        return Ok(data.clone());
    };

    let len = data.len();

    if data.get(len - 1).is_none_or(|b| *b != padding) {
        return Err(Error::InvalidPadding(padding));
    }

    let Some(last) = data.get(len - padding as usize..) else {
        return Err(Error::InvalidPadding(padding));
    };

    if !last.iter().all_equal() {
        return Err(Error::InvalidPadding(padding));
    }

    let bytes = data
        .iter()
        .copied()
        .take(len - padding as usize)
        .collect_vec();
    Ok(Data::from(bytes))
}

impl Data {
    #[must_use]
    pub fn pad(&self, blocksize: usize) -> Data {
        pad(self, blocksize)
    }

    pub fn unpad(&self) -> Result<Data> {
        unpad(self)
    }
}
