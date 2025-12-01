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
    let padding = ((blocksize - (len % blocksize) - 1).rem_euclid(blocksize) + 1) as u8;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_equal_to_blocksize() {
        let res = Data::from("hello".as_bytes()).pad(5);
        assert_eq!("hello\x05\x05\x05\x05\x05", res);
    }

    #[test]
    fn s2c9_implement_pkcs7_padding() {
        let res = Data::from("YELLOW SUBMARINE".as_bytes()).pad(20);
        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04", res);
    }
}
