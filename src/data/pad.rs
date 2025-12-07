use itertools::Itertools;

use crate::{Data, Error, Result};

impl Data {
    #[expect(
        clippy::cast_possible_truncation,
        reason = "modulo wraps usize into u8"
    )]
    #[must_use]
    pub fn pad(&self, blocksize: u8) -> Data {
        let len = self.len();

        let padding = blocksize as usize - (len % blocksize as usize);
        let padding = if padding == 0 {
            blocksize
        } else {
            padding as u8
        };

        let bytes: Box<[u8]> = self
            .iter()
            .copied()
            .chain((0..padding).map(|_| padding))
            .collect();
        Data::from(bytes)
    }

    pub fn unpad(&self) -> Result<Data> {
        let Some(&padding) = self.last() else {
            return Ok(self.clone());
        };

        let len = self.len();

        if self.get(len - 1).is_none_or(|b| *b != padding) {
            return Err(Error::InvalidPadding(padding));
        }

        let Some(last) = self.get(len - padding as usize..) else {
            return Err(Error::InvalidPadding(padding));
        };

        if !last.iter().all_equal() {
            return Err(Error::InvalidPadding(padding));
        }

        let bytes = self
            .iter()
            .copied()
            .take(len - padding as usize)
            .collect_vec();
        Ok(Data::from(bytes))
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

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
