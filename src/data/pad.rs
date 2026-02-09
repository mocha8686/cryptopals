//! [PKCS #7 padding][PKCS7] implementation.
//!
//! [PKCS7]: https://en.wikipedia.org/wiki/PKCS_7

use itertools::Itertools;

use crate::{
    Data, Result,
    error::{PaddingError, format_error_input, map_label_index_length_hex},
};

impl Data {
    /// Pad a piece of [`Data`] to the next multiple of `blocksize` using [the PKCS #7
    /// standard][PKCS7].
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptopals::Data;
    ///
    /// let data = Data::from("hello".as_bytes());
    /// let padded = data.pad(8);
    /// assert_eq!("hello\x03\x03\x03", padded);
    /// ```
    ///
    /// [PKCS7]: https://en.wikipedia.org/wiki/PKCS_7
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

    /// Remove padding from a piece of [`Data`] using the last byte as the `blocksize`, as in
    /// [the PKCS #7 standard][PKCS7].
    ///
    /// # Errors
    ///
    /// Returns an error if the padding is invalid. See [`PaddingError`] for more details.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptopals::Data;
    ///
    /// let data = Data::from("hello\x03\x03\x03".as_bytes());
    /// let unpadded = data.unpad();
    ///
    /// let expected = Data::from("hello".as_bytes());
    /// assert_eq!(Ok(expected), unpadded);
    /// ```
    ///
    /// [PKCS7]: https://en.wikipedia.org/wiki/PKCS_7
    pub fn unpad(&self) -> Result<Data> {
        let Some(&padding) = self.last() else {
            return Ok(self.clone());
        };

        let len = self.len();

        let last = self
            .get(len.wrapping_sub(padding as usize)..)
            .ok_or(PaddingError::InputTooShort { byte: padding, len })?;

        if !last.iter().all(|b| *b == padding) {
            let start = len - padding as usize;

            return Err(PaddingError::InvalidPadding {
                byte: padding,
                input: format_error_input(self, true),
                label: map_label_index_length_hex(start, padding as usize),
            }
            .into());
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

    use crate::Error;

    use super::*;

    #[test]
    fn pad_equal_to_blocksize() {
        let res = Data::from("hello".as_bytes()).pad(5);
        assert_eq!("hello\x05\x05\x05\x05\x05", res);
    }

    #[test]
    fn unpad_errors() {
        let too_short = Data::from("hello\x10".as_bytes()).unpad();
        assert_eq!(
            Err(Error::PaddingError(PaddingError::InputTooShort {
                byte: 0x10,
                len: 6
            })),
            too_short
        );

        let invalid_padding = Data::from("hello, world!\x04\x04\x04".as_bytes()).unpad();
        assert_eq!(
            Err(Error::PaddingError(PaddingError::InvalidPadding {
                byte: 0x04,
                input: "68656c6c6f2c20776f726c6421040404".into(),
                label: (24, 8)
            })),
            invalid_padding
        );
    }

    #[test]
    fn s2c9_implement_pkcs7_padding() {
        let res = Data::from("YELLOW SUBMARINE".as_bytes()).pad(20);
        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04", res);
    }
}
