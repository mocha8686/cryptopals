//! Hex string handling.

use hex::FromHexError;

use crate::{
    Result,
    error::{ParseError, format_error_input, map_label_index},
};

use super::Data;

impl Data {
    /// Parse a hex string into the bytes, storing it into a [`Data`] struct.
    ///
    /// # Errors
    ///
    /// Returns an error if the string isn't an even length, or if there's an invalid character
    /// (that is, not in `[0-9A-Fa-f]`).
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptopals::Data;
    ///
    /// # fn main() -> cryptopals::Result<()> {
    /// let data = Data::from_hex("68656c6c6f2c20776f726c6421")?;
    /// assert_eq!("hello, world!", data.to_string());
    /// # Ok(())
    /// # }
    /// ```
    pub fn from_hex(input: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = hex::decode(&input).map_err(|e| ParseError::Hex {
            input: format_error_input(input.as_ref(), false),
            label: match e {
                FromHexError::InvalidHexCharacter { index, .. } => Some(map_label_index(index)),
                _ => None,
            },
            source: e,
        })?;
        let res = Self(bytes.into_boxed_slice());
        Ok(res)
    }

    /// Create a hex string using this [`Data`]'s bytes.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptopals::Data;
    ///
    /// let data = Data::from("hello, world!".as_bytes());
    /// let hex = data.hex();
    /// assert_eq!("68656c6c6f2c20776f726c6421", hex);
    /// ```
    #[must_use]
    pub fn hex(&self) -> String {
        hex::encode(self)
    }
}

#[cfg(test)]
mod tests {
    use miette::Result;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn is_involution() -> Result<()> {
        let s = "hello, world!";
        let data = Data::from_hex(&Data::from(s.as_bytes()).hex())?;
        assert_eq!(s, data);
        Ok(())
    }
}
