use base64::{
    DecodeError, Engine,
    engine::{GeneralPurpose, general_purpose::STANDARD},
};

use crate::{
    Result,
    error::{ParseError, format_error_input, map_label_index},
};

use super::Data;

const ENGINE: GeneralPurpose = STANDARD;

impl Data {
    /// Parse a [Base64] string into the bytes, storing it into a [`Data`] struct.
    ///
    /// [Base64]: https://en.wikipedia.org/wiki/Base64
    pub fn from_base64(input: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = ENGINE.decode(&input).map_err(|e| {
            let input = input.as_ref();
            let input_len = input.len();

            ParseError::Base64 {
                input: format_error_input(input, false),
                label: match e {
                    DecodeError::InvalidByte(index, _)
                    | DecodeError::InvalidLastSymbol(index, _) => Some(map_label_index(index, input_len)),
                    _ => None,
                },
                source: e,
            }
        })?;
        let res = Self(bytes.into_boxed_slice());
        Ok(res)
    }

    /// Create a [Base64] string using this [`Data`]'s bytes.
    ///
    /// [Base64]: https://en.wikipedia.org/wiki/Base64
    #[must_use]
    pub fn base64(&self) -> String {
        ENGINE.encode(self)
    }
}

#[cfg(test)]
mod tests {
    use miette::Result;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn is_invertible() -> Result<()> {
        let s = "hello, world!";
        let data = Data::from_base64(&Data::from(s.as_bytes()).base64())?;
        assert_eq!(s, data);
        Ok(())
    }
}
