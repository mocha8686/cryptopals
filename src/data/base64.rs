use base64::{
    DecodeError, Engine,
    engine::{GeneralPurpose, general_purpose::STANDARD},
};
use itertools::Itertools;

use crate::{
    Result,
    error::{INPUT_CHUNK_SIZE, ParseError},
};

use super::Data;

const ENGINE: GeneralPurpose = STANDARD;

impl Data {
    /// Parse a [Base64] string into the bytes, storing it into a [`Data`] struct.
    ///
    /// [Base64]: https://en.wikipedia.org/wiki/Base64
    pub fn from_base64(input: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = ENGINE.decode(&input).map_err(|e| ParseError::Base64 {
            input: input
                .as_ref()
                .chunks(INPUT_CHUNK_SIZE)
                .map(String::from_utf8_lossy)
                .join("\n"),
            label: match e {
                DecodeError::InvalidByte(i, _) | DecodeError::InvalidLastSymbol(i, _) => Some(i),
                _ => None,
            }
            .map(|i| i + (i / INPUT_CHUNK_SIZE)),
            source: e,
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
