use hex::FromHexError;
use itertools::Itertools;

use crate::{Result, error::{INPUT_CHUNK_SIZE, ParseError}};

use super::Data;

impl Data {
    pub fn from_hex(input: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = hex::decode(&input).map_err(|e| ParseError::Hex {
            input: input.as_ref().chunks(INPUT_CHUNK_SIZE).map(String::from_utf8_lossy).join("\n"),
            label: match e {
                FromHexError::InvalidHexCharacter { index, .. } => Some(index),
                _ => None,
            }.map(|i| i + (i / INPUT_CHUNK_SIZE)),
            source: e,
        })?;
        let res = Self(bytes.into_boxed_slice());
        Ok(res)
    }

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
    fn is_invertible() -> Result<()> {
        let s = "hello, world!";
        let data = Data::from_hex(&Data::from(s.as_bytes()).hex())?;
        assert_eq!(s, data);
        Ok(())
    }
}
