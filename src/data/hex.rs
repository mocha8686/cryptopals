use crate::{Result, error::ParseError};

use super::Data;

impl Data {
    pub fn from_hex<T: AsRef<[u8]>>(input: T) -> Result<Self> {
        let bytes = hex::decode(input).map_err(ParseError::from)?;
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
    use super::*;

    #[test]
    fn is_invertible() -> Result<()> {
        let s = "hello, world!";
        let data = Data::from_hex(&Data::from(s.as_bytes()).hex())?;
        assert_eq!(s, data);
        Ok(())
    }
}