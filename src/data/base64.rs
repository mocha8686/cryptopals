use base64::{
    Engine,
    engine::{GeneralPurpose, general_purpose::STANDARD},
};

use crate::{Result, error::ParseError};

use super::Data;

const ENGINE: GeneralPurpose = STANDARD;

impl Data {
    pub fn from_base64<T: AsRef<[u8]>>(input: T) -> Result<Self> {
        let bytes = ENGINE.decode(input).map_err(ParseError::from)?;
        let res = Self(bytes.into_boxed_slice());
        Ok(res)
    }

    pub fn from_base64_str(input: &str) -> Result<Self> {
        Self::from_base64(input.as_bytes())
    }

    #[must_use]
    pub fn base64(&self) -> String {
        ENGINE.encode(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_invertible() -> Result<()> {
        let s = "hello, world!";
        let data = Data::from_base64_str(&Data::from(s.as_bytes()).base64())?;
        assert_eq!(s, data);
        Ok(())
    }
}
