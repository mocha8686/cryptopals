use std::{borrow::Cow, fmt::Display, ops::BitXor, rc::Rc, str::FromStr};

use anyhow::Result;
use base64::{engine::general_purpose, Engine};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Data(Rc<[u8]>);

impl Data {
    pub fn from_hex(data: &str) -> Result<Self> {
        Ok(Self(hex::decode(data)?.into()))
    }

    pub fn from_b64(data: &str) -> Result<Self> {
        Ok(Self(general_purpose::STANDARD_NO_PAD.decode(data)?.into()))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn as_b64(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(&self.0)
    }
}

impl FromStr for Data {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(s.as_bytes().into()))
    }
}

impl Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            std::str::from_utf8(&self.0).unwrap_or("[invalid utf-8]")
        )
    }
}

impl<T: Into<Rc<[u8]>>> From<T> for Data {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl BitXor for &Data {
    type Output = Data;

    fn bitxor(self, rhs: Self) -> Self::Output {
        let mut lhs = Cow::from(&*self.0);
        let mut rhs = Cow::from(&*rhs.0);

        let lhs_len = lhs.len();
        let rhs_len = rhs.len();
        if lhs_len < rhs_len {
            *lhs.to_mut() = lhs.repeat((rhs_len as f64 / lhs_len as f64).ceil() as usize);
        } else if rhs_len < lhs_len {
            *rhs.to_mut() = rhs.repeat((lhs_len as f64 / rhs_len as f64).ceil() as usize);
        }

        let res = lhs
            .into_iter()
            .zip(rhs.into_iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect();
        Data(res)
    }
}

impl BitXor for Data {
    type Output = Data;

    fn bitxor(self, rhs: Self) -> Self::Output {
        &self ^ &rhs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convert_hex_to_base64() -> Result<()> {
        let data = Data::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")?;
        assert_eq!(
            data.as_b64(),
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
        );

        Ok(())
    }

    #[test]
    fn fixed_xor() -> Result<()> {
        let lhs = Data::from_hex("1c0111001f010100061a024b53535009181c")?;
        let rhs = Data::from_hex("686974207468652062756c6c277320657965")?;

        dbg!((&lhs ^ &rhs).to_string());

        assert_eq!(
            lhs ^ rhs,
            Data::from_hex("746865206b696420646f6e277420706c6179")?
        );
        Ok(())
    }
}