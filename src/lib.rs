use std::ops::BitXor;

use anyhow::Result;
use base64::{engine::general_purpose, Engine};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Data(Box<[u8]>);

impl Data {
    fn from_hex(data: &str) -> Result<Self> {
        Ok(Self(hex::decode(data)?.into()))
    }

    fn from_b64(data: &str) -> Result<Self> {
        Ok(Self(general_purpose::STANDARD_NO_PAD.decode(data)?.into()))
    }

    fn as_hex(&self) -> String {
        hex::encode(&self.0)
    }

    fn as_b64(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(&self.0)
    }
}

impl BitXor for Data {
    type Output = Data;

    fn bitxor(self, rhs: Self) -> Self::Output {
        assert_eq!(self.0.len(), rhs.0.len(), "Data lengths must match.");

        let res = self
            .0
            .iter()
            .zip(rhs.0.iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect();
        Self(res)
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
        let expected = Data::from_hex("746865206b696420646f6e277420706c6179")?;

        assert_eq!(lhs ^ rhs, expected);
        Ok(())
    }
}
