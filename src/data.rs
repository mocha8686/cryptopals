use std::{
    borrow::{Borrow, Cow},
    cmp::Ordering,
    fmt::Display,
    ops::{Add, BitXor},
    str::FromStr,
};

use anyhow::Result;
use base64::{engine::general_purpose, Engine};

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Data(Vec<u8>);

impl Data {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn from_hex(data: &str) -> Result<Self> {
        Ok(Self(hex::decode(data)?))
    }

    pub fn from_b64(data: &str) -> Result<Self> {
        Ok(Self(general_purpose::STANDARD.decode(data)?))
    }

    pub fn bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.bytes().len()
    }

    pub fn as_hex(&self) -> String {
        hex::encode(&self.0)
    }

    pub fn as_b64(&self) -> String {
        general_purpose::STANDARD.encode(&self.0)
    }
}

impl Default for Data {
    fn default() -> Self {
        Self::new()
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
        write!(f, "{}", String::from_utf8_lossy(&self.0))
    }
}

impl<T: Into<Vec<u8>>> From<T> for Data {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl<T: Borrow<Data>> Add<T> for &Data {
    type Output = Data;

    fn add(self, rhs: T) -> Self::Output {
        Data::from(
            self.bytes()
                .iter()
                .chain(rhs.borrow().bytes().iter())
                .copied()
                .collect::<Vec<_>>(),
        )
    }
}

impl<T: Borrow<Data>> Add<T> for Data {
    type Output = Data;

    fn add(self, rhs: T) -> Self::Output {
        &self + rhs
    }
}

impl<T: Borrow<Data>> BitXor<T> for &Data {
    type Output = Data;

    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_precision_loss,
        clippy::cast_sign_loss
    )]
    fn bitxor(self, rhs: T) -> Self::Output {
        let mut lhs = Cow::from(&*self.0);
        let mut rhs = Cow::from(&*rhs.borrow().0);

        let lhs_len = lhs.len();
        let rhs_len = rhs.len();
        match lhs_len.cmp(&rhs_len) {
            Ordering::Less => {
                *lhs.to_mut() = lhs.repeat((rhs_len as f64 / lhs_len as f64).ceil() as usize);
            }
            Ordering::Greater => {
                *rhs.to_mut() = rhs.repeat((lhs_len as f64 / rhs_len as f64).ceil() as usize);
            }
            Ordering::Equal => {}
        }

        let xor_bytes = lhs
            .iter()
            .zip(rhs.iter())
            .map(|(lhs, rhs)| lhs ^ rhs)
            .collect();

        Data(xor_bytes)
    }
}

impl<T: Borrow<Data>> BitXor<T> for Data {
    type Output = Data;

    fn bitxor(self, rhs: T) -> Self::Output {
        &self ^ rhs
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

    #[test]
    fn repeating_key_xor() -> Result<()> {
        let plaintext: Data =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .parse()?;
        let key: Data = "ICE".parse()?;
        let ciphertext = plaintext ^ key;

        assert_eq!(
            ciphertext,
            Data::from_hex(
                "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
            )?
        );

        Ok(())
    }
}
