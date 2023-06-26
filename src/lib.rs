use anyhow::Result;
use base64::{engine::general_purpose, Engine};

pub struct Data(Box<[u8]>);

impl Data {
    fn from_hex(data: &str) -> Result<Self> {
        Ok(Self(hex::decode(data)?.into()))
    }

    fn from_b64(data: &str) -> Result<Self> {
        Ok(Self(general_purpose::STANDARD_NO_PAD.decode(data)?.into()))
    }

    fn as_b64(&self) -> String {
        general_purpose::STANDARD_NO_PAD.encode(&self.0)
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
}
