#![allow(clippy::missing_errors_doc, reason = "ignore docs for now")]

pub mod attack;
pub mod cipher;
pub mod data;
pub mod error;
pub mod hamming_distance;
pub mod pad;

pub use data::Data;
pub use error::{Error, Result};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s1c1_convert_hex_to_base64() -> Result<()> {
        let res = Data::from_hex_str("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")?
            .base64();

        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            res
        );

        Ok(())
    }
}
