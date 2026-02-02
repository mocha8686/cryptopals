//! A collection of tools for completing the [cryptopals crypto challenges](https://cryptopals.com).
//!
//! Functionality is split into modules, grouped by general usage:
//! - [`cipher`] – Working with ciphers such as XOR, AES-128 in ECB or CBC mode, and others
//! - [`blackbox`] – Mock implementations of real-life systems for testing attacks
//! - [`error`] – Error types
//! - [`attack`] – Attacks on different [ciphers][cipher] and [blackboxes][blackbox]

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

pub mod attack;
pub mod blackbox;
pub mod cipher;
mod data;
pub mod error;

pub use cipher::{AesCbc, AesEcb};
pub use data::Data;
pub use error::{Error, Result};

#[cfg(test)]
mod tests {
    use miette::Result;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn s1c1_convert_hex_to_base64() -> Result<()> {
        let res = Data::from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")?
            .base64();

        assert_eq!(
            "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
            res
        );

        Ok(())
    }
}
