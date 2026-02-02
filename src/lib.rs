//! A collection of tools for completing the [cryptopals crypto challenges](https://cryptopals.com).
//!
//! Functionality is split into modules, grouped by general usage:
//! - [`cipher`] – Working with ciphers such as XOR, AES-128 in ECB or CBC mode, and others
//! - [`blackbox`] – Mock implementations of real-life systems for testing attacks
//! - [`error`] – Error types
//! - [`attack`] – Attacks on different [ciphers][cipher] and [blackboxes][blackbox]

#![warn(missing_docs, clippy::missing_docs_in_private_items)]

/// Collection of attacks on ciphers and certain blackboxes.
///
/// Attacks may require certain side-channels, sufficiently long ciphertexts, a partial or full
/// ciphertext decryption sample, or other additional info. The effects range from ciphertext
/// injection (e.g. `admin=true`), to partial plaintext extraction, or for some cases, a full key
/// extraction and plaintext decryption.
pub mod attack;

/// Mock implementations of certain vulnerable parts of real-world systems.
pub mod blackbox;

/// Ciphers for encrypting and decrypting text.
pub mod cipher;

mod data;

/// Error types.
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
