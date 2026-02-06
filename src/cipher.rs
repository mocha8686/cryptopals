//! Ciphers for encrypting and decrypting text.
//!
//! For developing real applications, it's probably better to use a real, established library such
//! as the ones by [the RustCrypto group][https://github.com/RustCrypto/].

use crate::Data;

pub(crate) mod aes_cbc;
pub(crate) mod aes_ecb;

pub use aes_cbc::AesCbc;
pub use aes_ecb::AesEcb;

/// Interface for defining a cipher.
pub trait Cipher {
    /// Associated error type for errors during encryption or decryption.
    type Error;

    /// Decrypt a piece of data using the cipher.
    fn decrypt(&mut self, data: &Data) -> Result<Data, Self::Error>;

    /// Encrypt a piece of data using the cipher.
    fn encrypt(&mut self, data: &Data) -> Result<Data, Self::Error>;
}
