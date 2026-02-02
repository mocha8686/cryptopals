//! Ciphers for encrypting and decrypting text.

use crate::Data;

pub mod aes_cbc;
pub mod aes_ecb;

pub use aes_cbc::AesCbc;
pub use aes_ecb::AesEcb;

pub trait Cipher {
    type Error;

    fn decrypt(&mut self, data: &Data) -> Result<Data, Self::Error>;
    fn encrypt(&mut self, data: &Data) -> Result<Data, Self::Error>;
}
