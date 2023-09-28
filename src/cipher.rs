use anyhow::Result;

use crate::data::Data;

pub mod aes_128_cbc;
pub mod aes_128_ecb;

pub trait Cipher {
    fn encrypt(&self, plaintext: &Data) -> Result<Data>;
    fn decrypt(&self, ciphertext: &Data) -> Result<Data>;
}
