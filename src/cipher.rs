use anyhow::Result;

use crate::data::Data;

pub mod aes_128_cbc;
pub mod aes_128_ecb;

pub trait Encrypt {
    fn encrypt(&self, plaintext: &Data) -> Result<Data>;
}

pub trait Decrypt {
    fn decrypt(&self, ciphertext: &Data) -> Result<Data>;
}
