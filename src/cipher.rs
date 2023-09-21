use anyhow::Result;

use crate::data::Data;

pub mod aes_128_cbc;
pub mod aes_128_ecb;

trait Cipher {
    const BLOCK_SIZE: u8;

    fn encrypt(&self, plaintext: &Data) -> Result<Data>;
    fn decrypt(&self, ciphertext: &Data) -> Result<Data>;
}
