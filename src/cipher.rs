use anyhow::Result;

use crate::data::Data;

pub(crate) mod aes_128_ecb;
pub(crate) mod aes_128_cbc;

trait Cipher {
    const BLOCK_SIZE: u8;

    fn encrypt(&self, plaintext: &Data) -> Result<Data>;
    fn decrypt(&self, ciphertext: &Data) -> Result<Data>;
}
