use anyhow::Result;

use crate::data::Data;

mod aes_128_ecb;

trait Cipher {
    fn encrypt(&self, plaintext: &Data) -> Result<Data>;
    fn decrypt(&self, ciphertext: &Data) -> Result<Data>;
}
