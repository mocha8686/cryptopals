use anyhow::Result;

use super::Aes128Ecb;
use crate::{cipher::Encrypt, data::Data};

#[derive(Debug, Clone)]
pub struct Prefix {
    cipher: Aes128Ecb,
    unknown: Data,
}

impl Prefix {
    pub fn new(key: [u8; 16], unknown: Data) -> Self {
        Self {
            cipher: Aes128Ecb::new(key),
            unknown,
        }
    }
}

impl Encrypt for Prefix {
    fn encrypt(&self, plaintext: &Data) -> Result<Data> {
        self.cipher.encrypt(&(plaintext + &self.unknown))
    }
}
