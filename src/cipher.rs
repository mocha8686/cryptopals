use crate::{Data, Result};

pub mod aes_ecb;

pub trait Cipher {
    fn decode(&mut self, data: &Data) -> Result<Data>;
    fn encode(&mut self, data: &Data) -> Result<Data>;
}

impl Data {
    pub fn decode(&self, cipher: &mut impl Cipher) -> Result<Data> {
        cipher.decode(self)
    }

    pub fn encode(&self, cipher: &mut impl Cipher) -> Result<Data> {
        cipher.encode(self)
    }
}
