use crate::{Data, Result};

pub mod aes_cbc;
pub mod aes_ecb;

pub trait Cipher {
    fn decode(&mut self, data: &Data) -> Result<Data>;
    fn encode(&mut self, data: &Data) -> Result<Data>;
}
