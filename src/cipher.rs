use crate::{Data, Result};

pub mod aes_cbc;
pub mod aes_ecb;

pub use aes_cbc::AesCbc;
pub use aes_ecb::AesEcb;

pub trait Cipher {
    fn decode(&mut self, data: &Data) -> Result<Data>;
    fn encode(&mut self, data: &Data) -> Result<Data>;
}
