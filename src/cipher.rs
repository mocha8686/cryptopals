use crate::Data;

pub mod aes_cbc;
pub mod aes_ecb;

pub use aes_cbc::AesCbc;
pub use aes_ecb::AesEcb;

pub trait Cipher {
    type Error;

    fn decode(&mut self, data: &Data) -> Result<Data, Self::Error>;
    fn encode(&mut self, data: &Data) -> Result<Data, Self::Error>;
}
