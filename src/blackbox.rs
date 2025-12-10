use crate::Data;

pub mod aes_ecb_cbc;
pub mod aes_ecb_prefix;

pub trait Blackbox {
    type Error;

    fn process(&mut self, data: &Data) -> Result<Data, Self::Error>;
}
