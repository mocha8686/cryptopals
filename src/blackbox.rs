use crate::{Data, Result};

pub mod aes_ecb_cbc;

pub trait Blackbox {
    fn process(&mut self, data: &Data) -> Result<Data>;
}
