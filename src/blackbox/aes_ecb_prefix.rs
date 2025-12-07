use aes::{
    Aes128,
    cipher::{KeyInit, generic_array::GenericArray},
};

use crate::{AesEcb, Data, Result, cipher::Cipher};

use super::Blackbox;

const UNKNOWN_STR: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

pub struct AesEcbPrefix {
    cipher: AesEcb,
}

impl AesEcbPrefix {
    #[must_use]
    pub fn new() -> Self {
        let key: [u8; 16] = rand::random();
        let key = GenericArray::from(key);
        let cipher = Aes128::new(&key);
        let cipher = AesEcb::init(cipher, false);

        Self { cipher }
    }
}

impl Default for AesEcbPrefix {
    fn default() -> Self {
        Self::new()
    }
}

impl Blackbox for AesEcbPrefix {
    fn process(&mut self, data: &Data) -> Result<Data> {
        let bytes: Box<[u8]> = data.iter().chain(UNKNOWN_STR.as_bytes()).copied().collect();
        let data = Data::from(bytes);
        self.cipher.encode(&data)
    }
}
