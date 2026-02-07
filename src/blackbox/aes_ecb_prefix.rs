//! Implementation of the [`AesEcbPrefix`] blackbox.
// FIXME: rename to suffix

#![allow(missing_docs, clippy::missing_docs_in_private_items)] // TODO: remove when done with 2-12

use aes::{
    Aes128,
    cipher::{KeyInit, generic_array::GenericArray},
};

use crate::{AesEcb, Data, Result, cipher::Cipher};

use super::Blackbox;

// TODO: fill in `OUR ATTACK`
/// Fixed, unknown string, encoded in Base64 to be extracted by `OUR ATTACK`.
///
/// Taken from [set 2 challenge 12][challenge] of the [cryptopals] website.
///
/// [challenge]: https://cryptopals.com/sets/2/challenges/12
/// [cryptopals]: https://cryptopals.com/
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
    type Error = crate::Error;

    fn process(&mut self, data: &Data) -> Result<Data> {
        let bytes: Box<[u8]> = data.iter().chain(UNKNOWN_STR.as_bytes()).copied().collect();
        let data = Data::from(bytes);
        self.cipher.encrypt(&data)
    }
}
