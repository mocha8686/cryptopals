use aes::{
    Aes128,
    cipher::{BlockEncryptMut, KeyInit, generic_array::GenericArray},
};
use itertools::Itertools;

use crate::{Data, Error, Result, cipher::aes_ecb::AesEcb, error::InvalidLengthType};

use super::Cipher;

const BLOCKSIZE: u8 = 16;
const BLOCKSIZE_USIZE: usize = BLOCKSIZE as usize;

#[derive(Debug, Clone)]
pub struct AesCbc {
    cipher: Aes128,
    iv: [u8; BLOCKSIZE_USIZE],
}

impl AesCbc {
    pub fn new(key: impl AsRef<[u8]>, iv: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let iv = iv.as_ref();

        let cipher = Aes128::new_from_slice(key).map_err(|_| Error::InvalidLength {
            kind: InvalidLengthType::Key,
            expected: BLOCKSIZE_USIZE,
            actual: key.len(),
        })?;

        let iv = iv.try_into().map_err(|_| Error::InvalidLength {
            kind: InvalidLengthType::IV,
            expected: BLOCKSIZE_USIZE,
            actual: iv.len(),
        })?;

        Ok(Self::init(cipher, iv))
    }

    #[must_use]
    pub fn init(cipher: Aes128, iv: [u8; BLOCKSIZE_USIZE]) -> Self {
        Self { cipher, iv }
    }
}

impl Cipher for AesCbc {
    fn decode(&mut self, data: &Data) -> Result<Data> {
        let mut ecb = AesEcb::init(self.cipher.clone(), false);
        let decoded = ecb.decode(data)?;

        let xor: Box<[u8]> = self
            .iv
            .iter()
            .chain(data.iter().dropping_back(BLOCKSIZE_USIZE))
            .copied()
            .collect();
        let xor = Data::from(xor);

        let res = decoded ^ xor;
        let res = res.unpad()?;
        Ok(res)
    }

    fn encode(&mut self, data: &Data) -> Result<Data> {
        let (_, bytes) = data.pad(BLOCKSIZE).chunks(BLOCKSIZE_USIZE).fold(
            (Data::from(self.iv), vec![]),
            |(prev, mut acc): (Data, Vec<u8>), data| {
                let data = Data::from(data);
                let mut xor = prev ^ &data;
                let bytes = GenericArray::from_mut_slice(&mut xor);
                self.cipher.encrypt_block_mut(bytes);
                acc.extend(bytes.as_slice());
                (data, acc)
            },
        );
        let data = Data::from(bytes);
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use miette::Result;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn s2c10_implement_cbc_mode() -> Result<()> {
        let text = include_str!("../../data/10.txt").replace('\n', "");
        let data = Data::from_base64(text)?;
        let mut cipher = AesCbc::new("YELLOW SUBMARINE", [0u8; BLOCKSIZE_USIZE])?;
        let res = cipher.decode(&data)?;

        assert_eq!(include_str!("../../data/funky.txt"), res.to_string());

        Ok(())
    }
}
