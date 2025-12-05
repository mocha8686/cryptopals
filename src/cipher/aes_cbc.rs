use aes::{
    Aes128,
    cipher::{BlockEncryptMut, KeyInit, generic_array::GenericArray},
};
use itertools::Itertools;

use crate::{Data, Error, Result, cipher::aes_ecb::AesEcb, error::InvalidLengthType};

use super::Cipher;

pub struct AesCbc {
    cipher: Aes128,
    iv: [u8; 16],
}

impl AesCbc {
    pub fn new(key: impl AsRef<[u8]>, iv: impl AsRef<[u8]>) -> Result<Self> {
        let key = key.as_ref();
        let iv = iv.as_ref();

        let cipher = Aes128::new_from_slice(key).map_err(|_| Error::InvalidLength {
            kind: InvalidLengthType::Key,
            expected: 16,
            actual: key.len(),
        })?;

        let iv = iv.try_into().map_err(|_| Error::InvalidLength {
            kind: InvalidLengthType::IV,
            expected: 16,
            actual: iv.len(),
        })?;

        Ok(Self { cipher, iv })
    }
}

impl Cipher for AesCbc {
    fn decode(&mut self, data: &Data) -> Result<Data> {
        let mut ecb = AesEcb {
            cipher: self.cipher.clone(),
            pad: false,
        };
        let decoded = ecb.decode(data)?;

        let mut xor = self.iv.to_vec();
        xor.extend(data.iter().copied().dropping_back(16));
        let xor = Data::from(xor);

        let res = decoded ^ xor;
        let res = res.unpad()?;
        Ok(res)
    }

    fn encode(&mut self, data: &Data) -> Result<Data> {
        let (_, bytes) = data.pad(16).chunks(16).fold(
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
    use super::*;

    #[test]
    fn s2c10_implement_cbc_mode() -> Result<()> {
        let text = include_str!("../../data/10.txt").replace('\n', "");
        let data = Data::from_base64(text)?;
        let mut cipher = AesCbc::new("YELLOW SUBMARINE", [0u8; 16])?;
        let res = cipher.decode(&data)?;

        assert_eq!(include_str!("../../data/funky.txt"), res.to_string());

        Ok(())
    }
}
