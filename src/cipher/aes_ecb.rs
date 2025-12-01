use aes::{
    Aes128,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, generic_array::GenericArray},
};
use itertools::Itertools;

use crate::{Data, Error, Result};

use super::Cipher;

pub struct AesEcb {
    cipher: Aes128,
    pad: bool,
}

impl AesEcb {
    pub fn new(key: impl AsRef<[u8]>, pad: bool) -> Result<Self> {
        let key = key.as_ref();
        let cipher = Aes128::new_from_slice(key).map_err(|_| Error::InvalidLength {
            expected: 16,
            actual: key.len(),
        })?;

        Ok(Self { cipher, pad })
    }
}

impl Cipher for AesEcb {
    fn decode(&mut self, data: &Data) -> Result<Data> {
        let bytes = data
            .pad(16)
            .iter()
            .copied()
            .chunks(16)
            .into_iter()
            .filter_map(itertools::Itertools::collect_array::<16>)
            .map(GenericArray::from)
            .flat_map(|mut block| {
                self.cipher.decrypt_block_mut(&mut block);
                block
            })
            .collect_vec();

        if self.pad {
            let data = Data::from(bytes).unpad()?;
            Ok(data)
        } else {
            Ok(Data::from(bytes))
        }
    }

    fn encode(&mut self, data: &Data) -> Result<Data> {
        let bytes = data
            .iter()
            .copied()
            .chunks(16)
            .into_iter()
            .filter_map(itertools::Itertools::collect_array::<16>)
            .map(GenericArray::from)
            .flat_map(|mut block| {
                self.cipher.encrypt_block_mut(&mut block);
                block
            })
            .collect_vec();

        if self.pad {
            let data = Data::from(bytes).pad(16);
            Ok(data)
        } else {
            Ok(Data::from(bytes))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s1c7_aes_in_ecb_mode() -> Result<()> {
        let text = include_str!("../../data/7.txt").replace('\n', "");
        let data = Data::from_base64_str(&text)?;
        let mut cipher = AesEcb::new("YELLOW SUBMARINE", true)?;
        let res = data.decode(&mut cipher)?;

        assert_eq!(include_str!("../../data/funky.txt"), res.to_string());

        Ok(())
    }
}
