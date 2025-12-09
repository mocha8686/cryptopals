use aes::{
    Aes128,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, generic_array::GenericArray},
};
use itertools::Itertools;

use crate::{Data, Error, Result, error::InvalidLengthType};

use super::Cipher;

#[derive(Debug, Clone)]
pub struct AesEcb {
    cipher: Aes128,
    pad: bool,
}

impl AesEcb {
    pub fn new(key: impl AsRef<[u8]>, pad: bool) -> Result<Self> {
        let key = key.as_ref();
        let cipher = Aes128::new_from_slice(key).map_err(|_| Error::InvalidLength {
            kind: InvalidLengthType::Key,
            expected: 16,
            actual: key.len(),
        })?;

        Ok(Self::init(cipher, pad))
    }

    #[must_use]
    pub fn init(cipher: Aes128, pad: bool) -> Self {
        Self { cipher, pad }
    }
}

impl Cipher for AesEcb {
    fn decode(&mut self, data: &Data) -> Result<Data> {
        let bytes = data
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

#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    reason = "higher scores will be rare"
)]
pub fn score(bytes: &[u8]) -> u32 {
    bytes
        .chunks(16)
        .counts()
        .into_values()
        .map(|v| v.saturating_sub(1) as u32)
        .sum()
}

#[cfg(test)]
mod tests {
    use miette::Result;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn s1c7_aes_in_ecb_mode() -> Result<()> {
        let text = include_str!("../../data/7.txt").replace('\n', "");
        let data = Data::from_base64(&text)?;
        let mut cipher = AesEcb::new("YELLOW SUBMARINE", true)?;
        let res = cipher.decode(&data)?;

        assert_eq!(include_str!("../../data/funky.txt"), res.to_string());

        Ok(())
    }

    #[test]
    fn s1c8_detect_aes_in_ecb_mode() -> Result<()> {
        let text = include_str!("../../data/8.txt");
        let res = text
            .split('\n')
            .map(Data::from_hex)
            .collect::<crate::Result<Vec<_>>>()?
            .into_iter()
            .max_by_key(|d| score(d))
            .unwrap();

        assert_eq!(
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
            res.hex()
        );

        Ok(())
    }
}
