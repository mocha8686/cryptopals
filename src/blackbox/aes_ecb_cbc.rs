use crate::{AesCbc, AesEcb, Data, Result, cipher::Cipher};
use aes::{
    Aes128,
    cipher::{KeyInit, generic_array::GenericArray},
};
use itertools::Itertools;
use rand::Rng;

use super::Blackbox;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EcbOrCbc {
    Ecb,
    Cbc,
}

#[derive(Debug, Clone)]
pub struct AesEcbOrCbc {
    cipher: Aes128,
    mode: Option<EcbOrCbc>,
}

impl AesEcbOrCbc {
    #[must_use]
    pub fn new(mode: Option<EcbOrCbc>) -> Self {
        let key: [u8; 16] = rand::random();
        let key = GenericArray::from(key);
        let cipher = Aes128::new(&key);

        Self { cipher, mode }
    }
}

impl Default for AesEcbOrCbc {
    fn default() -> Self {
        Self::new(None)
    }
}

impl Blackbox for AesEcbOrCbc {
    fn process(&mut self, data: &Data) -> Result<Data> {
        let mut rng = rand::rng();
        let mut cipher: Box<dyn Cipher> =
            if self.mode.is_some_and(|m| matches!(m, EcbOrCbc::Ecb)) || (self.mode.is_none() && rng.random()) {
                let cipher = AesEcb::init(self.cipher.clone(), true);
                Box::new(cipher)
            } else {
                let mut iv = [0u8; 16];
                rng.fill(&mut iv);
                let cipher = AesCbc::init(self.cipher.clone(), iv);
                Box::new(cipher)
            };

        let prefix_count = rng.random_range(5..=10);
        let suffix_count = rng.random_range(5..=10);
        let mut new_bytes = vec![0; prefix_count + data.len() + suffix_count];
        rng.fill(new_bytes.as_mut_slice());
        new_bytes[prefix_count..prefix_count + data.len()].copy_from_slice(data);

        let data = Data::from(new_bytes);
        let data = cipher.encode(&data)?;
        Ok(data)
    }
}

pub fn detect_aes_mode(blackbox: &mut dyn Blackbox) -> Result<EcbOrCbc> {
    const BLOCKSIZE: usize = 16;
    let data = Data::from([b'A'; BLOCKSIZE * 3]);
    let res = blackbox.process(&data)?;

    let mode = if res
        .chunks(BLOCKSIZE)
        .inspect(|c| {
            dbg!(hex::encode(c));
        })
        .counts()
        .into_values()
        .any(|v| v > 1)
    {
        EcbOrCbc::Ecb
    } else {
        EcbOrCbc::Cbc
    };

    Ok(mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_mode(mode: EcbOrCbc) -> Result<()> {
        dbg!(mode);
        let mut blackbox = AesEcbOrCbc::new(Some(mode));
        let res = detect_aes_mode(&mut blackbox)?;
        assert_eq!(mode, res);
        Ok(())
    }

    #[test]
    fn s2c11_an_ecb_cbc_detection_oracle() -> Result<()> {
        test_mode(EcbOrCbc::Ecb)?;
        test_mode(EcbOrCbc::Cbc)?;

        Ok(())
    }

    #[test]
    fn s2c11_an_ecb_cbc_detection_oracle_x100() -> Result<()> {
        for _ in 0..100 {
            test_mode(EcbOrCbc::Ecb)?;
            test_mode(EcbOrCbc::Cbc)?;
        }

        Ok(())
    }
}
