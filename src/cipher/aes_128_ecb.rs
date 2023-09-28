use anyhow::Result;
use openssl::symm::{self, Cipher as OpenSslCipher};

use crate::data::Data;

use super::Cipher;

pub struct Aes128Ecb {
    key: [u8; 16],
}

impl Aes128Ecb {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }
}

impl Cipher for Aes128Ecb {
    fn encrypt(&self, plaintext: &Data) -> Result<crate::data::Data> {
        Ok(Data::from(symm::encrypt(
            OpenSslCipher::aes_128_ecb(),
            &self.key,
            None,
            plaintext.bytes(),
        )?))
    }

    fn decrypt(&self, ciphertext: &Data) -> Result<Data> {
        Ok(Data::from(symm::decrypt(
            OpenSslCipher::aes_128_ecb(),
            &self.key,
            None,
            ciphertext.bytes(),
        )?))
    }
}

#[cfg(test)]
mod tests {
    use crate::{oracle::count_repeating_blocks, FUNKY_MUSIC};

    use super::*;

    #[test]
    fn cryptopals() -> Result<()> {
        let input = include_str!("../../data/1/7.txt").trim().replace('\n', "");
        let ciphertext = Data::from_b64(&input)?;

        let key = "YELLOW SUBMARINE".as_bytes().try_into()?;
        let cipher = Aes128Ecb::new(key);

        let res = cipher.decrypt(&ciphertext)?;
        assert_eq!(res, FUNKY_MUSIC.parse()?);

        Ok(())
    }

    #[test]
    fn test() -> Result<()> {
        let input = include_str!("../../data/1/7.txt").trim().replace('\n', "");
        let ciphertext = Data::from_b64(&input)?;

        let key = "YELLOW SUBMARINE".as_bytes().try_into()?;
        let cipher = Aes128Ecb::new(key);
        let res = cipher.decrypt(&ciphertext)?;

        let encrypted_res = cipher.encrypt(&res)?;
        assert_eq!(encrypted_res, ciphertext);

        Ok(())
    }

    #[test]
    fn detect() -> Result<()> {
        let input = include_str!("../../data/1/8.txt").trim().to_owned();
        let res = input
            .lines()
            .flat_map(|line| Data::from_hex(line.trim()))
            .max_by_key(|data| count_repeating_blocks(data, 16))
            .unwrap();

        assert_eq!(
            res,
            Data::from_hex("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")?
        );

        Ok(())
    }
}
