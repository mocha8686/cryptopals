use std::rc::Rc;

use anyhow::Result;
use openssl::symm::{Crypter, Mode};

use crate::{cipher::aes_128_ecb::Aes128Ecb, data::Data, pkcs7};

use super::Cipher;

pub struct Aes128Cbc {
    key: [u8; 16],
    iv: [u8; 16],
}

impl Aes128Cbc {
    pub fn new(key: [u8; 16], iv: [u8; 16]) -> Self {
        Self { key, iv }
    }
}

impl Cipher for Aes128Cbc {
    fn encrypt(&self, plaintext: &Data) -> Result<Data> {
        let cipher = Aes128Ecb::new(self.key);
        let padded = pkcs7::pad(plaintext, 16);
        let bytes = padded.bytes();
        let (ciphertext, _) = bytes.chunks_exact(16).map(Data::from).try_fold(
            (Data::from(&self.iv[..]), Data::new()),
            |(prev, ciphertext), chunk| {
                let xor_chunk = &prev ^ &chunk;
                let ciphertext_chunk = cipher.encrypt(&xor_chunk)?;
                anyhow::Ok((chunk, ciphertext + ciphertext_chunk))
            },
        )?;
        Ok(ciphertext)
    }

    fn decrypt(&self, ciphertext: &Data) -> Result<Data> {
        let decrypted = {
            let mut decrypter = Crypter::new(
                openssl::symm::Cipher::aes_128_ecb(),
                Mode::Decrypt,
                &self.key,
                Some(&self.iv),
            )
            .unwrap();
            decrypter.pad(false);

            let block_size = openssl::symm::Cipher::aes_128_ecb().block_size();
            let mut decrypted_bytes = vec![0; ciphertext.len() + block_size];
            let mut count = decrypter
                .update(ciphertext.bytes(), &mut decrypted_bytes)
                .unwrap();
            count += decrypter.finalize(&mut decrypted_bytes[count..]).unwrap();
            decrypted_bytes.truncate(count);

            Data::from(decrypted_bytes)
        };

        let xor = Data::from(
            self.iv[..]
                .iter()
                .chain(ciphertext.bytes().iter())
                .take(ciphertext.len())
                .copied()
                .collect::<Rc<_>>(),
        );
        let xored = decrypted ^ xor;
        let plaintext = pkcs7::unpad(&xored);
        Ok(plaintext.into_owned())
    }
}

#[cfg(test)]
mod tests {
    use crate::{pkcs7::unpad, FUNKY_MUSIC};

    use super::*;

    #[test]
    fn cryptopals_test() -> Result<()> {
        let input = include_str!("../../data/2/10.txt").trim().replace('\n', "");
        let ciphertext = Data::from_b64(&input)?;

        let key = "YELLOW SUBMARINE".as_bytes().try_into()?;
        let iv = [0u8; 16];
        let cipher = Aes128Cbc::new(key, iv);

        let res = cipher.decrypt(&ciphertext)?;
        let unpadded = unpad(&res);

        assert_eq!(unpadded.into_owned(), FUNKY_MUSIC.parse()?);

        Ok(())
    }
}
