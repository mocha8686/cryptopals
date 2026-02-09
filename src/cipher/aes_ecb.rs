//! Implementation for the [`AesEcb`] cipher.

#![allow(clippy::missing_docs_in_private_items, reason = "self-documenting")]

use aes::{
    Aes128,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, generic_array::GenericArray},
};
use itertools::Itertools;

use crate::{
    Data, Error, Result,
    error::{CipherError, CipherErrorType, InvalidLengthType},
};

use super::Cipher;

/// Cipher blocksize.
pub const BLOCKSIZE: u8 = 16;

/// Cipher blocksize, as a [`usize`].
pub const BLOCKSIZE_USIZE: usize = BLOCKSIZE as usize;

/// Name of the cipher.
pub const CIPHER_NAME: &str = "AES-ECB";

/// Cipher for [AES-128] under [ECB mode].
///
/// ECB is extremely vulnerable and should not be used in production applications.
///
/// # Examples
///
/// ```
/// use cryptopals::{Data, cipher::AesEcb};
///
/// # fn main() -> cryptopals::Result<()> {
/// let text = "CRIwqt4+szDbqkNY+I0qbDe3LQz0wiw0..."; // truncated
/// # let text = "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\n".replace('\n', "");
/// let data = Data::from_base64(&text)?;
/// let mut cipher = AesEcb::new("YELLOW SUBMARINE", true)?;
/// let res = cipher.decrypt(&data)?;
///
/// let plaintext = "I'm back and I'm ringin' the bell..."; // truncated
/// # let plaintext = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";
/// assert_eq!(plaintext, res.to_string());
/// # Ok(())
/// # }
/// ```
///
/// [AES-128]: https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
/// [ECB mode]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
#[derive(Debug, Clone)]
pub struct AesEcb {
    cipher: Aes128,
    pad: bool,
}

impl AesEcb {
    /// Create a new AES-CBC cipher with a specified key and optional
    /// [padding via PKCS#7][Data::pad()].
    ///
    /// # Errors
    ///
    /// Returns an error if the `key` isn't exactly 16 bytes long.
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptopals::cipher::AesEcb;
    ///
    /// let mut cipher = AesEcb::new("YELLOW SUBMARINE", true)?;
    /// ```
    pub fn new(key: impl AsRef<[u8]>, pad: bool) -> Result<Self> {
        let key = key.as_ref();
        let cipher = Aes128::new_from_slice(key).map_err(|_| {
            Error::CipherError(CipherError {
                cipher_name: CIPHER_NAME,
                kind: CipherErrorType::InvalidLength {
                    kind: InvalidLengthType::Key,
                    expected: BLOCKSIZE_USIZE,
                    actual: key.len(),
                },
            })
        })?;

        Ok(Self::init(cipher, pad))
    }

    /// Initialize an AES-ECB cipher with a pre-existing [`Aes128`] struct and optional
    /// [padding via PKCS#7][Data::pad()].
    #[must_use]
    pub(crate) fn init(cipher: Aes128, pad: bool) -> Self {
        Self { cipher, pad }
    }
}

impl Cipher for AesEcb {
    type Error = Error;

    fn decrypt(&mut self, data: &Data) -> Result<Data> {
        let bytes = data
            .chunks(BLOCKSIZE_USIZE)
            .map(|s| itertools::Itertools::collect_array::<BLOCKSIZE_USIZE>(s.iter().copied()))
            .map(|o| {
                o.ok_or(Error::CipherError(CipherError {
                    cipher_name: CIPHER_NAME,
                    kind: CipherErrorType::InvalidLength {
                        kind: InvalidLengthType::Block,
                        expected: BLOCKSIZE_USIZE,
                        actual: data.len() / BLOCKSIZE_USIZE,
                    },
                }))
            })
            .map_ok(GenericArray::from)
            .map_ok(|mut block| {
                self.cipher.decrypt_block_mut(&mut block);
                block
            })
            .flatten_ok()
            .collect::<Result<Vec<_>>>()?;

        if self.pad {
            let data = Data::from(bytes).unpad()?;
            Ok(data)
        } else {
            Ok(Data::from(bytes))
        }
    }

    fn encrypt(&mut self, data: &Data) -> Result<Data> {
        let data = if self.pad { &data.pad(BLOCKSIZE) } else { data };

        let bytes = data
            .chunks(BLOCKSIZE_USIZE)
            .map(|s| itertools::Itertools::collect_array::<BLOCKSIZE_USIZE>(s.iter().copied()))
            .map(|o| {
                o.ok_or(Error::CipherError(CipherError {
                    cipher_name: CIPHER_NAME,
                    kind: CipherErrorType::InvalidLength {
                        kind: InvalidLengthType::Block,
                        expected: BLOCKSIZE_USIZE,
                        actual: data.len() / BLOCKSIZE_USIZE,
                    },
                }))
            })
            .map_ok(GenericArray::from)
            .map_ok(|mut block| {
                self.cipher.encrypt_block_mut(&mut block);
                block
            })
            .flatten_ok()
            .collect::<Result<Vec<_>>>()?;

        Ok(Data::from(bytes))
    }
}

/// Calculate the number of repeating 16-byte blocks.
#[must_use]
#[allow(
    clippy::cast_possible_truncation,
    reason = "higher scores will be rare"
)]
pub fn aes_ecb_score(bytes: &[u8]) -> u32 {
    bytes
        .chunks_exact(BLOCKSIZE_USIZE)
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
        let res = cipher.decrypt(&data)?;

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
            .max_by_key(|d| aes_ecb_score(d))
            .expect("data/8.txt should not be empty");

        assert_eq!(
            "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a",
            res.hex()
        );

        Ok(())
    }
}
