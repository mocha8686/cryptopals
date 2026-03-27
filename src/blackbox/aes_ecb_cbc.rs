//! Implementation of the [`AesEcbOrCbc`] blackbox.

use std::fmt::{Display, Formatter, Result as FmtResult};

use crate::{
    AesCbc, AesEcb, Data, Result,
    cipher::Cipher,
};
use aes::{
    Aes128,
    cipher::{KeyInit, generic_array::GenericArray},
};
use rand::Rng;

use super::Blackbox;

/// Tags to differentiate which AES block cipher mode is used for the [`AesEcbOrCbc`] blackbox, for
/// testing and debugging purposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EcbOrCbc {
    /// [AES-ECB][AesEcb] mode.
    Ecb,
    /// [AES-CBC][AesEcb] mode.
    Cbc,
}

impl Display for EcbOrCbc {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        let s = match self {
            EcbOrCbc::Ecb => "ECB",
            EcbOrCbc::Cbc => "CBC",
        };
        write!(f, "{s}")
    }
}

/// Blackbox that encrypts under AES-128, randomly switching between [ECB][AesEcb] and [CBC][AesCbc] block cipher
/// modes unless otherwise set.
///
/// # Examples
///
/// ```
/// use cryptopals::{
///     Data,
///     blackbox::{AesEcbOrCbc, Blackbox},
/// };
///
/// # fn main() -> cryptopals::Result<()> {
/// let mut blackbox = AesEcbOrCbc::new(None);
/// let data = Data::from("Hello, world!".as_bytes());
///
/// let res = blackbox.process(&data)?;
/// // `res` is either encrypted via ECB or CBC.
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct AesEcbOrCbc {
    /// Underlying cipher.
    cipher: Aes128,

    /// Optionally fix the cipher's mode to [ECB][AesEcb] or [CBC][AesCbc].
    mode: Option<EcbOrCbc>,
}

impl AesEcbOrCbc {
    /// Create a new ECB or CBC blackbox, optionally fixing the mode to [ECB][AesEcb] or [CBC][AesCbc].
    ///
    /// # Examples
    ///
    /// ```
    /// use cryptopals::{
    ///     Data,
    ///     blackbox::{AesEcbOrCbc, Blackbox, EcbOrCbc},
    /// };
    ///
    /// let mut random = AesEcbOrCbc::new(None);
    /// let mut always_ecb = AesEcbOrCbc::new(Some(EcbOrCbc::Ecb));
    /// ```
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
    type Error = crate::Error;

    fn process(&mut self, data: &Data) -> Result<Data> {
        let mut rng = rand::rng();
        let mut cipher: Box<dyn Cipher<Error = crate::Error>> =
            if self.mode.is_some_and(|m| matches!(m, EcbOrCbc::Ecb))
                || (self.mode.is_none() && rng.random())
            {
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
        let data = cipher.encrypt(&data)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use miette::Result;
    use pretty_assertions::assert_eq;

    use crate::attack::block::is_ecb;

    use super::*;

    fn test_mode(mode: EcbOrCbc) -> Result<()> {
        let mut blackbox = AesEcbOrCbc::new(Some(mode));
        let res = is_ecb(&mut blackbox, 16)?;

        let expected = match mode {
            EcbOrCbc::Ecb => true,
            EcbOrCbc::Cbc => false,
        };
        assert_eq!(expected, res);

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
