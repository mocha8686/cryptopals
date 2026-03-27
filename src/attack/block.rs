//! Attacks on block ciphers (for example, [AES-ECB][crate::cipher::AesEcb]).

use crate::{Data, Result, blackbox::Blackbox, score};

/// Determine whether a blackbox is a cipher encrypting under [ECB mode][AesEcb].
///
/// # Errors
///
/// Returns an error if the `blackbox` fails to process an arbitrary payload.
///
/// # Examples
///
/// ```
/// use cryptopals::{
///     attack::block::is_ecb,
///     blackbox::{AesEcbOrCbc, Blackbox, EcbOrCbc},
/// };
///
/// # fn main() -> cryptopals::Result<()> {
/// let mut blackbox = AesEcbOrCbc::new(Some(EcbOrCbc::Ecb));
/// let res = is_ecb(&mut blackbox)?;
/// assert_eq!(EcbOrCbc::Ecb, res);
/// # Ok(())
/// # }
/// ```
///
/// [ECB mode]: https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_codebook_(ECB)
pub fn is_ecb(blackbox: &mut dyn Blackbox<Error = crate::Error>, blocksize: usize) -> Result<bool> {
    let data = Data::from("A".repeat(blocksize * 3).as_bytes());
    let res = blackbox.process(&data)?;

    let is_ecb = score::ecb_count(&res, blocksize) > 0;
    Ok(is_ecb)
}
