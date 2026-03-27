//! Collection of attacks on ciphers and certain blackboxes.
//!
//! Attacks may require certain side-channels, sufficiently long ciphertexts, a partial or full
//! ciphertext decryption sample, or other additional info. The effects range from ciphertext
//! injection (e.g. `admin=true`), to partial plaintext extraction, or for some cases, a full key
//! extraction and plaintext decryption.
//!
//! # Examples
//!
//! ## Repeating-key XOR decryption
//!
//! ```
//! use cryptopals::{
//!     Data,
//!     attack::xor::repeating_key_xor,
//! };
//!
//! # use cryptopals::Result;
//! # fn main() -> Result<()> {
//! let base64 = "HUIfTQsPAh9PE048GmllH0kcDk4TAQsH..."; // truncated
//! # let base64 = include_str!("../data/6.txt").replace('\n', "");
//! let data = Data::from_base64(base64.as_bytes())?;
//! let (key, res) = repeating_key_xor(&data);
//!
//! let expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike..."; // truncated
//! # let expected = include_str!("../data/funky.txt");
//!
//! assert_eq!("Terminator X: Bring the noise", key.to_string());
//! assert_eq!(expected, res.to_string());
//!
//! # Ok(())
//! # }
//! ```

pub mod block;
pub mod xor;
