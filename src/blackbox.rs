//! Mock implementations of certain vulnerable parts of real-world systems.
//!
//! # Examples
//!
//! ```
//! use cryptopals::{
//!     Data,
//!     blackbox::{AesEcbOrCbc, Blackbox},
//! };
//!
//! # fn main() -> cryptopals::Result<()> {
//! let mut blackbox = AesEcbOrCbc::new(None);
//! let data = Data::from("Hello, world!".as_bytes());
//!
//! let res = blackbox.process(&data)?;
//! // `res` is either encrypted via ECB or CBC.
//! # Ok(())
//! # }
//! ```

use crate::Data;
 
mod aes_ecb_cbc;
mod aes_ecb_prefix;

pub use aes_ecb_cbc::{AesEcbOrCbc, EcbOrCbc, detect_aes_mode};
pub use aes_ecb_prefix::AesEcbPrefix;

/// Interface for implementing a blackbox.
pub trait Blackbox {
    /// Associated error type for possible errors during processing.
    type Error;

    /// Transform a piece of data in any arbitrary fashion.
    #[allow(clippy::missing_errors_doc, reason = "error is implementation-defined")]
    fn process(&mut self, data: &Data) -> Result<Data, Self::Error>;
}
