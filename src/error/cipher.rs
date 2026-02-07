//! Errors related to [ciphers][crate::cipher].

use std::fmt::Display;

use miette::Diagnostic;
use thiserror::Error;

/// Failure to construct or use a [cipher][crate::cipher].
#[derive(Error, Debug, Diagnostic, Clone, PartialEq, Eq, Hash)]
#[error("Cipher error with {cipher_name}: {kind}")]
#[diagnostic(code("cryptopals::cipher"), url(docsrs))]
pub struct CipherError {
    /// Name of the cipher.
    pub cipher_name: &'static str,

    /// What kind of error happened.
    #[source]
    pub kind: CipherErrorType,
}

/// Different kinds of cipher-related errors.
#[derive(Error, Debug, Diagnostic, Clone, PartialEq, Eq, Hash)]
pub enum CipherErrorType {
    /// Invalid length of data passed to a cipher.
    ///
    /// May either occur in construction (e.g. invalid-length keys or IVs), or in usage (e.g.
    /// invalid-length data blocks).
    #[error("Invalid {kind} length (expected `{expected}`, got `{actual}`)")]
    #[diagnostic(code("cryptopals::cipher::invalid_length"), url(docsrs))]
    InvalidLength {
        /// Which cipher component had an invalid length.
        kind: InvalidLengthType,

        /// Expected length.
        expected: usize,

        /// Actual length.
        actual: usize,
    },
}

/// Discriminator for which cipher component had an invalid length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InvalidLengthType {
    /// Cipher data block, during decryption.
    Block,

    /// Key, during construction.
    Key,

    /// IV, during construction.
    IV,
}

impl Display for InvalidLengthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            InvalidLengthType::Block => "block",
            InvalidLengthType::Key => "key",
            InvalidLengthType::IV => "IV",
        };

        write!(f, "{s}")
    }
}
