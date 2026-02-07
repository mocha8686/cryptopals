//! Errors related to parsing strings of certain input formats to [`Data`] structs.

use miette::Diagnostic;
use thiserror::Error;

/// Failure to parse a string of some format to a [`Data`][crate::Data] struct.
#[derive(Error, Debug, Diagnostic, Clone, PartialEq)]
pub enum ParseError {
    /// Failure to parse a hex string using [`Data::from_hex()`][crate::Data::from_hex()].
    #[error("Couldn't parse hex string")]
    #[diagnostic(code("cryptopals::parse::hex"), url(docsrs))]
    Hex {
        /// The original hex string.
        #[source_code]
        input: String,

        /// The location of the invalid character, if it exists.
        #[label = "here"]
        label: Option<usize>,

        /// The underlying error.
        #[source]
        source: hex::FromHexError,
    },

    /// Failure to parse a Base64 string using [`Data::from_base64()`][crate::Data::from_base64()].
    #[error("Couldn't parse base64 string")]
    #[diagnostic(code("cryptopals::parse::base64"), url(docsrs))]
    Base64 {
        /// The original Base64 string.
        #[source_code]
        input: String,

        /// The location of the invalid character, if it exists.
        #[label = "here"]
        label: Option<usize>,

        /// The underlying error.
        #[source]
        source: base64::DecodeError,
    },
}
