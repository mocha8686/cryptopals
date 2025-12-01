use std::fmt::Display;

use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Error, Debug, Diagnostic, Clone)]
pub enum Error {
    #[error("Couldn't parse input into `Data`")]
    ParseError(#[from] ParseError),

    #[error("Invalid {kind} length (expected `{expected}`, got `{actual}`)")]
    InvalidLength {
        kind: InvalidLengthType,
        expected: usize,
        actual: usize,
    },

    #[error("Invalid padding (padding byte: `{0}`)")]
    InvalidPadding(u8),
}

#[derive(Error, Debug, Diagnostic, Clone)]
pub enum ParseError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

#[derive(Debug, Clone)]
pub enum InvalidLengthType {
    Block,
    Key,
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
