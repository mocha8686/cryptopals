use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Error, Debug, Diagnostic)]
pub enum Error {
    #[error("Couldn't parse input into `Data`")]
    ParseError(#[from] ParseError),

    #[error("Invalid block length (expected `{expected}`, got `{actual}`)")]
    InvalidLength { expected: usize, actual: usize },

    #[error("Invalid padding (padding byte: `{0}`)")]
    InvalidPadding(u8),
}

#[derive(Error, Debug, Diagnostic)]
pub enum ParseError {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),

    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}
