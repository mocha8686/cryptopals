#![allow(
    unused_assignments,
    reason = "compiler doesn't play nicely with miette error reporting"
)]

use std::fmt::Display;

use miette::Diagnostic;
use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

pub(crate) const INPUT_CHUNK_SIZE: usize = 32;

#[derive(Error, Debug, Diagnostic, Clone, PartialEq)]
pub enum Error {
    #[error("Couldn't parse input into `Data`")]
    #[diagnostic(transparent)]
    ParseError(#[from] ParseError),

    // #[error("Couldn't decode input using {cipher}")]
    // DecodeError {
    //     cipher: String,
    // },
    #[error("Invalid {kind} length (expected `{expected}`, got `{actual}`)")]
    InvalidLength {
        kind: InvalidLengthType,
        expected: usize,
        actual: usize,
    },

    #[error("Couldn't strip padding from `Data`")]
    #[diagnostic(transparent)]
    PaddingError(#[from] PaddingError),
}

#[derive(Error, Debug, Diagnostic, Clone, PartialEq)]
pub enum PaddingError {
    #[error("Input too short for padding byte (padding byte: {byte}, length: {len})")]
    #[diagnostic(code("cryptopals::padding::input_too_short"), url(docsrs))]
    InputTooShort { byte: u8, len: usize },

    #[error("Invalid padding (padding byte: `{byte:#04x}`)")]
    #[diagnostic(code("cryptopals::padding::invalid_padding"), url(docsrs))]
    InvalidPadding {
        byte: u8,

        #[source_code]
        input: String,

        #[label = "here"]
        label: (usize, usize),
    },
}

#[derive(Error, Debug, Diagnostic, Clone, PartialEq)]
pub enum ParseError {
    #[error("Couldn't parse hex string")]
    #[diagnostic(code("cryptopals::parse::hex"), url(docsrs))]
    Hex {
        #[source_code]
        input: String,

        #[label = "here"]
        label: Option<usize>,

        #[source]
        source: hex::FromHexError,
    },

    #[error("Couldn't parse base64 string")]
    #[diagnostic(code("cryptopals::parse::base64"), url(docsrs))]
    Base64 {
        #[source_code]
        input: String,

        #[label = "here"]
        label: Option<usize>,

        #[source]
        source: base64::DecodeError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
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
