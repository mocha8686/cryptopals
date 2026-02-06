//! Error types.

#![allow(
    unused_assignments,
    reason = "compiler doesn't play nicely with miette error reporting"
)]

use miette::Diagnostic;
use thiserror::Error;

mod cipher;
mod padding;
mod parse;

pub use cipher::{CipherError, CipherErrorType, InvalidLengthType};
pub use padding::PaddingError;
pub use parse::ParseError;

/// Helper wrapper around [`core::result::Result`], pre-defined to use the [crate
/// `Error`][crate::Error] type.
pub type Result<T> = core::result::Result<T, Error>;

/// Defines the maximum length of a line for splitting up a long input string in an error (e.g.
/// when including the original string in a [hex parsing error][ParseError::Hex]).
pub(crate) const INPUT_CHUNK_SIZE: usize = 32;

/// Main error type.
///
/// See documentation for wrapped types for more info on each error.
#[allow(
    missing_docs,
    reason = "all items are transparent, docs are the same as the inner type's docs"
)]
#[derive(Error, Debug, Diagnostic, Clone, PartialEq)]
pub enum Error {
    #[error(transparent)]
    #[diagnostic(transparent)]
    CipherError(#[from] CipherError),

    #[error("Couldn't strip padding from `Data`")]
    #[diagnostic(transparent)]
    PaddingError(#[from] PaddingError),

    #[error("Couldn't parse input into `Data`")]
    #[diagnostic(transparent)]
    ParseError(#[from] ParseError),
}
