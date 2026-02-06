use miette::Diagnostic;
use thiserror::Error;

/// Invalid padding detected while trying to [`unpad()`][`crate::Data::unpad()`] data.
#[derive(Error, Debug, Diagnostic, Clone, PartialEq, Eq, Hash)]
pub enum PaddingError {
    /// Padding byte was larger than the length of the input [`Data`][crate::Data].
    #[error("Input too short for padding byte (padding byte: {byte}, length: {len})")]
    #[diagnostic(code("cryptopals::padding::input_too_short"), url(docsrs))]
    InputTooShort {
        /// Padding byte.
        byte: u8,

        /// Length of the input [`Data`].
        len: usize,
    },

    /// For a padding byte `n`, the last `n` bytes of the `input` did not match.
    ///
    /// Contains the input [`Data`][crate::Data] as a hex string.
    #[error("Bad padding (padding byte: `{byte:#04x}`)")]
    #[diagnostic(code("cryptopals::padding::invalid_padding"), url(docsrs))]
    InvalidPadding {
        /// Padding byte.
        byte: u8,

        /// The original input, as a hex string.
        #[source_code]
        input: String,

        /// The start and end locations of the padding checked.
        #[label = "here"]
        label: (usize, usize),
    },
}
