//! Helper functions for formatting error input strings.

#![allow(dead_code, reason = "helper functions")]

use itertools::Itertools;

/// Defines the maximum length of a line for splitting up a long input string in an error (e.g.
/// when including the original string in a [parsing error][ParseError]).
const INPUT_CHUNK_SIZE: usize = 32;

/// Split an input into [`INPUT_CHUNK_SIZE`] bytes, optionally turning it into a hex string.
pub(crate) fn format_error_input(input: &[u8], hexify: bool) -> String {
    let input = if hexify {
        hex::encode(input)
    } else {
        String::from_utf8_lossy(input).to_string()
    };

    input
        .as_bytes()
        .chunks(INPUT_CHUNK_SIZE)
        .map(String::from_utf8_lossy)
        .join("\n")
}

/// Map a label index from an original input to its new position after a [`format_error_input()`], where
/// `hexify == false`.
pub(crate) fn map_label_index(index: usize) -> usize {
    let preceding_newlines = index / INPUT_CHUNK_SIZE;
    index + preceding_newlines
}

/// Map a label index and length pair from an original input to its new position after a
/// [`format_error_input()`], where `hexify == false`.
pub(crate) fn map_label_index_length(index: usize, len: usize) -> (usize, usize) {
    let start = map_label_index(index);
    let end = map_label_index(index + len - 1);
    let len = end - start + 1;
    (start, len)
}

/// Map a label index from an original input to its new position after a [`format_error_input()`], where
/// `hexify == true`.
pub(crate) fn map_label_index_hex(index: usize) -> (usize, usize) {
    let start = map_label_index(index * 2);
    (start, start + 1)
}

/// Map a label index and length pair from an original input to its new position after a
/// [`format_error_input()`], where `hexify == true`.
pub(crate) fn map_label_index_length_hex(
    index: usize,
    len: usize,
) -> (usize, usize) {
    let (start, _) = map_label_index_hex(index);
    let (_, end) = map_label_index_hex(index + len - 1);
    let len = end - start + 1;
    (start, len)
}
