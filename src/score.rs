//! Functions for scoring a piece of plaintext based on different metrics.

use phf::phf_map;

/// Frequency map of english letters (case-insensitive).
///
/// Data is sourced from [Cryptological Mathematics].
///
/// Spaces are the most common character in many plaintexts, so they are given a very high score.
///
/// [Cryptological Mathematics]: https://web.archive.org/web/20080708193159/http://pages.central.edu/emp/LintonT/classes/spring01/cryptography/letterfreq.html
static EN_FREQUENCIES: phf::Map<u8, i32> = phf_map! {
    b' ' => 20000,
    b'e' => 12700,
    b't' =>  9100,
    b'a' =>  8200,
    b'o' =>  7500,
    b'i' =>  7000,
    b'n' =>  6700,
    b's' =>  6300,
    b'h' =>  6100,
    b'r' =>  6000,
    b'd' =>  4300,
    b'l' =>  4000,
    b'c' =>  2800,
    b'u' =>  2800,
    b'm' =>  2400,
    b'w' =>  2400,
    b'f' =>  2200,
    b'g' =>  2000,
    b'y' =>  2000,
    b'p' =>  1900,
    b'b' =>  1500,
    b'v' =>   980,
    b'k' =>   770,
    b'j' =>   160,
    b'x' =>   150,
    b'q' =>   120,
    b'z' =>    74,
};

/// Score a plaintext based on the character frequency of letters in English texts.
///
/// Data is sourced from [Cryptological Mathematics].
///
/// If a character in the plaintext doesn't appear in the frequency map, the score will be
/// penalized minorly. The penalty is small to allow for punctuation to be marked as plaintext,
/// but if the plaintext is gibberish, then the penalty will add up regardless.
///
/// This scoring method becomes more accurate the longer the plaintext is.
///
/// # Examples
///
/// ```
/// use cryptopals::{Data, score::en_frequency_score};
///
/// let data = Data::from("Hello, world! I am a yellow submarine.".as_bytes());
/// let score = en_frequency_score(&data);
/// assert_eq!(287_500, score);
/// ```
///
/// [Cryptological Mathematics]: https://web.archive.org/web/20080708193159/http://pages.central.edu/emp/LintonT/classes/spring01/cryptography/letterfreq.html
pub fn en_frequency_score(bytes: &[u8]) -> i32 {
    bytes
        .iter()
        .map(u8::to_ascii_lowercase)
        .map(|b| EN_FREQUENCIES.get(&b).unwrap_or(&-1000))
        .sum()
}
