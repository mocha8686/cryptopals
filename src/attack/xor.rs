//! Attacks on [repeating key XOR ciphers][crate::Data::xor()].
//!
//! Due to the nature of the repeating key, we are able to extract the entire plaintext and key
//! given a sufficiently high ciphertext length to key length ratio.

use itertools::Itertools;

use crate::{Data, score::en_frequency_score};

/// Decrypt a ciphertext encrypted using repeating-key XOR, where the length of the key is 1.
///
/// Assuming each byte has been XOR'ed with the same key byte, we perform a brute-force search
/// through every possible [`u8`], taking the one with the highest [`en_frequency_score`].
///
/// The time complexity of this algorithm is `O(n)`, though note that since it performs the scoring
/// for each [`u8`], the runtime has a coefficient of `2^8 == 256`.
#[must_use]
pub fn single_byte_xor(ciphertext: &Data) -> (u8, Data) {
    let Some(res) = (u8::MIN..=u8::MAX)
        .map(|b| (b, ciphertext ^ b))
        .max_by_key(|(_, data)| en_frequency_score(data))
    else {
        unreachable!()
    };

    res
}

/// Decrypt a ciphertext encrypted using repeating-key XOR.
///
/// At a high level, the algorithm follows four steps:
///   1. [Guess the keysize][guess_keysize] of the ciphertext, `keysize`.
///   2. [Parittion the ciphertext][partition] into `keysize` blocks, such that, assuming the key
///      is `keysize` bytes long, every byte in a single block has been XOR'ed with the same byte.
///   3. Break each block using [`single_byte_xor`].
///   4. [Unpartition the decrypted partitions][unpartition] and reconstruct the original
///      plaintext.
///
/// [A more detailed walkthrough][walkthrough] of the algorithm is also available externally.
///
/// The time complexity of this algorithm is `O(n^2)`.
///
/// [walkthrough]: https://mocha8686.neocities.org/learning/cryptopals/set1/#break-repeating-key-xor
#[must_use]
pub fn repeating_key_xor(ciphertext: &Data) -> (Data, Data) {
    let keysize = guess_keysize(ciphertext);
    let partitions = partition(ciphertext, keysize);

    let (key_bytes, partitions): (Vec<u8>, Vec<Data>) = partitions
        .into_iter()
        .map(|data| single_byte_xor(&data))
        .collect();

    let key = Data::from(key_bytes);
    let data = unpartition(partitions);

    (key, data)
}

#[allow(clippy::doc_markdown, reason = "`XORing` false positive")]
/// Guess the keysize used to encrypt a certain ciphertext.
///
/// This algorithm uses the fact that XOR has [certain properties]:
///
///   1. [Associativity]
///   2. [Commutativity]
///   3. [Involution]
///
/// The algorithm guesses the keysize by finding the keysize in a certain range that produces the
/// minimum [hamming distance][Data::hamming_distance()]. It accomplishes this in `O(n)` time.
///
/// # Explanation
///
/// Consider a plaintext encrypted under [repeating-key XOR][Data::xor()] using the key `meow`.
/// Taking the first two ciphertext blocks of length 4 and XORing them, we see that
///
/// ```txt
///  plaintext: ..........................
///        key: meowmeowmeowmeowmeowmeowme
/// ciphertext: qwertyuiopasdfghjklzxcvbnm
///
/// ciphertext[0..4] == plaintext[0..4] ^ "meow"
/// ciphertext[4..8] == plaintext[4..8] ^ "meow"
///
/// ciphertext[0..4] ^ ciphertext[4..8]
/// == plaintext[0..4] ^ "meow" ^ plaintext[4..8] ^ "meow"
/// == plaintext[0..4] ^ plaintext[4..8] ^ "meow" ^ "meow"  (commutation and association)
/// == plaintext[0..4] ^ plaintext[4..8]                    (involution)
/// ```
///
/// When `blocksize == keysize`, the key cancels out, decreasing the total edits to the text.
/// Otherwise, if `blocksize != keysize`, the key would be fragmented (`"meowm" ^ "eowme"`, for
/// example), and would contribute to the total edits. Thus, minimizing edits (Hamming distance) is
/// analogous to finding the correct `blocksize` for the key to cancel out, which will be the
/// `keysize`.
///
/// [A more detailed explanation][explanation] is also available externally.
///
/// [certain properties]: https://en.wikipedia.org/wiki/Exclusive_or#Properties
///
/// [Associativity]: https://en.wikipedia.org/wiki/Associative_property
/// [Commutativity]: https://en.wikipedia.org/wiki/Commutative_property
/// [Involution]: https://en.wikipedia.org/wiki/Involution_(mathematics)
/// [explanation]: https://mocha8686.neocities.org/learning/cryptopals/set1/#guessing-the-keysize
#[must_use]
pub fn guess_keysize(ciphertext: &Data) -> u32 {
    const MAX_KEYSIZE: u32 = 40;
    let Some(res) = (2u32..=MAX_KEYSIZE).min_by_key(|keysize| {
        let (score, count, _) = ciphertext.chunks_exact(*keysize as usize).fold(
            (0, 0, None),
            |(acc, n, prev), chunk| {
                let res = prev.map_or(0, |prev: &[u8]| {
                    let prev = Data::from(prev);
                    let chunk = Data::from(chunk);
                    let Some(res) = prev.hamming_distance(&chunk) else {
                        unreachable!()
                    };
                    res
                });
                (acc + res, n + 1, Some(chunk))
            },
        );
        score * 100 / count / *keysize
    }) else {
        unreachable!()
    };

    res
}

/// Partition a ciphertext into `keysize` different blocks in a cyclic (modulo) fashion.
///
/// Assuming a certain `ciphertext` is encrypted with a key of length `keysize`, each resulting
/// block will contain the bytes from `ciphertext` encrypted with the same byte from the key.
///
/// ```txt
///             ┌ keysize = 4
///             ├───┬───┬───┬───┬───┬───┬───┐
///      i % 4: 01230123012301230123012301
///        key: meowmeowmeowmeowmeowmeowme
/// ciphertext: qwertyuiopasdfghjklzxcvbnm
///             │   │   │   │   │   │   │
///        key: m   m   m   m   m   m   m ─► mmmmmmm
/// ciphertext: q   t   o   d   j   x   n ─► qtodjxn
///      i    : 0   4   8  12  16  20  24
///      i % 4: 0   0   0   0   0   0   0
/// ```
///
/// This algorithm's time complexity is `O(n)`.
pub fn partition(ciphertext: &Data, keysize: u32) -> Vec<Data> {
    ciphertext
        .iter()
        .copied()
        .zip(0u32..)
        .into_group_map_by(|(_, i)| i % keysize)
        .into_iter()
        .sorted_by_key(|(n, _)| *n)
        .map(|(_, vec)| vec.into_iter().map(|(b, _)| b).collect_vec())
        .map(Data::from)
        .collect_vec()
}

/// Combine multiple partitions of a [`partition`ed][partition] ciphertext back in the original
/// order.
///
/// Given a list of partitions generated by [`partition()`], this function reconstructs the
/// data into the original ordering. Relative to the original data length `n`, this algorithm is
/// `O(n)`.
#[must_use]
pub fn unpartition(partitions: Vec<Data>) -> Data {
    let keysize = partitions.len();
    let bytes = partitions
        .into_iter()
        .enumerate()
        .flat_map(|(i, data)| {
            data.iter()
                .copied()
                .enumerate()
                .map(|(n, b)| (n * keysize + i, b))
                .collect_vec()
        })
        .sorted_by_key(|(i, _)| *i)
        .map(|(_, b)| b)
        .collect_vec();
    Data::from(bytes)
}

#[cfg(test)]
mod tests {
    use miette::Result;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn s1c3_single_byte_xor_cipher() -> Result<()> {
        let data =
            Data::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
        let (key, res) = single_byte_xor(&data);

        assert_eq!('X', key.into());
        assert_eq!("Cooking MC's like a pound of bacon", res.to_string());

        Ok(())
    }

    #[test]
    #[ignore = "slow"]
    fn s1c4_detect_single_character_xor() -> Result<()> {
        let text = include_str!("../../data/4.txt");
        let (key, data) = text
            .split_ascii_whitespace()
            .map(Data::from_hex)
            .collect::<crate::Result<Vec<_>>>()?
            .into_iter()
            .map(|data| single_byte_xor(&data))
            .max_by_key(|(_, data)| en_frequency_score(data))
            .expect("data/4.txt should not be empty");

        assert_eq!('5', key.into());
        assert_eq!("Now that the party is jumping\n", data);

        Ok(())
    }

    #[test]
    fn s1c6_break_repeating_key_xor() -> Result<()> {
        let text = include_str!("../../data/6.txt").replace('\n', "");
        let data = Data::from_base64(&text)?;
        let (key, res) = repeating_key_xor(&data);

        assert_eq!("Terminator X: Bring the noise", key.to_string());
        assert_eq!(include_str!("../../data/funky.txt"), res.to_string());

        Ok(())
    }
}
