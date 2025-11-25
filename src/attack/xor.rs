use itertools::Itertools;

use crate::{Data, attack::score::score, hamming_distance::hamming_distance};

#[must_use]
pub fn single_byte_xor(data: &Data) -> (u8, Data) {
    let Some(res) = (u8::MIN..=u8::MAX)
        .map(|b| (b, data ^ b))
        .max_by_key(|(_, data)| score(data.iter()))
    else {
        unreachable!()
    };

    res
}

#[must_use]
pub fn repeating_key_xor(data: &Data) -> (Data, Data) {
    let keysize = guess_keysize(data);
    let partitions = partition(data, keysize);

    let (key_bytes, partitions): (Vec<u8>, Vec<Data>) = partitions
        .into_iter()
        .map(|data| single_byte_xor(&data))
        .collect();

    let key = Data::from(key_bytes);
    let data = unpartition(partitions);

    (key, data)
}

#[allow(
    clippy::cast_possible_truncation,
    reason = "keysizes that large will be rare"
)]
fn guess_keysize(data: &Data) -> usize {
    const MAX_KEYSIZE: usize = 40;

    let Some(res) = (2..=MAX_KEYSIZE).min_by_key(|keysize| {
        let (score, count, _) =
            data.chunks_exact(*keysize)
                .fold((0, 0, None), |(acc, n, prev), chunk| {
                    let res =
                        prev.map_or(0, |prev: &[u8]| hamming_distance(prev.iter(), chunk.iter()));
                    (acc + res, n + 1, Some(chunk))
                });
        score * 100 / count / *keysize as u32
    }) else {
        unreachable!()
    };

    res
}

fn partition(data: &Data, keysize: usize) -> Vec<Data> {
    data.iter()
        .copied()
        .enumerate()
        .into_group_map_by(|(i, _)| i % keysize)
        .into_iter()
        .sorted_by_key(|(n, _)| *n)
        .map(|(_, vec)| vec.into_iter().map(|(_, b)| b).collect_vec())
        .map(Data::from)
        .collect_vec()
}

fn unpartition(partitions: Vec<Data>) -> Data {
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
    use crate::Result;

    use super::*;

    #[test]
    fn s1c3_single_byte_xor_cipher() -> Result<()> {
        let data = Data::from_hex_str(
            "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736",
        )?;
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
            .flat_map(Data::from_hex_str)
            .map(|data| single_byte_xor(&data))
            .max_by_key(|(_, data)| score(data.iter()))
            .unwrap();

        assert_eq!('5', key.into());
        assert_eq!("Now that the party is jumping\n", data);

        Ok(())
    }

    #[test]
    fn s1c6_break_repeating_key_xor() -> Result<()> {
        let text = include_str!("../../data/6.txt").replace('\n', "");
        let data = Data::from_base64_str(&text)?;
        let (key, res) = repeating_key_xor(&data);

        assert_eq!("Terminator X: Bring the noise", key.to_string());
        assert_eq!(include_str!("../../data/funky.txt"), res.to_string());

        Ok(())
    }
}
