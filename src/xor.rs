use anyhow::{ensure, Result};
use itertools::Itertools;

use super::{data::Data, score};

const MAX_KEYSIZE: usize = 40;
const USE_FIRST_N_KEYSIZES: usize = 3;

pub fn break_repeating_key(data: &Data) -> Data {
    let keysizes = guess_keysizes(data);
    keysizes[0..USE_FIRST_N_KEYSIZES]
        .iter()
        .map(|keysize| {
            let keysize = *keysize;
            let plaintext_columns: Box<_> = (0..keysize)
                .map(|offset| get_column(data, keysize, offset))
                .map(|ciphertext_column| guess_single_byte_key(&ciphertext_column.into()).0)
                .collect();

            (0..plaintext_columns[0].bytes().len())
                .flat_map(|i| {
                    plaintext_columns
                        .iter()
                        .map(move |column| column.bytes().get(i))
                })
                .flatten()
                .copied()
                .collect::<Box<[u8]>>()
                .into()
        })
        .max_by_key(score)
        .unwrap()
}

pub fn detect_single_byte_key(data: &[Data]) -> Data {
    data.iter()
        .map(guess_single_byte_key)
        .max_by_key(|(_, score)| score.to_owned())
        .unwrap()
        .0
}

fn get_column(data: &Data, row_length: usize, column: usize) -> Box<[u8]> {
    data.bytes()
        .iter()
        .skip(column)
        .step_by(row_length)
        .copied()
        .collect()
}

fn guess_keysizes(data: &Data) -> Box<[usize]> {
    (2..=MAX_KEYSIZE)
        .map(|keysize| {
            let hamming_distances: Box<[usize]> = data
                .bytes()
                .chunks_exact(keysize)
                .tuple_windows()
                .map(|(lhs, rhs)| hamming_distance(&lhs.into(), &rhs.into()).unwrap() * 1000)
                .collect();

            let average_hamming_distance =
                hamming_distances.iter().sum::<usize>() / hamming_distances.len();
            let normalized_hamming_distance = average_hamming_distance / keysize;

            (keysize, normalized_hamming_distance)
        })
        .sorted_by_key(|(_, normalized_hamming_distance)| *normalized_hamming_distance)
        .map(|(keysize, _)| keysize)
        .collect()
}

fn hamming_distance(lhs: &Data, rhs: &Data) -> Result<usize> {
    ensure!(
        lhs.bytes().len() == rhs.bytes().len(),
        "Data must be same size to get Hamming distance."
    );

    Ok(lhs
        .bytes()
        .iter()
        .copied()
        .zip(rhs.bytes().iter().copied())
        .map(|(lhs, rhs)| lhs ^ rhs)
        .map(|byte| byte.count_ones() as usize)
        .sum())
}

fn guess_single_byte_key(data: &Data) -> (Data, u64) {
    (u8::MIN..=u8::MAX)
        .map(|c| data.clone() ^ vec![c].into())
        .map(|data| {
            let score = score(&data);
            (data, score)
        })
        .max_by_key(|(_, score)| score.to_owned())
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FUNKY_MUSIC;
    use anyhow::Result;
    use std::str::FromStr;

    #[test]
    fn single_byte_key_works() -> Result<()> {
        let data =
            Data::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;

        assert_eq!(
            guess_single_byte_key(&data).0,
            Data::from_str("Cooking MC's like a pound of bacon")?
        );

        Ok(())
    }

    #[test]
    #[ignore = "slow"]
    fn detect_single_byte_key_test() -> Result<()> {
        let input = include_str!("../data/1/4.txt");
        let data: Vec<Data> = input
            .lines()
            .filter_map(|line| Data::from_hex(line).ok())
            .collect();
        let res = detect_single_byte_key(&data);

        assert_eq!(res, "Now that the party is jumping\n".parse()?);

        Ok(())
    }

    #[test]
    fn hamming_distance_test() -> Result<()> {
        let lhs = "this is a test".parse()?;
        let rhs = "wokka wokka!!!".parse()?;

        assert_eq!(hamming_distance(&lhs, &rhs)?, 37);

        Ok(())
    }

    #[test]
    #[ignore = "slow"]
    fn break_repeating_key_test() -> Result<()> {
        let input = include_str!("../data/1/6.txt").trim().replace('\n', "");
        let data = Data::from_b64(&input)?;
        let res = break_repeating_key(&data);

        assert_eq!(res, FUNKY_MUSIC.parse()?);

        Ok(())
    }
}
