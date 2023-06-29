mod data;
use data::Data;
use phf::phf_map;

static LETTER_FREQUENCIES: phf::Map<char, u64> = phf_map! {
    ' ' => 999999,
    'e' => 127000,
    't' => 910000,
    'a' => 820000,
    'o' => 750000,
    'i' => 700000,
    'n' => 670000,
    's' => 630000,
    'h' => 610000,
    'r' => 600000,
    'd' => 430000,
    'l' => 400000,
    'c' => 280000,
    'u' => 280000,
    'm' => 240000,
    'w' => 240000,
    'f' => 220000,
    'g' => 200000,
    'y' => 200000,
    'p' => 190000,
    'b' => 150000,
    'v' => 098000,
    'k' => 077000,
    'x' => 015000,
    'j' => 015000,
    'q' => 009500,
    'z' => 007400,
};

fn hamming_distance(lhs: &Data, rhs: &Data) -> usize {
    assert_eq!(
        lhs.bytes().len(),
        rhs.bytes().len(),
        "Data must be same size to get Hamming distance."
    );

    lhs.bytes()
        .iter()
        .cloned()
        .zip(rhs.bytes().iter().cloned())
        .map(|(lhs, rhs)| lhs ^ rhs)
        .map(|byte| byte.count_ones() as usize)
        .sum()
}

fn guess_single_byte_xor(data: &Data) -> (Data, u64) {
    (u8::MIN..=u8::MAX)
        .map(|c| data.clone() ^ vec![c].into())
        .map(|data| {
            let score = score(&data);
            (data, score)
        })
        .max_by_key(|(_, score)| score.to_owned())
        .unwrap()
}

fn detect_single_byte_xor(data: &[Data]) -> Data {
    data.into_iter()
        .map(|data| guess_single_byte_xor(data))
        .max_by_key(|(_, score)| score.to_owned())
        .unwrap()
        .0
}

fn score(data: &Data) -> u64 {
    data.bytes()
        .to_owned()
        .into_iter()
        .map(|c| LETTER_FREQUENCIES.get(&(c as char)).copied().unwrap_or(0))
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use std::str::FromStr;

    #[test]
    fn single_byte_xor_cipher() -> Result<()> {
        let data =
            Data::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;

        assert_eq!(
            guess_single_byte_xor(&data).0,
            Data::from_str("Cooking MC's like a pound of bacon")?
        );

        Ok(())
    }

    #[test]
    fn detect_single_character_xor() -> Result<()> {
        let input = std::fs::read_to_string("./data/1/4.txt")?;
        let data: Vec<Data> = input
            .lines()
            .map(|line| Data::from_hex(line).ok())
            .flatten()
            .collect();
        let res = detect_single_byte_xor(&data);

        assert_eq!(res, "Now that the party is jumping\n".parse()?);

        Ok(())
    }

    #[test]
    fn hamming_distance_test() -> Result<()> {
        let lhs = "this is a test".parse()?;
        let rhs = "wokka wokka!!!".parse()?;

        assert_eq!(hamming_distance(&lhs, &rhs), 37);

        Ok(())
    }
}
