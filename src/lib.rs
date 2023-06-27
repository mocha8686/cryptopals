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

fn guess_single_byte_xor(data: &Data) -> Data {
    (u8::MIN..=u8::MAX)
        .map(|c| data.clone() ^ vec![c].into())
        .map(|data| {
            let score = score(&data);
            (data, score)
        })
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
            guess_single_byte_xor(&data),
            Data::from_str("Cooking MC's like a pound of bacon")?
        );

        Ok(())
    }
}
