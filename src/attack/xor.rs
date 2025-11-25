use crate::{Data, attack::score::score};

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
}
