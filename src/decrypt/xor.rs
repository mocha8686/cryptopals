use crate::{
    data::Data,
    score,
    xor::{guess_keysizes, guess_single_byte_key},
};

const USE_FIRST_N_KEYSIZES: usize = 3;

pub fn repeating_key(data: &Data) -> Data {
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

fn get_column(data: &Data, row_length: usize, column: usize) -> Box<[u8]> {
    data.bytes()
        .iter()
        .skip(column)
        .step_by(row_length)
        .copied()
        .collect()
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::*;
    use crate::FUNKY_MUSIC;

    #[test]
    #[ignore = "slow"]
    fn break_repeating_key_test() -> Result<()> {
        let input = include_str!("../../data/1/6.txt").trim().replace('\n', "");
        let data = Data::from_b64(&input)?;
        let res = repeating_key(&data);

        assert_eq!(res, FUNKY_MUSIC.parse()?);

        Ok(())
    }
}
