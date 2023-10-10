use anyhow::{bail, ensure, Result};
use itertools::Itertools;

use crate::{
    cipher::{aes_128_ecb::prefix::Prefix, Encrypt},
    data::Data,
    pkcs7,
};

pub fn prefix_attack(cipher: &Prefix) -> Result<Data> {
    let block_size = find_block_size(cipher)?;
    let block_size_minus_1 = block_size - 1;

    ensure!(
        {
            let payload = "A".repeat(block_size * 2).parse()?;
            let encrypted = cipher.encrypt(&payload)?;
            encrypted.bytes()[0..block_size] == encrypted.bytes()[block_size..block_size * 2]
        },
        "Cipher is not ECB."
    );

    let unknown_data_len = find_unknown_data_len(cipher)?;

    let mut res = vec![];

    let initial_padding_len = ((unknown_data_len + block_size_minus_1) & !block_size_minus_1) - 1;
    let target_block_index = initial_padding_len / block_size;

    for i in 0..unknown_data_len {
        let padding_len = initial_padding_len - i;
        let padding = [b'A'].repeat(padding_len).into_iter().collect_vec();

        let target = cipher.encrypt(&padding.clone().into())?;
        let target_block = target
            .bytes()
            .chunks_exact(block_size)
            .nth(target_block_index)
            .unwrap();

        let Some(byte) = (0..=u8::MAX).find(|&byte|  {
            let payload = padding
                .iter()
                .chain(res.iter())
                .chain(&[byte][..])
                .copied()
                .collect_vec()
                .into();

            let Ok(guess) = cipher.encrypt(&payload) else {
                return false;
            };

            let guess_block = guess
                .bytes()
                .chunks_exact(block_size)
                .nth(target_block_index)
                .unwrap();

            target_block == guess_block
        }) else {
            bail!("Failed to find matching byte.");
        };

        res.push(byte);
    }

    let res = Data::from(res);
    let unpad = pkcs7::unpad(&res);

    Ok(unpad.into_owned())
}

fn find_block_size(cipher: &Prefix) -> Result<usize> {
    let ciphertext_len = cipher.encrypt(&"".parse().unwrap())?.len();

    for i in 1..=u8::MAX {
        let payload = "A".repeat(i as usize);
        let new_ciphertext_len = cipher.encrypt(&payload.parse().unwrap())?.len();
        match new_ciphertext_len - ciphertext_len {
            0 => continue,
            n => return Ok(n),
        }
    }

    bail!("Failed to find block size.");
}

fn find_unknown_data_len(cipher: &Prefix) -> Result<usize> {
    let ciphertext_len = cipher.encrypt(&"".parse().unwrap())?.len();

    for i in 1..=u8::MAX {
        let payload = "A".repeat(i as usize);
        let new_ciphertext_len = cipher.encrypt(&payload.parse().unwrap())?.len();
        match new_ciphertext_len - ciphertext_len {
            0 => continue,
            _ => return Ok(ciphertext_len - (i - 1) as usize),
        }
    }

    bail!("Failed to find unknown data length.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data::Data;

    const UNKNOWN: &str = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";

    #[test]
    fn challenge_11() -> Result<()> {
        let unknown = Data::from_b64(UNKNOWN)?;
        let cipher = Prefix::new(rand::random(), unknown);

        let plaintext = prefix_attack(&cipher)?;

        assert_eq!(
            plaintext,
            "Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n".parse()?,
        );

        Ok(())
    }
}
