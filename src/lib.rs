mod data;

use anyhow::Result;
use data::Data;
use itertools::Itertools;
use openssl::symm::{self, Cipher};
use phf::phf_map;

const MAX_KEYSIZE: usize = 40;
const USE_FIRST_N_KEYSIZES: usize = 3;

static LETTER_FREQUENCIES: phf::Map<char, u64> = phf_map! {
    ' ' => 999_999,
    'e' => 127_000,
    't' => 910_000,
    'a' => 820_000,
    'o' => 750_000,
    'i' => 700_000,
    'n' => 670_000,
    's' => 630_000,
    'h' => 610_000,
    'r' => 600_000,
    'd' => 430_000,
    'l' => 400_000,
    'c' => 280_000,
    'u' => 280_000,
    'm' => 240_000,
    'w' => 240_000,
    'f' => 220_000,
    'g' => 200_000,
    'y' => 200_000,
    'p' => 190_000,
    'b' => 150_000,
    'v' =>  98_000,
    'k' =>  77_000,
    'x' =>  15_000,
    'j' =>  15_000,
    'q' =>   9_500,
    'z' =>   7_400,
};

fn break_repeating_key_xor(data: &Data) -> Data {
    let keysizes = guess_keysizes(data);
    keysizes[0..USE_FIRST_N_KEYSIZES]
        .iter()
        .map(|keysize| {
            let keysize = *keysize;
            let plaintext_columns: Box<_> = (0..keysize)
                .map(|offset| get_column(data, keysize, offset))
                .map(|ciphertext_column| guess_single_byte_xor(&ciphertext_column.into()).0)
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

fn guess_keysizes(data: &Data) -> Box<[usize]> {
    (2..=MAX_KEYSIZE)
        .map(|keysize| {
            let hamming_distances: Box<[usize]> = data
                .bytes()
                .chunks_exact(keysize)
                .tuple_windows()
                .map(|(lhs, rhs)| hamming_distance(&lhs.into(), &rhs.into()) * 1000)
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

fn hamming_distance(lhs: &Data, rhs: &Data) -> usize {
    assert_eq!(
        lhs.bytes().len(),
        rhs.bytes().len(),
        "Data must be same size to get Hamming distance."
    );

    lhs.bytes()
        .iter()
        .copied()
        .zip(rhs.bytes().iter().copied())
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
    data.iter()
        .map(guess_single_byte_xor)
        .max_by_key(|(_, score)| score.to_owned())
        .unwrap()
        .0
}

fn score(data: &Data) -> u64 {
    data.bytes()
        .iter()
        .copied()
        .map(|c| LETTER_FREQUENCIES.get(&(c as char)).copied().unwrap_or(0))
        .sum()
}

fn aes_128_ecb_decrypt(key: &Data, ciphertext: &Data) -> Result<Data> {
    let cipher = Cipher::aes_128_ecb();
    Ok(Data::from(symm::decrypt(
        cipher,
        key.bytes(),
        None,
        ciphertext.bytes(),
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use itertools::Itertools;
    use std::{fs::read_to_string, str::FromStr};

    const FUNKY_MUSIC: &str = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n";

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
        let input = read_to_string("./data/1/4.txt")?;
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

    #[test]
    #[ignore = "slow"]
    fn break_repeating_key_xor_test() -> Result<()> {
        let input = read_to_string("./data/1/6.txt")?.trim().replace("\n", "");
        let data = Data::from_b64(&input)?;
        let res = break_repeating_key_xor(&data);

        assert_eq!(res, FUNKY_MUSIC.parse()?);

        Ok(())
    }

    #[test]
    fn aes_128_ecb_test() -> Result<()> {
        let input = read_to_string("./data/1/7.txt")?.trim().replace("\n", "");
        let ciphertext = Data::from_b64(&input)?;
        let key = "YELLOW SUBMARINE".parse()?;
        let res = aes_128_ecb_decrypt(&key, &ciphertext)?;

        assert_eq!(res, FUNKY_MUSIC.parse()?);

        Ok(())
    }

    #[test]
    fn detect_aes_128_ecb() -> Result<()> {
        let input = read_to_string("./data/1/8.txt")?.trim().to_owned();
        let res = input
            .lines()
            .map(|line| Data::from_hex(line.trim()))
            .flatten()
            .max_by_key(|data| {
                data.bytes()
                    .into_iter()
                    .chunks(16)
                    .into_iter()
                    .map(|chunk| chunk.collect::<Box<_>>())
                    .counts()
                    .into_values()
                    .map(|count| count - 1)
                    .sum::<usize>()
            })
            .unwrap();

        assert_eq!(
            res,
            Data::from_hex("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a")?
        );

        Ok(())
    }
}
