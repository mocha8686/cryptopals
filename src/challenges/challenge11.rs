use anyhow::Result;
use itertools::Itertools;
use rand::prelude::*;

use crate::{
    cipher::{aes_128_cbc::Aes128Cbc, aes_128_ecb::Aes128Ecb, Encrypt},
    data::Data,
    FUNKY_MUSIC, oracle::{EcbOrCbc, ecb_or_cbc},
};

const NUM_TESTS: usize = 1000;

fn black_box(plaintext: &Data) -> (Data, EcbOrCbc) {
    let key: [u8; 16] = rand::random();
    let (cipher, oracle_result): (Box<dyn Encrypt>, _) = if rand::random() {
        (Box::new(Aes128Ecb::new(key)), EcbOrCbc::Ecb)
    } else {
        let iv: [u8; 16] = rand::random();
        (Box::new(Aes128Cbc::new(key, iv)), EcbOrCbc::Cbc)
    };

    let prefix: Data = (0..=(thread_rng().gen_range(5..=10)))
        .map(|_| random())
        .collect_vec()
        .into();
    let postfix: Data = (0..=(thread_rng().gen_range(5..=10)))
        .map(|_| random())
        .collect_vec()
        .into();

    (
        cipher.encrypt(&(prefix + plaintext + postfix)).unwrap(),
        oracle_result,
    )
}

#[test]
#[ignore = "loop"]
fn ecb_or_cbc_test() -> Result<()> {
    for _ in 0..NUM_TESTS {
        let (data, expected) = black_box(&FUNKY_MUSIC.parse()?);
        assert_eq!(expected, ecb_or_cbc(&data));
    }

    Ok(())
}
