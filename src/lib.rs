

}

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_byte_xor_cipher() -> Result<()> {
        let data =
            Data::from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;

        assert_eq!(
            guess_single_byte_xor(&data),
            Data::from_str("Cooking MC's like a pound of bacon")
        );

        Ok(())
    }

    #[test]
    fn fixed_xor() -> Result<()> {
        let lhs = Data::from_hex("1c0111001f010100061a024b53535009181c")?;
        let rhs = Data::from_hex("686974207468652062756c6c277320657965")?;
        let expected = Data::from_hex("746865206b696420646f6e277420706c6179")?;

        assert_eq!(lhs ^ rhs, expected);
        Ok(())
    }
}
