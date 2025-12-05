use std::ops::BitXor;

use super::Data;

impl Data {
    #[must_use]
    pub fn xor(&self, other: &Self) -> Self {
        let len = self.len().max(other.len());
        let bytes = self
            .iter()
            .cycle()
            .zip(other.iter().cycle())
            .take(len)
            .map(|(a, b)| a ^ b)
            .collect();
        Self(bytes)
    }
}

impl BitXor for &Data {
    type Output = Data;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.xor(rhs)
    }
}

impl BitXor for Data {
    type Output = Data;

    fn bitxor(self, rhs: Self) -> Self::Output {
        self.xor(&rhs)
    }
}

impl BitXor<Data> for &Data {
    type Output = Data;

    fn bitxor(self, rhs: Data) -> Self::Output {
        self.xor(&rhs)
    }
}

impl BitXor<&Data> for Data {
    type Output = Data;

    fn bitxor(self, rhs: &Data) -> Self::Output {
        self.xor(rhs)
    }
}

impl BitXor<u8> for &Data {
    type Output = Data;

    fn bitxor(self, rhs: u8) -> Self::Output {
        let bytes = self.iter().map(|b| b ^ rhs).collect();
        Data(bytes)
    }
}

impl BitXor<u8> for Data {
    type Output = Data;

    fn bitxor(self, rhs: u8) -> Self::Output {
        (&self).bitxor(rhs)
    }
}

#[cfg(test)]
mod tests {
    use crate::Result;

    use super::*;

    #[test]
    fn s1c2_fixed_xor() -> Result<()> {
        let lhs = Data::from_hex("1c0111001f010100061a024b53535009181c")?;
        let rhs = Data::from_hex("686974207468652062756c6c277320657965")?;

        let res = lhs ^ rhs;
        assert_eq!("746865206b696420646f6e277420706c6179", res.hex());

        Ok(())
    }

    #[test]
    fn s1c5_implement_repeating_key_xor() {
        let data = Data::from(
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes(),
        );
        let key = Data::from("ICE".as_bytes());

        let res = data ^ key;
        assert_eq!(
            "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
            res.hex()
        );
    }
}
