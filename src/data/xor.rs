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

#[cfg(test)]
mod tests {
    use crate::Result;

    use super::*;

    #[test]
    fn s1c2_fixed_xor() -> Result<()> {
        let lhs = Data::from_hex_str("1c0111001f010100061a024b53535009181c")?;
        let rhs = Data::from_hex_str("686974207468652062756c6c277320657965")?;

        let res = lhs ^ rhs;
        assert_eq!("746865206b696420646f6e277420706c6179", res.hex());

        Ok(())
    }
}
