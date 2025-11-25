pub fn hamming_distance<'l, 'r, L, R, T, U>(lhs: L, rhs: R) -> u32
where
    T: Into<&'l u8>,
    U: Into<&'r u8>,
    L: Iterator<Item = T>,
    R: Iterator<Item = U>,
{
    lhs
        .map(Into::into)
        .zip(rhs.map(Into::into))
        .map(|(a, b)| a ^ b)
        .map(u8::count_ones)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_works() {
        let lhs = "this is a test".as_bytes().iter();
        let rhs = "wokka wokka!!!".as_bytes().iter();
        let res = hamming_distance(lhs, rhs);
        assert_eq!(37, res);
    }
}
