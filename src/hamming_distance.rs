pub fn hamming_distance(lhs: &[u8], rhs: &[u8]) -> u32 {
    lhs.iter()
        .zip(rhs.iter())
        .map(|(a, b)| a ^ b)
        .map(u8::count_ones)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_distance_works() {
        let lhs = "this is a test".as_bytes();
        let rhs = "wokka wokka!!!".as_bytes();
        let res = hamming_distance(lhs, rhs);
        assert_eq!(37, res);
    }
}
