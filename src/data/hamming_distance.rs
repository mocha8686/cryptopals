use crate::Data;

impl Data {
    #[must_use]
    pub fn hamming_distance(&self, other: &Self) -> Option<u32> {
        if self.len() == other.len() {
            let res = (self ^ other).iter().map(|b| b.count_ones()).sum();
            Some(res)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn hamming_distance_works() {
        let lhs = Data::from("this is a test".as_bytes());
        let rhs = Data::from("wokka wokka!!!".as_bytes());
        let res = lhs.hamming_distance(&rhs);
        assert_eq!(Some(37), res);
    }
}
