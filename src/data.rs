use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
};

use crate::hamming_distance::hamming_distance;

pub mod base64;
pub mod hex;
pub mod xor;

#[derive(Debug, Clone)]
pub struct Data(pub(crate) Box<[u8]>);

impl Data {
    #[must_use]
    pub fn hamming_distance(&self, other: &Self) -> Option<u32> {
        if self.len() == other.len() {
            let res = hamming_distance(self, other);
            Some(res)
        } else {
            None
        }
    }
}

impl<T: Into<Box<[u8]>>> From<T> for Data {
    fn from(value: T) -> Self {
        Self(value.into())
    }
}

impl AsRef<[u8]> for Data {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<T: AsRef<[u8]>> PartialEq<T> for Data {
    fn eq(&self, other: &T) -> bool {
        &*self.0 == other.as_ref()
    }
}

impl PartialEq<Data> for &str {
    fn eq(&self, other: &Data) -> bool {
        &*other.0 == self.as_bytes()
    }
}

impl Display for Data {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self))
    }
}

impl Deref for Data {
    type Target = Box<[u8]>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Data {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
