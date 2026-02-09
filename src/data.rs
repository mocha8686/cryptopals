//! [`Data`] struct definition, trait impls, and other methods.

use std::{
    fmt::Display,
    ops::{Deref, DerefMut},
};

mod base64;
mod hamming_distance;
mod hex;
mod pad;
mod xor;

/// The main struct for manipulating bytes with [ciphers][crate::cipher],
/// [blackboxes][crate::blackbox], and other transformations.
///
/// # Examples
///
/// ```
/// use cryptopals::Data;
///
/// let data1 = Data::from("hello, world!".as_bytes());
/// let data2 = Data::from("alfredo sauce".as_bytes());
///
/// let hamming_distance = data1.hamming_distance(&data2);
/// assert_eq!(Some(38), hamming_distance);
/// ```
#[derive(Debug, Clone)]
pub struct Data(pub(crate) Box<[u8]>);

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
