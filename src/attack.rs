
/// Attacks on [repeating key XOR ciphers][crate::Data::xor()].
///
/// Due to the nature of the repeating key, we are able to extract the entire plaintext and key
/// given a sufficiently long ciphertext.
pub mod xor;
