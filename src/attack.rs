//! Collection of attacks on ciphers and certain blackboxes.
//!
//! Attacks may require certain side-channels, sufficiently long ciphertexts, a partial or full
//! ciphertext decryption sample, or other additional info. The effects range from ciphertext
//! injection (e.g. `admin=true`), to partial plaintext extraction, or for some cases, a full key
//! extraction and plaintext decryption.

pub mod xor;
