//! Hash abstraction and domain separation.

use sha2::{Digest as _, Sha256};

use crate::digest::{Digest, DIGEST_LEN};
use crate::encoding::CanonicalEncode;

/// A cryptographic hash function.
///
/// The [`Self::Output`] associated type exists so concrete functions can
/// return typed digests rather than bare byte vectors.
pub trait HashFunction {
    /// The output type produced by this hash function.
    type Output: AsRef<[u8]>;

    /// Hashes raw bytes.
    fn hash(data: &[u8]) -> Self::Output;

    /// Hashes `data` under an application-specific protocol `domain`.
    ///
    /// The domain is canonically length-prefixed before being hashed
    /// together with `data`, making cross-domain collisions impossible
    /// for any two distinct domains of any lengths.
    fn hash_domain(domain: &[u8], data: &[u8]) -> Self::Output;
}

/// SHA-256, the workspace's default hash function.
#[derive(Clone, Copy, Debug)]
pub struct Sha256Hash;

impl HashFunction for Sha256Hash {
    type Output = [u8; DIGEST_LEN];

    fn hash(data: &[u8]) -> Self::Output {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    fn hash_domain(domain: &[u8], data: &[u8]) -> Self::Output {
        let mut framed = Vec::with_capacity(4 + domain.len() + data.len());
        domain.encode(&mut framed);
        framed.extend_from_slice(data);
        Self::hash(&framed)
    }
}

impl From<[u8; DIGEST_LEN]> for Digest {
    fn from(bytes: [u8; DIGEST_LEN]) -> Self {
        Digest::new(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::DIGEST_LEN;

    #[test]
    fn known_sha256_vector() {
        let out = Sha256Hash::hash(b"abc");
        let expected = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        assert_eq!(out, expected);
        let d: Digest = out.into();
        assert_eq!(d.as_bytes().len(), DIGEST_LEN);
    }

    #[test]
    fn domains_are_separated() {
        let a = Sha256Hash::hash_domain(b"ab", b"c");
        let b = Sha256Hash::hash_domain(b"a", b"bc");
        assert_ne!(a, b);
        assert_eq!(a, Sha256Hash::hash_domain(b"ab", b"c"));
    }

    #[test]
    fn domain_output_differs_from_plain_hash() {
        let framed = Sha256Hash::hash_domain(b"d", b"x");
        assert_ne!(framed, Sha256Hash::hash(b"x"));
        assert_ne!(framed, Sha256Hash::hash(b"dx"));
    }
}
