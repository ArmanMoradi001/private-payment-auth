//! Canonical, unambiguous encoding of values into byte buffers.
//!
//! All encodings here are deterministic and self-delimiting where
//! variable-length data is involved, so that concatenations of encoded
//! values have unique decodings.

use crate::digest::Digest;
use crate::secret::SecretBytes;

/// Canonical encoding of a value into a byte buffer.
///
/// Implementations must be injective: distinct logical values must never
/// produce the same encoding. Variable-length data is therefore framed
/// with its length as 4 bytes big-endian.
pub trait CanonicalEncode {
    /// Appends the canonical encoding of `self` to `out`.
    fn encode(&self, out: &mut Vec<u8>);
}

fn encode_length_prefixed(bytes: &[u8], out: &mut Vec<u8>) {
    let len = u32::try_from(bytes.len()).expect("encoding input exceeds u32 length");
    out.reserve(4 + bytes.len());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

impl CanonicalEncode for &[u8] {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_length_prefixed(self, out);
    }
}

impl CanonicalEncode for SecretBytes {
    fn encode(&self, out: &mut Vec<u8>) {
        encode_length_prefixed(self.as_bytes(), out);
    }
}

impl CanonicalEncode for Digest {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_are_length_prefixed() {
        let mut out = Vec::new();
        (&b"abc"[..]).encode(&mut out);
        assert_eq!(out, [0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn empty_slice_encodes_to_length_only() {
        let mut out = Vec::new();
        (&[][..]).encode(&mut out);
        assert_eq!(out, [0, 0, 0, 0]);
    }

    #[test]
    fn secret_bytes_match_slice_encoding() {
        let secret = SecretBytes::new(vec![1, 2]);
        let mut from_secret = Vec::new();
        secret.encode(&mut from_secret);
        let mut from_slice = Vec::new();
        (&[1_u8, 2][..]).encode(&mut from_slice);
        assert_eq!(from_secret, from_slice);
    }

    #[test]
    fn digest_is_unprefixed_fixed_width() {
        let d = Digest::new([7; DIGEST_TEST_LEN]);
        let mut out = Vec::new();
        d.encode(&mut out);
        assert_eq!(out.len(), DIGEST_TEST_LEN);
        assert!(out.iter().all(|&b| b == 7));
    }

    const DIGEST_TEST_LEN: usize = 32;
}
