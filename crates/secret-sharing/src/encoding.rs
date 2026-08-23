//! Canonical binary encoding for [`Share`].
//!
//! Wire format (all integers big-endian):
//!
//! ```text
//! version (1 byte)
//!   || threshold  (4 bytes BE)
//!   || share_count (4 bytes BE)
//!   || index      (4 bytes BE)
//!   || value      (FIELD_ELEMENT_SIZE bytes BE, zero-padded)
//! ```
//!
//! The encoding is canonical: a given share has exactly one valid byte
//! representation and decoding rejects trailing bytes.

use crate::error::SecretSharingError;
use crate::field::{element_to_be_bytes, FIELD_ELEMENT_SIZE};
use crate::share::{Share, SHARE_VERSION};

/// Number of bytes in an encoded share.
pub const ENCODED_SHARE_SIZE: usize = 13 + FIELD_ELEMENT_SIZE;

impl Share {
    /// Encodes this share into its canonical byte representation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ENCODED_SHARE_SIZE);
        out.push(self.version);
        out.extend_from_slice(&self.threshold.to_be_bytes());
        out.extend_from_slice(&self.share_count.to_be_bytes());
        out.extend_from_slice(&self.index.to_be_bytes());
        out.extend_from_slice(&element_to_be_bytes(&self.value));
        out
    }

    /// Decodes a share from its canonical byte representation.
    ///
    /// # Errors
    ///
    /// Returns [`SecretSharingError::MalformedEncoding`] if the input length
    /// is wrong or the version byte is unsupported,
    /// [`SecretSharingError::InvalidShareIndex`] if the index is zero, and
    /// [`SecretSharingError::InvalidFieldElement`] if the value is at or
    /// above the field modulus.
    pub fn decode(bytes: &[u8]) -> Result<Self, SecretSharingError> {
        if bytes.len() != ENCODED_SHARE_SIZE {
            return Err(SecretSharingError::MalformedEncoding);
        }
        if bytes[0] != SHARE_VERSION {
            return Err(SecretSharingError::MalformedEncoding);
        }
        let threshold = u32::from_be_bytes(bytes[1..5].try_into().expect("fixed slice"));
        let share_count = u32::from_be_bytes(bytes[5..9].try_into().expect("fixed slice"));
        let index = u32::from_be_bytes(bytes[9..13].try_into().expect("fixed slice"));
        let value = crate::field::element_from_be_bytes(&bytes[13..])
            .map_err(|_| SecretSharingError::InvalidFieldElement)?;
        if threshold == 0 || share_count == 0 {
            return Err(SecretSharingError::MalformedEncoding);
        }
        if index == 0 || index > share_count {
            return Err(SecretSharingError::InvalidShareIndex);
        }
        Ok(Self {
            version: SHARE_VERSION,
            threshold,
            share_count,
            index,
            value,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::element_from_be_bytes;

    fn sample_share() -> Share {
        Share::new(
            3,
            5,
            2,
            element_from_be_bytes(&[0x01, 0x02, 0x03]).expect("valid"),
        )
        .expect("valid")
    }

    #[test]
    fn round_trip() {
        let share = sample_share();
        let encoded = share.encode();
        assert_eq!(encoded.len(), ENCODED_SHARE_SIZE);
        assert_eq!(Share::decode(&encoded).expect("valid"), share);
    }

    #[test]
    fn layout_is_canonical() {
        let encoded = sample_share().encode();
        assert_eq!(encoded[0], SHARE_VERSION);
        assert_eq!(&encoded[1..5], &3u32.to_be_bytes());
        assert_eq!(&encoded[5..9], &5u32.to_be_bytes());
        assert_eq!(&encoded[9..13], &2u32.to_be_bytes());
        assert_eq!(&encoded[13..16], &[0, 0, 0]);
        assert_eq!(&encoded[13 + 29..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn rejects_trailing_bytes_and_bad_lengths() {
        let mut encoded = sample_share().encode();
        encoded.push(0);
        assert_eq!(
            Share::decode(&encoded),
            Err(SecretSharingError::MalformedEncoding)
        );
        encoded.pop();
        encoded.pop();
        assert_eq!(
            Share::decode(&encoded),
            Err(SecretSharingError::MalformedEncoding)
        );
        assert_eq!(
            Share::decode(&[]),
            Err(SecretSharingError::MalformedEncoding)
        );
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut encoded = sample_share().encode();
        encoded[0] = 99;
        assert_eq!(
            Share::decode(&encoded),
            Err(SecretSharingError::MalformedEncoding)
        );
    }

    #[test]
    fn rejects_zero_index_and_invalid_value() {
        let mut encoded = sample_share().encode();
        encoded[12] = 0;
        assert_eq!(
            Share::decode(&encoded),
            Err(SecretSharingError::InvalidShareIndex)
        );

        let mut encoded = sample_share().encode();
        // Field modulus starts with 0x10 in the top byte; 0xff exceeds it.
        encoded[13] = 0xff;
        assert_eq!(
            Share::decode(&encoded),
            Err(SecretSharingError::InvalidFieldElement)
        );
    }
}
