//! Fixed-size digests with constant-time equality.

use core::fmt;
use subtle::ConstantTimeEq;

/// Number of bytes in a [`Digest`].
pub const DIGEST_LEN: usize = 32;

/// A fixed-size (32-byte) typed digest.
#[derive(Copy, Clone)]
pub struct Digest([u8; DIGEST_LEN]);

impl Digest {
    /// The all-zero digest.
    pub const ZERO: Self = Self([0u8; DIGEST_LEN]);

    /// Constructs a digest from raw bytes.
    pub fn new(bytes: [u8; DIGEST_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the digest bytes.
    pub fn as_bytes(&self) -> &[u8; DIGEST_LEN] {
        &self.0
    }

    /// Returns `true` if this digest equals `other` in constant time.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl PartialEq for Digest {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl Eq for Digest {}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({})", self.hex())
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.hex())
    }
}

impl Digest {
    fn hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equality_is_constant_time_semantics() {
        let a = Digest::new([1; DIGEST_LEN]);
        assert!(a.ct_eq(&a));
        assert!(a == a);
        assert!(!(a.ct_eq(&Digest::ZERO)));
        assert!(a != Digest::ZERO);
    }

    #[test]
    fn hex_formatting() {
        let d = Digest::new([0xab; DIGEST_LEN]);
        assert_eq!(format!("{d}"), "ab".repeat(DIGEST_LEN));
        assert_eq!(format!("{d:?}"), format!("Digest({})", "ab".repeat(32)));
    }
}
