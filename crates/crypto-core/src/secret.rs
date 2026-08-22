//! Owned secret byte containers with zeroization on drop.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// An owned container for secret bytes.
///
/// Contents are zeroized when the value is dropped and are redacted in
/// [`Debug`] output.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Wraps the given bytes into a protected container.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Borrows the secret contents.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the length of the secret in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the secret is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretBytes([REDACTED])")
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted() {
        let secret = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(format!("{secret:?}"), "SecretBytes([REDACTED])");
    }

    #[test]
    fn accessors_work() {
        let secret = SecretBytes::new(vec![9, 8]);
        assert_eq!(secret.as_bytes(), &[9, 8]);
        assert_eq!(secret.len(), 2);
        assert!(!secret.is_empty());
        assert!(SecretBytes::new(Vec::new()).is_empty());
    }
}
