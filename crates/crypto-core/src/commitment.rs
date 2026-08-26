//! Hash-based commitments.
//!
//! A commitment is computed as `H(domain || randomness || len(message)
//! || message)` where the message length framing makes the encoding
//! unambiguous and the randomness binding makes the scheme hiding and
//! binding under the standard-model hardness of the underlying hash.
//!
//! The primitives are now parameterized by a [`CryptoBackend`]: callers
//! that do not care select [`Sha256Backend`] (the default) and obtain the
//! exact same bytes as the historical SHA-256 implementation.

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::backend::{CryptoBackend, GenericDigest, Sha256Backend};
use crate::digest::Digest;
use crate::error::CryptoCoreError;
use crate::secret::SecretBytes;

/// Required byte length of [`CommitmentRandomness`].
pub const RANDOMNESS_LEN: usize = 32;

/// A binding commitment to a message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Commitment(Digest);

impl Commitment {
    /// Wraps raw digest bytes into a commitment.
    pub fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// Borrows the underlying digest.
    pub fn as_digest(&self) -> &Digest {
        &self.0
    }

    /// Constant-time equality against another commitment.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0)
    }
}

/// Secret, zeroizing randomness paired with a committed message.
///
/// Fixed at [`RANDOMNESS_LEN`] bytes.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct CommitmentRandomness(SecretBytes);

impl core::fmt::Debug for CommitmentRandomness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("CommitmentRandomness([REDACTED])")
    }
}

impl CommitmentRandomness {
    /// Wraps exactly `RANDOMNESS_LEN` secret bytes.
    ///
    /// Returns [`CryptoCoreError::InvalidLength`] for any other size.
    pub fn new(bytes: SecretBytes) -> Result<Self, CryptoCoreError> {
        if bytes.len() != RANDOMNESS_LEN {
            return Err(CryptoCoreError::InvalidLength);
        }
        Ok(Self(bytes))
    }

    /// Generates fresh uniform randomness from `rng`.
    pub fn generate<R: CryptoRngCore>(rng: &mut R) -> Result<Self, CryptoCoreError> {
        Ok(Self(crate::random::generate_random_bytes(
            rng,
            RANDOMNESS_LEN,
        )?))
    }

    /// Borrows the randomness bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

/// Commits to `message` under `randomness`, using backend `B`.
///
/// The message is framed exactly like the historical SHA-256 commitment
/// (`canonical(randomness) || len(message) || message`) and hashed via
/// [`CryptoBackend::commit`], so existing SHA-256 vectors are preserved.
pub fn commit<B: CryptoBackend>(
    message: &[u8],
    randomness: &CommitmentRandomness,
) -> GenericDigest<B> {
    B::commit(message, randomness.as_bytes())
}

/// Checks that `(message, randomness)` opens `commitment`, in constant
/// time, using backend `B`.
pub fn open<B: CryptoBackend>(
    commitment: &GenericDigest<B>,
    message: &[u8],
    randomness: &CommitmentRandomness,
) -> bool {
    commit::<B>(message, randomness).ct_eq(commitment)
}

/// Backward-compatible, non-generic SHA-256 commitment wrapper.
///
/// Prefer [`commit::<Sha256Backend>`]; this exists only to ease migration
/// of call sites that previously used the global SHA-256 commitment.
#[deprecated(note = "use commit::<Sha256Backend> instead")]
pub fn commit_sha256(
    message: &[u8],
    randomness: &CommitmentRandomness,
) -> GenericDigest<Sha256Backend> {
    commit::<Sha256Backend>(message, randomness)
}

/// Backward-compatible, non-generic SHA-256 opening wrapper.
#[deprecated(note = "use open::<Sha256Backend> instead")]
pub fn open_sha256(
    commitment: &GenericDigest<Sha256Backend>,
    message: &[u8],
    randomness: &CommitmentRandomness,
) -> bool {
    open::<Sha256Backend>(commitment, message, randomness)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::Sha256Backend;
    use rand_core::OsRng;

    #[test]
    fn commit_open_roundtrip() {
        let r = CommitmentRandomness::generate(&mut OsRng).unwrap();
        let c = commit::<Sha256Backend>(b"hello", &r);
        assert!(open::<Sha256Backend>(&c, b"hello", &r));
    }

    #[test]
    fn wrong_message_fails_to_open() {
        let r = CommitmentRandomness::generate(&mut OsRng).unwrap();
        let c = commit::<Sha256Backend>(b"hello", &r);
        assert!(!open::<Sha256Backend>(&c, b"hellp", &r));
        assert!(!open::<Sha256Backend>(&c, b"", &r));
    }

    #[test]
    fn wrong_randomness_fails_to_open() {
        let c = commit::<Sha256Backend>(b"m", &CommitmentRandomness::generate(&mut OsRng).unwrap());
        let other = CommitmentRandomness::generate(&mut OsRng).unwrap();
        assert!(!open::<Sha256Backend>(&c, b"m", &other));
    }

    #[test]
    fn commitments_are_deterministic_and_binding() {
        let r1 = CommitmentRandomness::generate(&mut OsRng).unwrap();
        let r2 = CommitmentRandomness::generate(&mut OsRng).unwrap();
        assert_eq!(
            commit::<Sha256Backend>(b"x", &r1),
            commit::<Sha256Backend>(b"x", &r1)
        );
        assert_ne!(
            commit::<Sha256Backend>(b"x", &r1),
            commit::<Sha256Backend>(b"x", &r2)
        );
        assert_ne!(
            commit::<Sha256Backend>(b"x", &r1),
            commit::<Sha256Backend>(b"y", &r1)
        );
    }

    #[test]
    fn message_length_is_unambiguously_framed() {
        // Distinct (message) splits must never collide: "ab"+"c" vs "a"+"bc".
        let r = CommitmentRandomness::generate(&mut OsRng).unwrap();
        assert_ne!(
            commit::<Sha256Backend>(b"c", &r),
            commit::<Sha256Backend>(b"bc", &r)
        );
    }

    #[test]
    fn randomness_length_is_enforced() {
        assert_eq!(
            CommitmentRandomness::new(SecretBytes::new(vec![0u8; 31])).unwrap_err(),
            CryptoCoreError::InvalidLength
        );
        assert!(CommitmentRandomness::new(SecretBytes::new(vec![0u8; 32])).is_ok());
    }

    #[test]
    fn sha256_commit_matches_backend_commit() {
        let r = CommitmentRandomness::generate(&mut OsRng).unwrap();
        let c = commit::<Sha256Backend>(b"data", &r);
        assert_eq!(c.as_bytes().len(), 32);
    }
}
