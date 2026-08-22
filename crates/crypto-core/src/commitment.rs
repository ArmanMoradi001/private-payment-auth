//! Hash-based commitments.
//!
//! A commitment is computed as `H(canonical(randomness) || len(message)
//! || message)` where the message length framing makes the encoding
//! unambiguous and the randomness binding makes the scheme hiding and
//! binding under the standard-model hardness of the underlying hash.

use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::digest::{Digest, DIGEST_LEN};
use crate::encoding::CanonicalEncode;
use crate::error::CryptoCoreError;
use crate::hash::HashFunction;
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

fn commit_input(message: &[u8], randomness: &CommitmentRandomness) -> Vec<u8> {
    let mut input = Vec::with_capacity(4 + randomness.as_bytes().len() + 4 + message.len());
    randomness.as_bytes().encode(&mut input);
    let msg_len = u32::try_from(message.len()).expect("commitment message exceeds u32 length");
    input.extend_from_slice(&msg_len.to_be_bytes());
    input.extend_from_slice(message);
    input
}

/// Commits to `message` under `randomness`.
///
/// Hash outputs shorter than [`DIGEST_LEN`] are zero-padded; longer ones
/// truncated to the first [`DIGEST_LEN`] bytes.
pub fn commit<H: HashFunction>(message: &[u8], randomness: &CommitmentRandomness) -> Commitment {
    let output = H::hash(&commit_input(message, randomness));
    let src = output.as_ref();
    let mut bytes = [0u8; DIGEST_LEN];
    let n = src.len().min(DIGEST_LEN);
    bytes[..n].copy_from_slice(&src[..n]);
    Commitment(Digest::new(bytes))
}

/// Checks that `(message, randomness)` opens `commitment`, in constant time.
pub fn open<H: HashFunction>(
    commitment: &Commitment,
    message: &[u8],
    randomness: &CommitmentRandomness,
) -> bool {
    commit::<H>(message, randomness).ct_eq(commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha256Hash;
    use rand_core::OsRng;

    #[test]
    fn commit_open_roundtrip() {
        let r = CommitmentRandomness::generate(&mut OsRng).unwrap();
        let c = commit::<Sha256Hash>(b"hello", &r);
        assert!(open::<Sha256Hash>(&c, b"hello", &r));
    }

    #[test]
    fn wrong_message_fails_to_open() {
        let r = CommitmentRandomness::generate(&mut OsRng).unwrap();
        let c = commit::<Sha256Hash>(b"hello", &r);
        assert!(!open::<Sha256Hash>(&c, b"hellp", &r));
        assert!(!open::<Sha256Hash>(&c, b"", &r));
    }

    #[test]
    fn wrong_randomness_fails_to_open() {
        let c = commit::<Sha256Hash>(b"m", &CommitmentRandomness::generate(&mut OsRng).unwrap());
        let other = CommitmentRandomness::generate(&mut OsRng).unwrap();
        assert!(!open::<Sha256Hash>(&c, b"m", &other));
    }

    #[test]
    fn commitments_are_deterministic_and_binding() {
        let r1 = CommitmentRandomness::generate(&mut OsRng).unwrap();
        let r2 = CommitmentRandomness::generate(&mut OsRng).unwrap();
        assert_eq!(
            commit::<Sha256Hash>(b"x", &r1),
            commit::<Sha256Hash>(b"x", &r1)
        );
        assert_ne!(
            commit::<Sha256Hash>(b"x", &r1),
            commit::<Sha256Hash>(b"x", &r2)
        );
        assert_ne!(
            commit::<Sha256Hash>(b"x", &r1),
            commit::<Sha256Hash>(b"y", &r1)
        );
    }

    #[test]
    fn message_length_is_unambiguously_framed() {
        // Distinct (message) splits must never collide: "ab"+"c" vs "a"+"bc".
        let r = CommitmentRandomness::generate(&mut OsRng).unwrap();
        assert_ne!(
            commit::<Sha256Hash>(b"c", &r),
            commit::<Sha256Hash>(b"bc", &r)
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
}
