//! View commitments.
//!
//! Each party's view is committed *before* the challenge is drawn,
//! binding the prover to all three views. Commitments are hash-based
//! (`crypto_core::commit` over SHA-256) with fresh 32-byte randomness
//! per view per repetition, domain-separated under
//! `private-payment-auth/mpcith/view/v1`.

use crypto_core::CanonicalEncode;
use crypto_core::{Commitment, CommitmentRandomness, Digest, Sha256Hash};

use crate::encoding;
use crate::error::MpcithError;
use crate::view::PartyView;

/// Domain separator binding view commitments to this protocol and
/// encoding version.
pub const VIEW_COMMITMENT_DOMAIN: &[u8] = b"private-payment-auth/mpcith/view/v1";

/// A binding commitment to one party's view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewCommitment(Digest);

impl ViewCommitment {
    /// Wraps a digest as a view commitment.
    pub fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// Borrows the underlying digest.
    pub fn as_digest(&self) -> &Digest {
        &self.0
    }
}

/// Commits to `view` under `randomness`.
///
/// The message is the canonical view encoding framed by the protocol
/// domain; the commitment is `H(len(randomness) ‖ randomness ‖ len(msg)
/// ‖ msg)` via [`crypto_core::commit`].
///
/// # Errors
///
/// - [`MpcithError::MalformedCommitment`] if `randomness` is not
///   exactly 32 bytes.
pub fn commit_view(
    view: &PartyView,
    randomness: &crypto_core::SecretBytes,
) -> Result<ViewCommitment, MpcithError> {
    let r = CommitmentRandomness::new(randomness.clone())
        .map_err(|_| MpcithError::MalformedCommitment)?;
    let message = commitment_message(view);
    let commitment = crypto_core::commit::<Sha256Hash>(&message, &r);
    Ok(ViewCommitment::from_digest(*commitment.as_digest()))
}

/// Checks that `(view, randomness)` opens `commitment`, comparing in
/// constant time.
///
/// # Errors
///
/// - [`MpcithError::MalformedCommitment`] if `randomness` is not
///   exactly 32 bytes.
pub fn verify_commitment(
    commitment: &ViewCommitment,
    view: &PartyView,
    randomness: &crypto_core::SecretBytes,
) -> Result<bool, MpcithError> {
    let r = CommitmentRandomness::new(randomness.clone())
        .map_err(|_| MpcithError::MalformedCommitment)?;
    let message = commitment_message(view);
    let expected = crypto_core::commit::<Sha256Hash>(&message, &r);
    Ok(expected.ct_eq(&Commitment::from_digest(*commitment.as_digest())))
}

/// Builds the domain-framed canonical message committed for a view.
fn commitment_message(view: &PartyView) -> Vec<u8> {
    let mut message = Vec::new();
    VIEW_COMMITMENT_DOMAIN.encode(&mut message);
    encoding::encode_view(view, &mut message);
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{FieldElement, PartyId, RepetitionId};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn sample_view() -> PartyView {
        PartyView {
            repetition_id: RepetitionId::new(1),
            party_id: PartyId::new(0).expect("valid"),
            input_shares: vec![FieldElement::from(42u64)],
            local_operations: Vec::new(),
            triple_shares: Vec::new(),
            opened_values: Vec::new(),
        }
    }

    fn randomness(seed: u64) -> crypto_core::SecretBytes {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let mut bytes = vec![0u8; 32];
        use rand_core::RngCore;
        rng.fill_bytes(&mut bytes);
        crypto_core::SecretBytes::new(bytes)
    }

    #[test]
    fn commitments_bind_views_and_randomness() {
        let view = sample_view();
        let c = commit_view(&view, &randomness(1)).expect("valid");
        assert!(verify_commitment(&c, &view, &randomness(1)).expect("valid"));

        // Different view fails to open.
        let mut other = sample_view();
        other.party_id = PartyId::new(1).expect("valid");
        assert!(!verify_commitment(&c, &other, &randomness(1)).expect("valid"));

        // Different randomness fails to open.
        assert!(!verify_commitment(&c, &view, &randomness(2)).expect("valid"));
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let view = sample_view();
        assert_eq!(
            commit_view(&view, &randomness(9)).expect("valid"),
            commit_view(&view, &randomness(9)).expect("valid")
        );
    }

    #[test]
    fn rejects_bad_randomness_length() {
        let view = sample_view();
        let short = crypto_core::SecretBytes::new(vec![0u8; 31]);
        assert_eq!(
            commit_view(&view, &short),
            Err(MpcithError::MalformedCommitment)
        );
    }
}
