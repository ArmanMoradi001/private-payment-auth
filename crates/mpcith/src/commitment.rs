//! View commitments.
//!
//! Each party's view is committed *before* the challenge is drawn,
//! binding the prover to all three views. Commitments are hash-based
//! over a selectable [`CryptoBackend`] with fresh 32-byte randomness per
//! view per repetition, domain-separated under
//! `private-payment-auth/mpcith/view/v2`.

use crypto_core::backend::{CryptoBackend, GenericDigest};
use crypto_core::CanonicalEncode;
use crypto_core::SecretBytes;

use crate::encoding;
use crate::error::MpcithError;
use crate::view::PartyView;

/// Domain separator binding view commitments to this protocol and
/// encoding version.
pub const VIEW_COMMITMENT_DOMAIN: &[u8] = b"private-payment-auth/mpcith/view/v2";

/// A binding commitment to one party's view.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewCommitment(crypto_core::Digest);

impl ViewCommitment {
    /// Wraps a digest as a view commitment.
    pub fn from_digest(digest: crypto_core::Digest) -> Self {
        Self(digest)
    }

    /// Borrows the underlying digest.
    pub fn as_digest(&self) -> &crypto_core::Digest {
        &self.0
    }
}

/// Commits to `view` under `randomness`, using backend `B`.
///
/// The message is the canonical view encoding framed by the protocol
/// domain; the commitment is `B::commit(message, randomness)` using the
/// backend-selected hash.
///
/// # Errors
///
/// - [`MpcithError::MalformedCommitment`] if `randomness` is not
///   exactly 32 bytes.
pub fn commit_view<B: CryptoBackend>(
    view: &PartyView,
    randomness: &SecretBytes,
) -> Result<ViewCommitment, MpcithError> {
    let r = crypto_core::CommitmentRandomness::new(randomness.clone())
        .map_err(|_| MpcithError::MalformedCommitment)?;
    let message = commitment_message(view);
    let digest: GenericDigest<B> = B::commit(&message, r.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest.as_bytes()[..32]);
    Ok(ViewCommitment::from_digest(crypto_core::Digest::new(bytes)))
}

/// Checks that `(view, randomness)` opens `commitment`, comparing in
/// constant time, using backend `B`.
///
/// # Errors
///
/// - [`MpcithError::MalformedCommitment`] if `randomness` is not
///   exactly 32 bytes.
pub fn verify_commitment<B: CryptoBackend>(
    commitment: &ViewCommitment,
    view: &PartyView,
    randomness: &SecretBytes,
) -> Result<bool, MpcithError> {
    let r = crypto_core::CommitmentRandomness::new(randomness.clone())
        .map_err(|_| MpcithError::MalformedCommitment)?;
    let message = commitment_message(view);
    let digest: GenericDigest<B> = B::commit(&message, r.as_bytes());
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest.as_bytes()[..32]);
    Ok(crypto_core::Digest::new(bytes).ct_eq(commitment.as_digest()))
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
    use crypto_core::backend::Sha256Backend;
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
        let c = commit_view::<Sha256Backend>(&view, &randomness(1)).expect("valid");
        assert!(verify_commitment::<Sha256Backend>(&c, &view, &randomness(1)).expect("valid"));

        // Different view fails to open.
        let mut other = sample_view();
        other.party_id = PartyId::new(1).expect("valid");
        assert!(!verify_commitment::<Sha256Backend>(&c, &other, &randomness(1)).expect("valid"));

        // Different randomness fails to open.
        assert!(!verify_commitment::<Sha256Backend>(&c, &view, &randomness(2)).expect("valid"));
    }

    #[test]
    fn deterministic_for_same_inputs() {
        let view = sample_view();
        assert_eq!(
            commit_view::<Sha256Backend>(&view, &randomness(9)).expect("valid"),
            commit_view::<Sha256Backend>(&view, &randomness(9)).expect("valid")
        );
    }

    #[test]
    fn rejects_bad_randomness_length() {
        let view = sample_view();
        let short = crypto_core::SecretBytes::new(vec![0u8; 31]);
        assert_eq!(
            commit_view::<Sha256Backend>(&view, &short),
            Err(MpcithError::MalformedCommitment)
        );
    }
}
