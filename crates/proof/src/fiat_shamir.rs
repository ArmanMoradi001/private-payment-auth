//! Fiat–Shamir challenge derivation.
//!
//! The challenge for each repetition is a deterministic hash of
//! everything the prover has committed to before opening views:
//! protocol version, statement, repetition id, and all three view
//! commitments. Prover and verifier run the *same* derivation, so a
//! stored challenge that disagrees with the recomputation is proof of
//! tampering.
//!
//! Domain separation: the message is hashed under
//! `private-payment-auth/mpcith/fs/v1` using the length-framed domain
//! hashing of `crypto_core::Sha256Hash::hash_domain`, making collision
//! with any other protocol use of SHA-256 impossible up to hash
//! security.
//!
//! Bias note: `hidden_party = digest[0] % 3` introduces a slight
//! modulo bias (2/256 vs 1/256 per party difference). For three
//! parties this is negligible relative to the 1/3 soundness error and
//! acceptable; rejection sampling would remove it entirely if ever
//! needed.

use crypto_core::{HashFunction, Sha256Hash};
use mpcith::{Challenge, PartyId, RepetitionId, ViewCommitment};

use crate::error::ProofError;
use crate::statement::Statement;

/// Domain separator for Fiat–Shamir challenge derivation.
pub const FS_DOMAIN: &[u8] = b"private-payment-auth/mpcith/fs/v1";

/// Derives FS challenges from statement and commitments.
#[derive(Clone, Copy, Debug, Default)]
pub struct FiatShamirChallengeGenerator;

/// Abstract generator so alternative derivation rules (future
/// versions) can be injected without touching callers.
pub trait ChallengeGenerator {
    /// Derives the hidden-party challenge for one repetition.
    fn derive(
        &self,
        statement: &Statement,
        commitments: &[ViewCommitment],
        repetition_id: RepetitionId,
    ) -> Result<Challenge, ProofError>;
}

impl ChallengeGenerator for FiatShamirChallengeGenerator {
    fn derive(
        &self,
        statement: &Statement,
        commitments: &[ViewCommitment],
        repetition_id: RepetitionId,
    ) -> Result<Challenge, ProofError> {
        let mut message = Vec::new();
        message.push(crate::PROTOCOL_VERSION);
        statement.encode_into(&mut message);
        message.extend_from_slice(&repetition_id.get().to_be_bytes());
        for commitment in commitments {
            message.extend_from_slice(commitment.as_digest().as_bytes());
        }

        let digest = Sha256Hash::hash_domain(FS_DOMAIN, &message);
        // Slight modulo bias (documented above): acceptable at k = 3.
        let value = digest[0] % 3;
        let hidden_party = PartyId::new(value).map_err(|_| ProofError::MalformedEncoding)?;
        Ok(Challenge { hidden_party })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;
    use circuit::CircuitId;
    use mpcith::FieldElement;

    fn fixture_statement() -> Statement {
        Statement {
            circuit_id: CircuitId::from_digest(crypto_core::Digest::new([1u8; 32])),
            public_inputs: vec![mpc::PublicValue::new(FieldElement::from(3u64))],
            expected_outputs: vec![mpc::PublicValue::new(FieldElement::zero())],
        }
    }

    fn commitments(seed: u8) -> Vec<ViewCommitment> {
        (0..3)
            .map(|i| ViewCommitment::from_digest(crypto_core::Digest::new([seed + i as u8; 32])))
            .collect()
    }

    #[test]
    fn derivation_is_deterministic() {
        let gen = FiatShamirChallengeGenerator;
        let s = fixture_statement();
        let c = commitments(10);
        assert_eq!(
            gen.derive(&s, &c, RepetitionId::new(0)).expect("ok"),
            gen.derive(&s, &c, RepetitionId::new(0)).expect("ok")
        );
    }

    #[test]
    fn mutations_change_the_challenge() {
        let gen = FiatShamirChallengeGenerator;
        let s = fixture_statement();
        let base = gen
            .derive(&s, &commitments(10), RepetitionId::new(0))
            .unwrap();

        // Different repetition id.
        assert_ne!(
            base,
            gen.derive(&s, &commitments(10), RepetitionId::new(1))
                .unwrap()
        );
        // Different commitments.
        assert_ne!(
            base,
            gen.derive(&s, &commitments(11), RepetitionId::new(0))
                .unwrap()
        );
        // Different public input.
        let mut other = fixture_statement();
        other.public_inputs[0] = mpc::PublicValue::new(FieldElement::from(4u64));
        assert_ne!(
            base,
            gen.derive(&other, &commitments(10), RepetitionId::new(0))
                .unwrap()
        );
    }
}
