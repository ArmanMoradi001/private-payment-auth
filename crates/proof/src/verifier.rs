//! The independent non-interactive verifier.
//!
//! This module never calls prover code. It re-derives every
//! Fiat–Shamir challenge from the statement and the committed views,
//! rejects any stored challenge that disagrees, and then delegates the
//! per-repetition MPCitH checks to [`mpcith::MpcithVerifier`] — which
//! re-implements circuit semantics from scratch on its side.

use circuit::Circuit;
use core::marker::PhantomData;
use crypto_core::backend::{CryptoBackend, Sha256Backend};

use mpcith::{FieldElement, MpcithVerifier, VerificationResult as InnerResult};

use crate::error::ProofError;
use crate::fiat_shamir::{ChallengeGenerator, FiatShamirChallengeGenerator};
use crate::proof::NonInteractiveProof;
use crate::statement::Statement;

/// Outcome of verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    /// All repetitions verified.
    Valid,
    /// Well-formed but semantically wrong.
    Invalid,
}

/// Verifies [`NonInteractiveProof`]s against circuits and statements.
///
/// The verifier is generic over a default [`CryptoBackend`] but, at
/// verification time, it reads the backend id bound into the proof and
/// re-derives the Fiat–Shamir challenges (and checks view commitments)
/// with *that* backend. A proof produced under SHA-256 can therefore
/// never verify under SHAKE256 and vice-versa — the mismatch is caught
/// as a challenge mismatch or an unsupported-backend error.
pub struct Verifier<B: CryptoBackend = Sha256Backend> {
    _marker: PhantomData<B>,
}

impl<B: CryptoBackend> Default for Verifier<B> {
    fn default() -> Self {
        Self {
            _marker: PhantomData,
        }
    }
}

impl<B: CryptoBackend> Verifier<B> {
    /// Creates a verifier.
    pub fn new() -> Self {
        Self::default()
    }

    /// Verifies a proof end-to-end using the verifier's pinned backend `B`.
    ///
    /// The proof is cryptographically bound to a single backend via its
    /// [`crypto_core::BackendId`]. A proof whose `backend_id` does not equal
    /// `B::ID` is unconditionally rejected with [`ProofError::UnsupportedBackend`]
    /// — this is what prevents a proof produced under one backend from being
    /// accepted under another (and blocks relabeling attacks).
    ///
    /// # Errors
    ///
    /// - [`ProofError::UnsupportedBackend`] when the proof's backend id does
    ///   not match this verifier's backend `B`.
    /// - [`ProofError::InvalidVersion`] for unknown version/protocol ids.
    /// - [`ProofError::CircuitIdMismatch`] / `InvalidCircuit` when the
    ///   circuit does not match the statement.
    /// - [`ProofError::ChallengeMismatch`] when a stored challenge
    ///   differs from the recomputed Fiat–Shamir challenge.
    /// - Propagated mpcith errors for malformed repetitions.
    /// - [`ProofError::VerificationFailed`] when a repetition fails
    ///   mpcith verification outright.
    pub fn verify(
        &self,
        circuit: &Circuit<FieldElement>,
        statement: &Statement,
        proof: &NonInteractiveProof,
    ) -> Result<VerificationResult, ProofError> {
        if proof.backend_id() != B::ID {
            return Err(ProofError::UnsupportedBackend);
        }
        self.verify_with::<B>(circuit, statement, proof)
    }

    fn verify_with<BB: CryptoBackend>(
        &self,
        circuit: &Circuit<FieldElement>,
        statement: &Statement,
        proof: &NonInteractiveProof,
    ) -> Result<VerificationResult, ProofError> {
        // 0. Structural validation.
        if proof.version() != crate::PROTOCOL_VERSION || proof.protocol_id() != crate::PROTOCOL_ID {
            return Err(ProofError::InvalidVersion);
        }
        if proof.repetitions().is_empty() {
            return Err(ProofError::VerificationFailed);
        }
        statement.validate(circuit)?;
        if proof.statement() != statement {
            return Err(ProofError::InvalidStatement);
        }

        // 1. Joint challenge recomputation from public inputs only,
        // using the proof's backend. Every repetition's stored challenge
        // must equal the challenge derived from the statement and the
        // FULL commitment transcript.
        let generator = FiatShamirChallengeGenerator::<BB>::default();
        let sessions: Vec<crate::fiat_shamir::FsSession<'_>> = proof
            .repetitions()
            .iter()
            .enumerate()
            .map(|(index, rep)| {
                crate::fiat_shamir::FsSession::new(
                    mpcith::RepetitionId::new(index as u32),
                    rep.commitments(),
                )
            })
            .collect();
        let derived = generator.derive_all(statement, &sessions)?;
        for (rep, challenge) in proof.repetitions().iter().zip(&derived) {
            if rep.challenge().hidden_party != challenge.hidden_party {
                return Err(ProofError::ChallengeMismatch);
            }
        }

        // 2. Per-repetition: hand the transcript to the independent
        // mpcith verifier (which never touches prover code) using the
        // proof's backend for view-commitment checks.
        let inner_statement = statement.to_mpcith();
        let mut inner_proofs = Vec::with_capacity(proof.repetitions().len());
        for (index, rep) in proof.repetitions().iter().enumerate() {
            inner_proofs.push(to_inner_repetition(rep, index as u32));
        }
        let inner = mpcith::MpcithProof {
            repetitions: inner_proofs,
        };

        let inner_result = MpcithVerifier::<BB>::new_backend()
            .verify(&inner_statement, &inner, circuit)
            .map_err(|_| ProofError::VerificationFailed)?;
        match inner_result {
            InnerResult::Valid => Ok(VerificationResult::Valid),
            InnerResult::Invalid => Err(ProofError::OutputMismatch),
        }
    }
}

/// Converts a proof-layer repetition into the mpcith-layer shape.
fn to_inner_repetition(rep: &crate::proof::ProofRepetition, index: u32) -> mpcith::Repetition {
    let opened_views = rep
        .opened_views()
        .iter()
        .zip(rep.opening_randomness())
        .map(|(view, randomness)| mpcith::OpenedView {
            view: view.clone(),
            randomness: randomness.clone(),
        })
        .collect();

    mpcith::Repetition {
        id: mpcith::RepetitionId::new(index),
        commitments: rep.commitments().to_vec(),
        challenge: *rep.challenge(),
        opened_views,
        hidden_output_shares: rep.hidden_output_shares().to_vec(),
        hidden_broadcasts: rep.hidden_broadcasts().to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProtocolConfig;
    use crate::prover::Prover;
    use circuit::CircuitBuilder;
    use mpc::PublicValue;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn fixture() -> (Circuit<FieldElement>, Statement, Vec<FieldElement>) {
        let mut b = CircuitBuilder::<FieldElement>::new();
        let x = b.secret_input();
        let c = b.constant(FieldElement::from(2u64));
        let t = b.add(x, c).expect("valid");
        let p = b.public_input();
        let m = b.mul(t, p).expect("valid");
        let s = b.add(m, x).expect("valid");
        b.output(s).expect("valid");
        let circuit = b.build().expect("valid");

        let statement = Statement {
            circuit_id: circuit.compute_id(),
            public_inputs: vec![PublicValue::new(FieldElement::from(5u64))],
            expected_outputs: vec![PublicValue::new(FieldElement::from(52u64))],
        };
        (circuit, statement, vec![FieldElement::from(7u64)])
    }

    #[test]
    fn honest_proof_verifies() {
        let (circuit, statement, witness) = fixture();
        let mut prover = Prover::new(
            &circuit,
            &statement,
            witness,
            ChaCha20Rng::seed_from_u64(13),
            ProtocolConfig::<crypto_core::Sha256Backend>::default(),
        )
        .expect("valid");
        let proof = prover.prove(4).expect("valid");
        assert_eq!(
            Verifier::<crypto_core::Sha256Backend>::new()
                .verify(&circuit, &statement, &proof)
                .expect("no error"),
            VerificationResult::Valid
        );
        assert!(proof.proof_id().is_ok());
    }

    #[test]
    fn tampered_challenge_is_rejected_as_mismatch() {
        use mpcith::PartyId;
        let (circuit, statement, witness) = fixture();
        let mut prover = Prover::new(
            &circuit,
            &statement,
            witness,
            ChaCha20Rng::seed_from_u64(12),
            ProtocolConfig::<crypto_core::Sha256Backend>::default(),
        )
        .unwrap();
        let proof = prover.prove(1).expect("valid");

        // Flip the stored challenge of repetition 0.
        let flipped =
            PartyId::new((proof.repetitions()[0].challenge().hidden_party.get() + 1) % 3).unwrap();
        let rep = proof.repetitions()[0].clone();
        let fixed = crate::proof::ProofRepetition::new(
            rep.commitments().to_vec(),
            mpcith::Challenge {
                hidden_party: flipped,
            },
            rep.opened_views().to_vec(),
            rep.opening_randomness().to_vec(),
            rep.hidden_broadcasts().to_vec(),
            rep.hidden_output_shares().to_vec(),
        );
        let rebuilt = NonInteractiveProof::new(
            proof.version(),
            proof.protocol_id(),
            proof.backend_id(),
            statement.clone(),
            vec![fixed],
        );

        assert_eq!(
            Verifier::<crypto_core::Sha256Backend>::new().verify(&circuit, &statement, &rebuilt),
            Err(ProofError::ChallengeMismatch)
        );
    }

    #[test]
    fn wrong_statement_rejects_before_verification() {
        use ark_ff::Zero;
        let (circuit, statement, witness) = fixture();
        let mut prover = Prover::new(
            &circuit,
            &statement,
            witness,
            ChaCha20Rng::seed_from_u64(13),
            ProtocolConfig::<crypto_core::Sha256Backend>::default(),
        )
        .unwrap();
        let proof = prover.prove(2).expect("valid");

        let mut other = statement.clone();
        other.expected_outputs[0] = PublicValue::new(FieldElement::zero());
        assert_eq!(
            Verifier::<crypto_core::Sha256Backend>::new().verify(&circuit, &other, &proof),
            Err(ProofError::InvalidStatement)
        );
    }
}
