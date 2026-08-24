//! The non-interactive prover.
//!
//! Wraps the interactive [`mpcith::MpcithProver`] with a Fiat–Shamir
//! challenge hook: for every repetition, mpcith
//! commits to all three views and then calls back into
//! [`FiatShamirChallengeGenerator`] with those commitments. The prover
//! therefore uses exactly the same challenge derivation as the
//! verifier — by construction, because both call the same generator.

use rand_core::CryptoRngCore;

use circuit::Circuit;
use mpcith::{FieldElement, MpcithProver as InnerProver};

use crate::error::ProofError;
use crate::fiat_shamir::{ChallengeGenerator, FiatShamirChallengeGenerator};
use crate::proof::{NonInteractiveProof, ProofRepetition};
use crate::statement::Statement;

/// Produces [`NonInteractiveProof`]s for a fixed
/// (circuit, statement, witness) triple.
pub struct Prover<'a, R: CryptoRngCore> {
    circuit: &'a Circuit<FieldElement>,
    statement: Statement,
    witness: Vec<FieldElement>,
    rng: R,
    generator: FiatShamirChallengeGenerator,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, R: CryptoRngCore> Prover<'a, R> {
    /// Creates a prover after validating the statement against the
    /// circuit and the witness against its input count.
    ///
    /// # Errors
    ///
    /// - [`ProofError::InvalidCircuit`] / [`ProofError::CircuitIdMismatch`].
    /// - [`ProofError::InvalidStatement`] shape problems.
    /// - [`ProofError::InvalidWitness`] on witness-count mismatch.
    pub fn new(
        circuit: &'a Circuit<FieldElement>,
        statement: &Statement,
        witness: Vec<FieldElement>,
        rng: R,
    ) -> Result<Self, ProofError> {
        statement.validate(circuit)?;
        if witness.len() != circuit.num_secret_inputs() {
            return Err(ProofError::InvalidWitness);
        }
        Ok(Self {
            circuit,
            statement: statement.clone(),
            witness,
            rng,
            generator: FiatShamirChallengeGenerator,
            _marker: std::marker::PhantomData,
        })
    }

    /// Generates a proof with `repetition_count` independent MPCitH
    /// repetitions. All randomness — sharings, triples, commitment
    /// seeds — is drawn freshly per repetition from this prover's RNG.
    ///
    /// # Errors
    ///
    /// - [`ProofError::MalformedEncoding`] if the FS derivation or an
    ///   mpcith invariant fails.
    pub fn prove(&mut self, repetition_count: u32) -> Result<NonInteractiveProof, ProofError> {
        let generator = self.generator;
        let statement_for_fs = self.statement.clone();
        let mpcith_statement = self.statement.to_mpcith();

        let mut inner = InnerProver::new(
            self.circuit,
            &mpcith_statement,
            self.witness.clone(),
            // The inner source is never consulted; prove_with overrides it.
            Box::new(mpcith::DeterministicChallengeSource::default()),
            &mut self.rng,
        )
        .map_err(proof_error)?;

        let interactive = inner
            .prove_with(repetition_count, |repetition_id, commitments| {
                generator
                    .derive(&statement_for_fs, commitments, repetition_id)
                    .map_err(|_| mpcith::MpcithError::InvalidProtocolState)
            })
            .map_err(proof_error)?;

        let repetitions = interactive
            .repetitions
            .into_iter()
            .map(|rep| {
                // Keep views and their randomness aligned by party id.
                let mut pairs: Vec<_> = rep
                    .opened_views
                    .into_iter()
                    .map(|ov| (ov.view.party_id.get(), ov.view, ov.randomness))
                    .collect();
                pairs.sort_by_key(|(pid, _, _)| *pid);
                let (opened_views, randomness): (Vec<_>, Vec<_>) =
                    pairs.into_iter().map(|(_, view, r)| (view, r)).unzip();
                ProofRepetition::new(
                    rep.commitments,
                    rep.challenge,
                    opened_views,
                    randomness,
                    rep.hidden_broadcasts,
                    rep.hidden_output_shares,
                )
            })
            .collect();

        Ok(NonInteractiveProof::new(
            crate::PROTOCOL_VERSION,
            crate::PROTOCOL_VERSION,
            self.statement.clone(),
            repetitions,
        ))
    }
}

fn proof_error(err: mpcith::MpcithError) -> ProofError {
    let _ = err;
    ProofError::VerificationFailed
}
