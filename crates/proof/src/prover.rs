//! The non-interactive prover.
//!
//! Wraps the interactive [`mpcith::MpcithProver`] with a *joint*
//! Fiat–Shamir transform: every repetition is simulated and committed
//! first; then all challenges are derived from the statement and the
//! full transcript of commitments; only afterwards are views opened.
//! The prover therefore uses exactly the same challenge derivation as
//! the verifier — by construction, because both call the same
//! generator.

use rand_core::CryptoRngCore;

use circuit::Circuit;
use crypto_core::backend::{BackendId, CryptoBackend, Sha256Backend};
use mpcith::FieldElement;

use crate::config::ProtocolConfig;
use crate::error::ProofError;
use crate::fiat_shamir::{ChallengeGenerator, FiatShamirChallengeGenerator};
use crate::proof::{NonInteractiveProof, ProofRepetition};
use crate::statement::Statement;

/// Produces [`NonInteractiveProof`]s for a fixed
/// (circuit, statement, witness) triple, using the [`CryptoBackend`]
/// selected by `config`.
pub struct Prover<'a, R: CryptoRngCore, B: CryptoBackend = Sha256Backend> {
    circuit: &'a Circuit<FieldElement>,
    statement: Statement,
    witness: Vec<FieldElement>,
    rng: R,
    generator: FiatShamirChallengeGenerator<B>,
    _marker: std::marker::PhantomData<(&'a (), B, R)>,
}

impl<'a, R: CryptoRngCore, B: CryptoBackend> Prover<'a, R, B> {
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
        config: ProtocolConfig<B>,
    ) -> Result<Self, ProofError> {
        statement.validate(circuit)?;
        if witness.len() != circuit.num_secret_inputs() {
            return Err(ProofError::InvalidWitness);
        }
        let _ = config;
        Ok(Self {
            circuit,
            statement: statement.clone(),
            witness,
            rng,
            generator: FiatShamirChallengeGenerator::<B>::default(),
            _marker: std::marker::PhantomData,
        })
    }

    /// Generates a proof with `repetition_count` independent MPCitH
    /// repetitions. All randomness — sharings, triples, commitment
    /// seeds — is drawn freshly per repetition from this prover's RNG.
    ///
    /// # Errors
    ///
    /// - [`ProofError::InvalidStatement`] if `repetition_count` is zero
    ///   (the joint derivation rejects empty transcripts).
    /// - [`ProofError::MalformedEncoding`] if an mpcith invariant fails.
    pub fn prove(&mut self, repetition_count: u32) -> Result<NonInteractiveProof, ProofError> {
        if repetition_count == 0 {
            return Err(ProofError::InvalidStatement);
        }
        let statement_for_fs = self.statement.clone();
        let mpcith_statement = self.statement.to_mpcith();

        let mut inner = mpcith::MpcithProver::<_, B>::new_backend(
            self.circuit,
            &mpcith_statement,
            self.witness.clone(),
            // The inner source is never consulted; prove_joint_fs drives
            // challenges through the joint Fiat–Shamir derivation.
            Box::new(mpcith::DeterministicChallengeSource::default()),
            &mut self.rng,
        )
        .map_err(proof_error)?;

        let backend_id: BackendId = B::ID;
        let interactive = inner
            .prove_joint_fs(repetition_count, |sessions| {
                let fs_sessions: Vec<crate::fiat_shamir::FsSession<'_>> = sessions
                    .iter()
                    .map(|(id, commitments)| crate::fiat_shamir::FsSession::new(*id, commitments))
                    .collect();
                self.generator
                    .derive_all(&statement_for_fs, &fs_sessions)
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
            crate::PROTOCOL_ID,
            backend_id,
            self.statement.clone(),
            repetitions,
        ))
    }
}

fn proof_error(err: mpcith::MpcithError) -> ProofError {
    let _ = err;
    ProofError::VerificationFailed
}
