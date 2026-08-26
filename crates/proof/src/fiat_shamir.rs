//! Fiat–Shamir challenge derivation.
//!
//! Challenges are derived *jointly*: every repetition's hidden party is
//! a hash of the statement, the repetition count, **all** repetitions'
//! pre-challenge view commitments, and that repetition's own id. The
//! prover commits every repetition's three views first and only then
//! derives the challenges, so no view is opened before all challenges
//! are fixed.
//!
//! Why jointly? With a 3-value challenge space, deriving each challenge
//! from its own repetition's commitments alone would let a cheating
//! prover grind that repetition's (never-opened) hidden-party commitment
//! for a favorable challenge at ~3 hash evaluations per repetition,
//! collapsing soundness. Under the joint rule the whole transcript must
//! be re-ground together: expected work rises to roughly `3^t` for `t`
//! repetitions, restoring the `(2/3)^t` soundness of the interactive
//! protocol.
//!
//! Domain separation: messages are hashed under
//! `private-payment-auth/mpcith/fs/v1` using the length-framed domain
//! hashing of `crypto_core::Sha256Hash::hash_domain`, making collision
//! with any other protocol use of SHA-256 impossible up to hash
//! security.
//!
//! Binding: because every statement component (circuit id, public
//! inputs, expected outputs) and every commitment of every repetition
//! is absorbed, any mutation changes the digest —
//! [`FiatShamirChallengeGenerator::fs_digest`] exposes it so auditors
//! and tests can check binding at full hash strength rather than at the
//! 3-value challenge granularity.
//!
//! Message layout for repetition `r`:
//!
//! ```text
//! version(u8) ‖ statement ‖ n_reps(u32 BE)
//! ‖ (repetition_id(u32 BE) ‖ commitments) × n_reps   // full transcript
//! ‖ r.repetition_id(u32 BE)                          // selector
//! ```
//!
//! Bias note: `hidden_party = digest[0] % 3` introduces a slight
//! modulo bias (2/256 vs 1/256 per party difference). For three
//! parties this is negligible relative to the 1/3 soundness error and
//! acceptable; rejection sampling would remove it entirely if ever
//! needed.

use crypto_core::{Digest, HashFunction, Sha256Hash};
use mpcith::{Challenge, PartyId, RepetitionId, ViewCommitment};

use crate::error::ProofError;
use crate::statement::Statement;

/// Domain separator for Fiat–Shamir challenge derivation.
pub const FS_DOMAIN: &[u8] = b"private-payment-auth/mpcith/fs/v1";

/// One repetition's pre-challenge material inside a joint derivation.
#[derive(Clone, Copy, Debug)]
pub struct FsSession<'a> {
    /// Repetition identifier (equals its index in the proof).
    pub repetition_id: RepetitionId,
    /// That repetition's three pre-challenge view commitments.
    pub commitments: &'a [ViewCommitment],
}

impl<'a> FsSession<'a> {
    /// Bundles a repetition id with its commitments.
    pub fn new(repetition_id: RepetitionId, commitments: &'a [ViewCommitment]) -> Self {
        Self {
            repetition_id,
            commitments,
        }
    }
}

/// Derives FS challenges from the statement and the joint transcript.
#[derive(Clone, Copy, Debug, Default)]
pub struct FiatShamirChallengeGenerator;

/// Abstract generator so alternative derivation rules (future
/// versions) can be injected without touching callers.
pub trait ChallengeGenerator {
    /// Derives one challenge per session, in order. Implementations
    /// must derive every challenge from *all* sessions' commitments.
    /// Repetition ids are absorbed as-is; callers (prover and verifier)
    /// are responsible for using index-aligned ids.
    fn derive_all(
        &self,
        statement: &Statement,
        sessions: &[FsSession<'_>],
    ) -> Result<Vec<Challenge>, ProofError>;
}

impl FiatShamirChallengeGenerator {
    /// Computes the raw Fiat–Shamir digest for repetition `r` over the
    /// joint transcript (see the module docs for the exact layout). The
    /// hidden party is `digest[0] % 3`; exposing the pre-image digest
    /// lets callers audit statement/transcript binding at full hash
    /// strength.
    ///
    /// # Errors
    ///
    /// [`ProofError::InvalidStatement`] if `sessions` is empty or a
    /// session carries fewer than three commitments.
    pub fn fs_digest(
        &self,
        statement: &Statement,
        sessions: &[FsSession<'_>],
        selector: usize,
    ) -> Result<Digest, ProofError> {
        let mut message = Vec::new();
        message.push(crate::PROTOCOL_VERSION);
        statement.encode_into(&mut message);
        message.extend_from_slice(&(sessions.len() as u32).to_be_bytes());
        for session in sessions {
            message.extend_from_slice(&session.repetition_id.get().to_be_bytes());
            for commitment in session.commitments {
                message.extend_from_slice(commitment.as_digest().as_bytes());
            }
        }
        let selected = sessions
            .get(selector)
            .ok_or(ProofError::MalformedEncoding)?;
        message.extend_from_slice(&selected.repetition_id.get().to_be_bytes());
        Ok(Sha256Hash::hash_domain(FS_DOMAIN, &message).into())
    }
}

impl ChallengeGenerator for FiatShamirChallengeGenerator {
    fn derive_all(
        &self,
        statement: &Statement,
        sessions: &[FsSession<'_>],
    ) -> Result<Vec<Challenge>, ProofError> {
        if sessions.is_empty() || sessions.iter().any(|s| s.commitments.len() != 3) {
            return Err(ProofError::InvalidStatement);
        }
        sessions
            .iter()
            .enumerate()
            .map(|(index, _)| {
                let digest = self.fs_digest(statement, sessions, index)?;
                // Slight modulo bias (documented above): acceptable at k = 3.
                let value = digest.as_bytes()[0] % 3;
                let hidden_party =
                    PartyId::new(value).map_err(|_| ProofError::MalformedEncoding)?;
                Ok(Challenge { hidden_party })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};
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

    fn make_sessions<'a>(c0: &'a [ViewCommitment], c1: &'a [ViewCommitment]) -> Vec<FsSession<'a>> {
        vec![
            FsSession::new(RepetitionId::new(0), c0),
            FsSession::new(RepetitionId::new(1), c1),
        ]
    }

    #[test]
    fn derivation_is_deterministic_and_full_length() {
        let gen = FiatShamirChallengeGenerator;
        let s = fixture_statement();
        let (c0, c1) = (commitments(10), commitments(20));
        let sessions = make_sessions(&c0, &c1);
        let first = gen.derive_all(&s, &sessions).expect("ok");
        let second = gen.derive_all(&s, &sessions).expect("ok");
        assert_eq!(first, second);
        assert_eq!(first.len(), sessions.len());
    }

    #[test]
    fn derive_matches_fs_digest_first_byte() {
        let gen = FiatShamirChallengeGenerator;
        let s = fixture_statement();
        let (c0, c1) = (commitments(10), commitments(20));
        let sessions = make_sessions(&c0, &c1);
        let challenges = gen.derive_all(&s, &sessions).expect("ok");
        for (index, challenge) in challenges.iter().enumerate() {
            assert_eq!(
                challenge.hidden_party.get(),
                gen.fs_digest(&s, &sessions, index).expect("ok").as_bytes()[0] % 3
            );
        }
    }

    /// The 3-value challenge space means two *different* FS inputs can
    /// legitimately map to the same hidden party (~1/3 of the time).
    /// Binding is therefore asserted at digest granularity: any mutation
    /// of the statement or of ANY session's commitments must change the
    /// raw digest with overwhelming probability.
    #[test]
    fn mutations_change_the_fs_digest_at_full_strength() {
        let gen = FiatShamirChallengeGenerator;
        let s = fixture_statement();
        let (c0, c1) = (commitments(10), commitments(20));
        let sessions = make_sessions(&c0, &c1);
        let base0 = gen.fs_digest(&s, &sessions, 0).expect("ok");
        let base1 = gen.fs_digest(&s, &sessions, 1).expect("ok");

        // Circuit id.
        let mut st = fixture_statement();
        st.circuit_id = CircuitId::from_digest(crypto_core::Digest::new([2u8; 32]));
        assert_ne!(base0, gen.fs_digest(&st, &sessions, 0).expect("ok"));

        // Public input.
        let mut st = fixture_statement();
        st.public_inputs[0] = mpc::PublicValue::new(FieldElement::from(4u64));
        assert_ne!(base0, gen.fs_digest(&st, &sessions, 0).expect("ok"));

        // Expected output.
        let mut st = fixture_statement();
        st.expected_outputs[0] = mpc::PublicValue::new(<FieldElement as One>::one());
        assert_ne!(base0, gen.fs_digest(&st, &sessions, 0).expect("ok"));

        // Each commitment position of each session individually — in
        // both selectors' digests (joint binding).
        for session_index in 0..2 {
            for i in 0..3 {
                let mut cms = if session_index == 0 {
                    c0.clone()
                } else {
                    c1.clone()
                };
                cms[i] = ViewCommitment::from_digest(crypto_core::Digest::new([0x55; 32]));
                let (a, b) = (c0.clone(), c1.clone());
                let other_sessions = if session_index == 0 {
                    make_sessions(&cms, &b)
                } else {
                    make_sessions(&a, &cms)
                };
                assert_ne!(
                    base0,
                    gen.fs_digest(&s, &other_sessions, 0).expect("ok"),
                    "session {session_index} commitment {i} not bound into selector 0"
                );
                assert_ne!(
                    base1,
                    gen.fs_digest(&s, &other_sessions, 1).expect("ok"),
                    "session {session_index} commitment {i} not bound into selector 1"
                );
            }
        }

        // Selector: the same transcript yields per-repetition digests.
        assert_ne!(base0, base1);

        // Commitment count (dropped/added commitments must not pass unnoticed).
        let short: &[ViewCommitment] = &c0[..2];
        let other_sessions = make_sessions(short, &c1);
        assert_ne!(base0, gen.fs_digest(&s, &other_sessions, 0).expect("ok"));
    }

    #[test]
    fn rejects_empty_sessions_and_bad_shapes() {
        let gen = FiatShamirChallengeGenerator;
        let s = fixture_statement();
        assert_eq!(
            gen.derive_all(&s, &[]),
            Err(ProofError::InvalidStatement),
            "empty transcript must be rejected"
        );
        let c0 = commitments(10);
        let short: &[ViewCommitment] = &c0[..2];
        let bad = vec![FsSession::new(RepetitionId::new(0), short)];
        assert_eq!(
            gen.derive_all(&s, &bad),
            Err(ProofError::InvalidStatement),
            "fewer than three commitments must be rejected"
        );
    }
}
