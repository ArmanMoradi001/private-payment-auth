//! The non-interactive proof artifact.
//!
//! A [`NonInteractiveProof`] is immutable once constructed: all fields
//! are private and exposed only through getters, so no downstream code
//! can mutate a proof in place. Every repetition stores the challenge
//! for convenience/auditability, but verifiers must recompute it.

use crypto_core::backend::BackendId;
use crypto_core::{Digest, HashFunction, SecretBytes, Sha256Hash};
use mpcith::{Challenge, FieldElement, PartyView, ViewCommitment};

use crate::statement::Statement;

/// Domain for proof identity hashing.
pub const PROOF_ID_DOMAIN: &[u8] = b"private-payment-auth/proof/id/v2";

/// One Fiat–Shamir repetition inside a [`NonInteractiveProof`].
#[derive(Clone, Debug)]
pub struct ProofRepetition {
    commitments: Vec<ViewCommitment>,
    challenge: Challenge,
    opened_views: Vec<PartyView>,
    opening_randomness: Vec<SecretBytes>,
    hidden_broadcasts: Vec<FieldElement>,
    hidden_output_shares: Vec<FieldElement>,
}

impl ProofRepetition {
    /// Builds a repetition. Construction is public; mutation is not:
    /// all fields are private and getter-only afterwards.
    pub fn new(
        commitments: Vec<ViewCommitment>,
        challenge: Challenge,
        opened_views: Vec<PartyView>,
        opening_randomness: Vec<SecretBytes>,
        hidden_broadcasts: Vec<FieldElement>,
        hidden_output_shares: Vec<FieldElement>,
    ) -> Self {
        Self {
            commitments,
            challenge,
            opened_views,
            opening_randomness,
            hidden_broadcasts,
            hidden_output_shares,
        }
    }

    /// The three pre-challenge view commitments, in party order.
    pub fn commitments(&self) -> &[ViewCommitment] {
        &self.commitments
    }

    /// The stored challenge (verifiers recompute it independently).
    pub fn challenge(&self) -> &Challenge {
        &self.challenge
    }

    /// The two opened party views, ascending party order.
    pub fn opened_views(&self) -> &[PartyView] {
        &self.opened_views
    }

    /// The two commitment randomness values matching `opened_views`.
    pub fn opening_randomness(&self) -> &[SecretBytes] {
        &self.opening_randomness
    }

    /// The hidden party's public broadcast contributions.
    pub fn hidden_broadcasts(&self) -> &[FieldElement] {
        &self.hidden_broadcasts
    }

    /// The hidden party's output shares completing the output sum
    /// against the statement's expected outputs.
    pub fn hidden_output_shares(&self) -> &[FieldElement] {
        &self.hidden_output_shares
    }
}

/// Complete non-interactive proof of correct circuit evaluation.
#[derive(Clone, Debug)]
pub struct NonInteractiveProof {
    version: u8,
    protocol_id: u8,
    backend_id: BackendId,
    statement: Statement,
    repetitions: Vec<ProofRepetition>,
}

impl NonInteractiveProof {
    /// Assembles a proof. Construction is public; mutation is not:
    /// all fields are private and getter-only afterwards.
    pub fn new(
        version: u8,
        protocol_id: u8,
        backend_id: BackendId,
        statement: Statement,
        repetitions: Vec<ProofRepetition>,
    ) -> Self {
        Self {
            version,
            protocol_id,
            backend_id,
            statement,
            repetitions,
        }
    }

    /// Encoding version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Protocol identifier (reserved; currently always 1).
    pub fn protocol_id(&self) -> u8 {
        self.protocol_id
    }

    /// The cryptographic backend used to produce this proof.
    pub fn backend_id(&self) -> BackendId {
        self.backend_id
    }

    /// The statement this proof attests.
    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    /// The repetitions, in order.
    pub fn repetitions(&self) -> &[ProofRepetition] {
        &self.repetitions
    }

    /// Semantic identity of the whole proof:
    /// `SHA-256("private-payment-auth/proof/id/v1" ‖ canonical_encoding)`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::ProofError::MalformedEncoding`] if the proof
    /// cannot be canonically serialized (should not happen for proofs
    /// built by the prover or decoder).
    pub fn proof_id(&self) -> Result<ProofId, crate::ProofError> {
        let bytes = crate::encoding::serialize_proof(self);
        Ok(ProofId(
            Sha256Hash::hash_domain(PROOF_ID_DOMAIN, &bytes).into(),
        ))
    }
}

/// Hash-based identifier of a complete proof.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct ProofId(Digest);

impl ProofId {
    /// Borrows the underlying digest.
    pub fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl core::fmt::Debug for ProofId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProofId({})", self.0)
    }
}

impl core::fmt::Display for ProofId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}
