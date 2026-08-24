//! Proof artifact types.
//!
//! The full prover algorithm lives in [`crate::prover::MpcithProver`];
//! this module defines only the data shapes so encoding and
//! commitments can reference them.

use crate::commitment::ViewCommitment;
use crate::types::{Challenge, FieldElement, RepetitionId};
use crypto_core::SecretBytes;

/// One opened party's view together with the commitment randomness
/// used to decommit it.
#[derive(Clone, Debug)]
pub struct OpenedView {
    /// The opened party's full execution view.
    pub view: crate::view::PartyView,
    /// Fresh randomness bound in the view commitment.
    pub randomness: SecretBytes,
}

/// One repetition: three pre-challenge commitments, the verifier's
/// challenge, and the post-challenge response (two opened views plus
/// the hidden party's output shares).
#[derive(Clone, Debug)]
pub struct Repetition {
    /// Repetition identifier (equals its index in the proof).
    pub id: RepetitionId,
    /// Commitments to all three party views, in party order, made
    /// before the challenge was drawn.
    pub commitments: Vec<ViewCommitment>,
    /// The challenge: which party stays hidden.
    pub challenge: Challenge,
    /// The two opened views (the parties other than the hidden one),
    /// in ascending party order.
    pub opened_views: Vec<OpenedView>,
    /// The hidden party's output share per declared circuit output,
    /// completing the sum when combined with the opened parties'
    /// verified output shares. Cheating here is caught whenever the
    /// hiding party is not the corrupted one (probability 2/3 per
    /// repetition).
    pub hidden_output_shares: Vec<FieldElement>,
}

/// A complete MPCitH proof: independent repetitions over fresh
/// sharing, triples, and commitment randomness.
#[derive(Clone, Debug)]
pub struct MpcithProof {
    /// One entry per repetition.
    pub repetitions: Vec<Repetition>,
}
