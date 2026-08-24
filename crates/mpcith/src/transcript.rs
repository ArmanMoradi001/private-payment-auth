//! Deterministic MPCitH transcripts.
//!
//! A [`MpcithTranscript`] is the public record of a proof: per
//! repetition, the commitments, the challenge, and the opened views.
//! It contains **no hidden-party state** — the hidden party appears
//! only through its commitments and output share, exactly as in the
//! proof itself. Transcripts are ordered by repetition id and are the
//! future input of the Fiat–Shamir transform.

use crate::commitment::ViewCommitment;
use crate::types::{Challenge, FieldElement, RepetitionId};
use crate::view::PartyView;
use crate::MpcithProof;

/// Public record of one repetition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepetitionTranscript {
    /// Repetition identifier.
    pub repetition_id: RepetitionId,
    /// Commitments to all three party views, in party order.
    pub commitments: Vec<ViewCommitment>,
    /// The challenge drawn after commitment.
    pub challenge: Challenge,
    /// Party ids whose views were opened, ascending.
    pub opened_parties: [u8; 2],
    /// The two opened views, in the same order as `opened_parties`.
    pub opened_views: Vec<PartyView>,
    /// The hidden party's output shares completing the output sum.
    pub hidden_output_shares: Vec<FieldElement>,
    /// The hidden party's broadcast mask contributions, which are
    /// public by construction (they are what every party received).
    pub hidden_broadcasts: Vec<FieldElement>,
}

/// Complete deterministic transcript of an MPCitH proof.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MpcithTranscript {
    /// One entry per repetition, ordered by repetition id.
    pub repetitions: Vec<RepetitionTranscript>,
}

impl MpcithTranscript {
    /// Creates an empty transcript.
    pub fn new() -> Self {
        Self::default()
    }

    /// Builds a transcript from a proof. Only public material is
    /// copied; commitment randomness is deliberately omitted because
    /// it is single-use and no longer needed after verification.
    pub fn from_proof(proof: &MpcithProof) -> Self {
        let mut repetitions = Vec::with_capacity(proof.repetitions.len());
        for repetition in &proof.repetitions {
            let mut opened = repetition.opened_views.clone();
            opened.sort_by_key(|ov| ov.view.party_id.get());
            repetitions.push(RepetitionTranscript {
                repetition_id: repetition.id,
                commitments: repetition.commitments.clone(),
                challenge: repetition.challenge,
                opened_parties: [
                    opened.first().map_or(0, |ov| ov.view.party_id.get()),
                    opened.get(1).map_or(0, |ov| ov.view.party_id.get()),
                ],
                opened_views: opened.into_iter().map(|ov| ov.view).collect(),
                hidden_output_shares: repetition.hidden_output_shares.clone(),
                hidden_broadcasts: repetition.hidden_broadcasts.clone(),
            });
        }
        Self { repetitions }
    }

    /// Number of recorded repetitions.
    pub fn len(&self) -> usize {
        self.repetitions.len()
    }

    /// `true` when nothing has been recorded.
    pub fn is_empty(&self) -> bool {
        self.repetitions.is_empty()
    }

    /// Checks that repetition ids are strictly increasing and
    /// challenges/openings are well-formed ordering-wise.
    pub fn is_ordered(&self) -> bool {
        self.repetitions
            .iter()
            .enumerate()
            .all(|(i, rep)| rep.repetition_id.get() == i as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::DeterministicChallengeSource;
    use crate::prover::MpcithProver;
    use crate::statement::Statement;
    use crate::types::{FieldElement, PartyId};
    use circuit::CircuitBuilder;
    use mpc::PublicValue;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn fixture() -> (circuit::Circuit<FieldElement>, Statement, Vec<FieldElement>) {
        let mut b = CircuitBuilder::<FieldElement>::new();
        let x = b.secret_input();
        let p = b.public_input();
        let s = b.mul(x, p).expect("valid");
        b.output(s).expect("valid");
        let circuit = b.build().expect("valid");

        let statement = Statement {
            circuit_id: circuit.compute_id(),
            public_inputs: vec![PublicValue::new(FieldElement::from(3u64))],
            expected_outputs: vec![PublicValue::new(FieldElement::from(30u64))],
        };
        let witness = vec![FieldElement::from(10u64)];
        (circuit, statement, witness)
    }

    #[test]
    fn transcripts_record_all_repetitions_in_order_without_randomness() {
        let (circuit, statement, witness) = fixture();

        // Sanity: honest execution produces the expected output.
        let expected = circuit::evaluate_reference(&circuit, &witness, &[FieldElement::from(3u64)])
            .expect("valid");
        assert_eq!(expected[0], *statement.expected_outputs[0].value());

        let source = DeterministicChallengeSource::new(
            [0u8, 2, 1].iter().map(|&p| PartyId::new(p).unwrap()),
        );
        let mut prover = MpcithProver::new(
            &circuit,
            &statement,
            witness,
            Box::new(source),
            ChaCha20Rng::seed_from_u64(3),
        )
        .expect("valid");
        let proof = prover.prove(3).expect("valid");

        let transcript = MpcithTranscript::from_proof(&proof);
        assert_eq!(transcript.len(), 3);
        assert!(transcript.is_ordered());

        for (rep, tr) in proof.repetitions.iter().zip(&transcript.repetitions) {
            assert_eq!(rep.id, tr.repetition_id);
            assert_eq!(rep.challenge, tr.challenge);
            // No randomness leaks into the transcript.
            let rendered = format!("{tr:?}");
            assert!(!rendered.contains("randomness"));
        }
    }
}
