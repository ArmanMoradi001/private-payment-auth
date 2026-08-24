//! The MPCitH verifier.
//!
//! This module is deliberately **independent of the prover**: it never
//! calls into [`crate::prover`] and re-implements the circuit
//! semantics from scratch. Given a statement, a circuit, and a proof,
//! it replays each repetition using only public information and the
//! opened views, checking commitments, per-party algebra, cross-party
//! mask agreement, and finally the output sum.
//!
//! Soundness intuition: any corrupted view is opened unless it belongs
//! to the challenged-hidden party, so one repetition catches cheating
//! with probability 2/3; R independent repetitions give forgery
//! probability (1/3)^R.

use ark_ff::Zero;

use circuit::Circuit;

use crate::commitment::verify_commitment;
use crate::error::MpcithError;
use crate::statement::Statement;
use crate::types::{FieldElement, PartyId, RepetitionId};
use crate::view::{LocalOperation, PartyView};
use crate::MpcithProof;

/// Outcome of verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    /// Every repetition verified.
    Valid,
    /// A proof was structurally fine but semantically wrong.
    Invalid,
}

/// Value of one circuit node during an opened party's replay.
#[derive(Clone, Copy)]
enum NodeVal {
    /// Plaintext value known to everyone.
    Public(FieldElement),
    /// This party's share of the node.
    Shared(FieldElement),
}

impl NodeVal {
    fn as_field(&self, _party: usize) -> FieldElement {
        match self {
            NodeVal::Public(v) | NodeVal::Shared(v) => *v,
        }
    }
}

/// Result of replaying one opened party's view.
struct Replay {
    /// Per-node recomputed values.
    values: Vec<NodeVal>,
}

/// Verifies MPCitH proofs against statements and circuits.
#[derive(Default)]
pub struct MpcithVerifier;

impl MpcithVerifier {
    /// Creates a verifier.
    pub fn new() -> Self {
        Self
    }

    /// Verifies every repetition of `proof` against `statement`.
    ///
    /// # Errors
    ///
    /// Structural problems (bad challenges, missing responses,
    /// commitment failures, inconsistent views) are reported as
    /// [`MpcithError`]; a well-formed but semantically wrong proof
    /// yields `Ok(VerificationResult::Invalid)`.
    pub fn verify(
        &self,
        statement: &Statement,
        proof: &MpcithProof,
        circuit: &Circuit<FieldElement>,
    ) -> Result<VerificationResult, MpcithError> {
        statement.validate(circuit)?;

        if proof.repetitions.is_empty() {
            return Err(MpcithError::InvalidProtocolState);
        }
        for (index, repetition) in proof.repetitions.iter().enumerate() {
            if repetition.id != RepetitionId::new(index as u32) {
                return Err(MpcithError::InconsistentView);
            }
            if !self.verify_repetition(statement, repetition, circuit)? {
                return Ok(VerificationResult::Invalid);
            }
        }
        Ok(VerificationResult::Valid)
    }

    /// Verifies one repetition; returns `false` on semantic failure.
    fn verify_repetition(
        &self,
        statement: &Statement,
        repetition: &crate::Repetition,
        circuit: &Circuit<FieldElement>,
    ) -> Result<bool, MpcithError> {
        // 1. Challenge validity: names one of parties 0..2.
        let hidden = PartyId::new(repetition.challenge.hidden_party.get())
            .map_err(|_| MpcithError::InvalidChallenge)?;
        let expected_opened = hidden.others();

        // All three commitments must exist.
        if repetition.commitments.len() != usize::from(crate::PARTY_COUNT) {
            return Err(MpcithError::MissingCommitment);
        }

        // 2. Exactly the two non-hidden views must be present, ordered.
        if repetition.opened_views.len() != 2
            || repetition.opened_views[0].view.party_id != expected_opened[0]
            || repetition.opened_views[1].view.party_id != expected_opened[1]
        {
            return Err(MpcithError::MissingResponse);
        }

        // 3. Commitments bind every opened view.
        for opened in &repetition.opened_views {
            let view = &opened.view;
            if view.repetition_id != repetition.id {
                return Err(MpcithError::InconsistentView);
            }
            let committed = repetition.commitments[view.party_id.get() as usize];
            if !verify_commitment(&committed, view, &opened.randomness)? {
                return Err(MpcithError::CommitmentMismatch);
            }
        }

        // 4. Independent replay of each opened party. First compute
        // the global broadcast masks: d and e are opened to everyone,
        // and the hidden party's contributions are part of the proof.
        let n_broadcasts = repetition.hidden_broadcasts.len();
        if !n_broadcasts.is_multiple_of(2) {
            return Err(MpcithError::InvalidOpening);
        }
        let mut globals = Vec::with_capacity(n_broadcasts);
        for k in (0..n_broadcasts).step_by(2) {
            let mut d = repetition.hidden_broadcasts[k];
            let mut e = repetition.hidden_broadcasts[k + 1];
            for opened in &repetition.opened_views {
                d += *opened
                    .view
                    .opened_values
                    .get(k)
                    .ok_or(MpcithError::InconsistentView)?;
                e += *opened
                    .view
                    .opened_values
                    .get(k + 1)
                    .ok_or(MpcithError::InconsistentView)?;
            }
            globals.push(d);
            globals.push(e);
        }

        let mut replays = Vec::with_capacity(2);
        for opened in &repetition.opened_views {
            replays.push(self.replay_party(statement, &opened.view, circuit, &globals)?);
        }

        // 5. Both opened parties' local contributions must have been
        // consistent with the global masks (checked inside replay);
        // nothing further to cross-compare here.
        self.check_outputs(statement, repetition, circuit, &replays)
    }

    /// Replays one opened party's computation from public data plus its
    /// claimed view, checking every recorded operation in order.
    ///
    /// `globals` holds the globally opened `(d, e)` pairs per
    /// multiplication, reconstructed from all parties' broadcasts.
    #[allow(clippy::too_many_lines)]
    fn replay_party(
        &self,
        statement: &Statement,
        view: &PartyView,
        circuit: &Circuit<FieldElement>,
        globals: &[FieldElement],
    ) -> Result<Replay, MpcithError> {
        if view.input_shares.len() != circuit.num_secret_inputs() {
            return Err(MpcithError::InconsistentView);
        }

        let mut values: Vec<NodeVal> = Vec::with_capacity(circuit.nodes().len());
        let mut next_secret = 0usize;
        let mut next_public = 0usize;
        let mut next_op = 0usize;
        let mut next_triple = 0usize;
        let mut next_opened = 0usize;
        let p = view.party_id.get() as usize;

        macro_rules! take_op {
            () => {{
                let op = view
                    .local_operations
                    .get(next_op)
                    .ok_or(MpcithError::InconsistentView)?;
                next_op += 1;
                op
            }};
        }
        macro_rules! expect_op {
            ($pattern:pat, $($check:expr),+) => {{
                match take_op!() {
                    $pattern => { $($check)+ }
                    _ => return Err(MpcithError::InvalidOperation),
                }
            }};
        }

        for (index, node) in circuit.nodes().iter().enumerate() {
            let out = circuit::NodeId::new(index as u32);
            let val = match node {
                circuit::Node::SecretInput => {
                    let share = *view
                        .input_shares
                        .get(next_secret)
                        .ok_or(MpcithError::InconsistentView)?;
                    next_secret += 1;
                    NodeVal::Shared(share)
                }
                circuit::Node::PublicInput => {
                    let v = *statement
                        .public_inputs
                        .get(next_public)
                        .ok_or(MpcithError::InvalidStatement)?
                        .value();
                    next_public += 1;
                    NodeVal::Public(v)
                }
                circuit::Node::Constant(c) => NodeVal::Public(*c.value()),
                circuit::Node::Add(a, b) => {
                    let va = values[a.as_usize()];
                    let vb = values[b.as_usize()];
                    match (va, vb) {
                        (NodeVal::Public(x), NodeVal::Public(y)) => NodeVal::Public(x + y),
                        (NodeVal::Shared(_), NodeVal::Shared(_)) => {
                            let expected = va.as_field(p) + vb.as_field(p);
                            expect_op!(
                                LocalOperation::Add { output, share },
                                if *output != out || *share != expected {
                                    return Err(MpcithError::InconsistentView);
                                }
                            );
                            NodeVal::Shared(expected)
                        }
                        // Mixed shared + public: only party 0 absorbs
                        // the public value and records an operation;
                        // other parties keep their share unchanged.
                        _ => {
                            if p == 0 {
                                let expected = va.as_field(0) + vb.as_field(0);
                                expect_op!(
                                    LocalOperation::Add { output, share },
                                    if *output != out || *share != expected {
                                        return Err(MpcithError::InconsistentView);
                                    }
                                );
                                NodeVal::Shared(expected)
                            } else {
                                match (va, vb) {
                                    (NodeVal::Shared(s), _) | (_, NodeVal::Shared(s)) => {
                                        NodeVal::Shared(s)
                                    }
                                    _ => return Err(MpcithError::InvalidOperation),
                                }
                            }
                        }
                    }
                }
                circuit::Node::Mul(a, b) => {
                    let va = values[a.as_usize()];
                    let vb = values[b.as_usize()];
                    match (va, vb) {
                        (NodeVal::Public(x), NodeVal::Public(y)) => NodeVal::Public(x * y),
                        (_, NodeVal::Public(s)) | (NodeVal::Public(s), _) => {
                            let expected = va.as_field(p) * vb.as_field(p);
                            let scalar = s;
                            expect_op!(
                                LocalOperation::MulPublic {
                                    output,
                                    public,
                                    share
                                },
                                if *output != out || *public != scalar || *share != expected {
                                    return Err(MpcithError::InconsistentView);
                                }
                            );
                            NodeVal::Shared(expected)
                        }
                        (NodeVal::Shared(_), NodeVal::Shared(_)) => {
                            // Beaver multiplication. Local consistency:
                            // this party's broadcast contribution must
                            // equal x_i - a and y_i - b.
                            let triple = view
                                .triple_shares
                                .get(next_triple)
                                .ok_or(MpcithError::InconsistentView)?;
                            next_triple += 1;

                            let d_claim = *view
                                .opened_values
                                .get(next_opened)
                                .ok_or(MpcithError::MissingResponse)?;
                            let e_claim = *view
                                .opened_values
                                .get(next_opened + 1)
                                .ok_or(MpcithError::MissingResponse)?;
                            next_opened += 2;

                            if d_claim != va.as_field(p) - triple.a
                                || e_claim != vb.as_field(p) - triple.b
                            {
                                return Err(MpcithError::InvalidOpening);
                            }

                            // Global consistency: the operation must use
                            // the globally opened masks at this position.
                            let d_global = *globals
                                .get(next_opened - 2)
                                .ok_or(MpcithError::InvalidOpening)?;
                            let e_global = *globals
                                .get(next_opened - 1)
                                .ok_or(MpcithError::InvalidOpening)?;

                            let mut z_expected =
                                triple.c + d_global * triple.b + e_global * triple.a;
                            if p == 0 {
                                z_expected += d_global * e_global;
                            }

                            expect_op!(
                                LocalOperation::BeaverMul {
                                    output,
                                    triple_index: ti,
                                    d,
                                    e,
                                    share
                                },
                                if *output != out
                                    || *ti != next_triple - 1
                                    || *d != d_global
                                    || *e != e_global
                                    || *share != z_expected
                                {
                                    return Err(MpcithError::InconsistentView);
                                }
                            );
                            NodeVal::Shared(z_expected)
                        }
                    }
                }
            };
            values.push(val);
        }

        // The view is fully consumed exactly when its claims are
        // consistent with the circuit shape.
        if next_op != view.local_operations.len()
            || next_triple != view.triple_shares.len()
            || next_opened != view.opened_values.len()
        {
            return Err(MpcithError::InconsistentView);
        }

        Ok(Replay { values })
    }

    /// Checks that the combined output shares equal the statement's
    /// expected outputs.
    fn check_outputs(
        &self,
        statement: &Statement,
        repetition: &crate::Repetition,
        circuit: &Circuit<FieldElement>,
        replays: &[Replay],
    ) -> Result<bool, MpcithError> {
        if repetition.hidden_output_shares.len() != circuit.outputs().len() {
            return Err(MpcithError::OutputMismatch);
        }

        for (k, output_id) in circuit.outputs().iter().enumerate() {
            let expected = *statement
                .expected_outputs
                .get(k)
                .ok_or(MpcithError::InvalidStatement)?
                .value();

            if !node_depends_on_secrets(circuit, *output_id) {
                // Fully public path: value is already determined and the
                // hidden party must contribute nothing.
                if repetition.hidden_output_shares[k] != FieldElement::zero() {
                    return Err(MpcithError::OutputMismatch);
                }
                continue;
            }

            let mut total = repetition.hidden_output_shares[k];
            for replay in replays {
                total += match replay.values[output_id.as_usize()] {
                    NodeVal::Shared(v) => v,
                    // Cannot happen for secret-dependent nodes.
                    NodeVal::Public(_) => return Err(MpcithError::InconsistentView),
                };
            }
            if total != expected {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Whether a node's evaluation depends on at least one secret input.
fn node_depends_on_secrets(circuit: &Circuit<FieldElement>, id: circuit::NodeId) -> bool {
    fn walk(circuit: &Circuit<FieldElement>, index: usize, cache: &mut [Option<bool>]) -> bool {
        if let Some(v) = cache[index] {
            return v;
        }
        let result = match circuit.nodes()[index] {
            circuit::Node::SecretInput => true,
            circuit::Node::PublicInput | circuit::Node::Constant(_) => false,
            circuit::Node::Add(a, b) | circuit::Node::Mul(a, b) => {
                walk(circuit, a.as_usize(), cache) || walk(circuit, b.as_usize(), cache)
            }
        };
        cache[index] = Some(result);
        result
    }
    let mut cache = vec![None; circuit.nodes().len()];
    walk(circuit, id.as_usize(), &mut cache)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::challenge::DeterministicChallengeSource;
    use crate::prover::MpcithProver;
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
        let s = b.mul(t, p).expect("valid");
        b.output(s).expect("valid");
        let circuit = b.build().expect("valid");

        let statement = Statement {
            circuit_id: circuit.compute_id(),
            public_inputs: vec![PublicValue::new(FieldElement::from(5u64))],
            expected_outputs: vec![PublicValue::new(FieldElement::from(35u64))],
        };
        (circuit, statement, vec![FieldElement::from(5u64)])
    }

    #[test]
    fn honest_proof_verifies_for_every_hidden_party() {
        for hidden in 0u8..3 {
            let (circuit, statement, witness) = fixture();
            let source = DeterministicChallengeSource::repeating(PartyId::new(hidden).unwrap(), 3);
            let mut prover = MpcithProver::new(
                &circuit,
                &statement,
                witness.clone(),
                Box::new(source),
                ChaCha20Rng::seed_from_u64(u64::from(hidden) + 1),
            )
            .expect("valid");
            let proof = prover.prove(3).expect("valid");
            assert_eq!(
                MpcithVerifier::new()
                    .verify(&statement, &proof, &circuit)
                    .expect("no error"),
                VerificationResult::Valid
            );
        }
    }

    #[test]
    fn wrong_output_is_invalid_not_error() {
        let (circuit, statement, _witness) = fixture();
        let source = DeterministicChallengeSource::repeating(PartyId::new(0).unwrap(), 1);
        let mut prover = MpcithProver::new(
            &circuit,
            &statement,
            vec![FieldElement::from(5u64)],
            Box::new(source),
            ChaCha20Rng::seed_from_u64(10),
        )
        .expect("valid");
        let proof = prover.prove(1).expect("valid");

        let mut wrong = statement;
        wrong.expected_outputs = vec![PublicValue::new(FieldElement::from(99u64))];
        assert_eq!(
            MpcithVerifier::new()
                .verify(&wrong, &proof, &circuit)
                .expect("no error"),
            VerificationResult::Invalid
        );
    }

    #[test]
    fn tampered_commitment_fails_closed() {
        let (circuit, statement, witness) = fixture();
        let source = DeterministicChallengeSource::repeating(PartyId::new(0).unwrap(), 1);
        let mut prover = MpcithProver::new(
            &circuit,
            &statement,
            witness,
            Box::new(source),
            ChaCha20Rng::seed_from_u64(21),
        )
        .expect("valid");
        let mut proof = prover.prove(1).expect("valid");

        use crypto_core::Digest;
        proof.repetitions[0].commitments[1] =
            crate::commitment::ViewCommitment::from_digest(Digest::new([7u8; 32]));

        assert!(matches!(
            MpcithVerifier::new().verify(&statement, &proof, &circuit),
            Err(MpcithError::CommitmentMismatch)
        ));
    }
}
