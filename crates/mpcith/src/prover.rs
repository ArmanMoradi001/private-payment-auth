//! The MPCitH prover.
//!
//! For every repetition the prover runs a *fresh* 3-party simulation:
//! secret inputs are re-shared from new randomness, fresh Beaver
//! triples are generated, and each party's view is recorded and
//! committed before the challenge is drawn. Nothing — shares, triples,
//! or commitment randomness — is ever reused across repetitions.
//!
//! Challenges come from an injectable [`ChallengeSource`]; the
//! Fiat–Shamir transform is deliberately deferred (ADR 0006).

use ark_ff::{UniformRand, Zero};
use crypto_core::SecretBytes;
use mpc::ShareContext;
use rand_core::CryptoRngCore;

use circuit::{Circuit, Node, NodeId};

use crate::challenge::ChallengeSource;
use crate::commitment::commit_view;
use crate::error::MpcithError;
use crate::statement::Statement;
use crate::types::{Challenge, FieldElement, PartyId, RepetitionId, PARTY_COUNT};
use crate::view::{LocalOperation, PartyView, TripleShare};

/// One opened party's view together with the commitment randomness
/// used to decommit it.
#[derive(Clone, Debug)]
pub struct OpenedView {
    /// The opened party's full execution view.
    pub view: PartyView,
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
    pub commitments: Vec<crate::commitment::ViewCommitment>,
    /// The challenge: which party stays hidden.
    pub challenge: Challenge,
    /// The two opened views (the parties other than the hidden one),
    /// in ascending party order.
    pub opened_views: Vec<OpenedView>,
    /// The hidden party's output share per declared circuit output,
    /// completing the output sum. Cheating here is caught whenever the
    /// corrupted party is not hidden (probability 2/3 per repetition).
    pub hidden_output_shares: Vec<FieldElement>,
}

/// A complete MPCitH proof: independent repetitions over fresh
/// sharing, triples, and commitment randomness.
#[derive(Clone, Debug)]
pub struct MpcithProof {
    /// One entry per repetition.
    pub repetitions: Vec<Repetition>,
}

/// Produces [`MpcithProof`]s for a fixed (circuit, statement, witness)
/// triple.
pub struct MpcithProver<'a, R: CryptoRngCore> {
    circuit: &'a Circuit<FieldElement>,
    statement: &'a Statement,
    witness: Vec<FieldElement>,
    challenge_source: Box<dyn ChallengeSource>,
    rng: R,
}

/// Value of one circuit node during the 3-party simulation: either a
/// plaintext value known to everyone or three additive shares.
#[derive(Clone, Copy)]
enum NodeVal {
    Public(FieldElement),
    Shared([FieldElement; 3]),
}

impl NodeVal {
    fn shared(&self) -> bool {
        matches!(self, NodeVal::Shared(_))
    }

    /// The plaintext value of a public node (zero for shared nodes;
    /// callers only invoke this on the public operand of a mixed gate).
    fn public_part(&self) -> FieldElement {
        match self {
            NodeVal::Public(v) => *v,
            NodeVal::Shared(_) => FieldElement::zero(),
        }
    }
}

/// Per-party mutable state accumulated during one repetition.
struct PartyState {
    input_shares: Vec<FieldElement>,
    local_operations: Vec<LocalOperation>,
    triple_shares: Vec<TripleShare>,
    opened_values: Vec<FieldElement>,
}

impl<'a, R: CryptoRngCore> MpcithProver<'a, R> {
    /// Creates a prover after checking statement/witness consistency.
    ///
    /// # Errors
    ///
    /// - [`MpcithError::InvalidCircuit`] if the circuit fails
    ///   validation or does not match the statement's id.
    /// - [`MpcithError::InvalidStatement`] if the witness or public
    ///   input counts disagree with the circuit.
    pub fn new(
        circuit: &'a Circuit<FieldElement>,
        statement: &'a Statement,
        witness: Vec<FieldElement>,
        challenge_source: Box<dyn ChallengeSource>,
        rng: R,
    ) -> Result<Self, MpcithError> {
        statement.validate(circuit)?;
        if witness.len() != circuit.num_secret_inputs() {
            return Err(MpcithError::InvalidStatement);
        }
        Ok(Self {
            circuit,
            statement,
            witness,
            challenge_source,
            rng,
        })
    }

    /// Draws one random field element.
    fn rand_element(&mut self) -> FieldElement {
        FieldElement::rand(&mut self.rng)
    }

    /// Draws a fresh 3-way additive sharing of `value`.
    fn share3(&mut self, value: &FieldElement) -> [FieldElement; 3] {
        let s0 = self.rand_element();
        let s1 = self.rand_element();
        let s2 = *value - s0 - s1;
        [s0, s1, s2]
    }

    /// Draws a fresh shared Beaver triple `(a, b, c = a·b)`.
    fn next_triple(&mut self) -> ([FieldElement; 3], [FieldElement; 3], [FieldElement; 3]) {
        let a = self.rand_element();
        let b = self.rand_element();
        let c = a * b;
        (self.share3(&a), self.share3(&b), self.share3(&c))
    }

    /// Proves correct evaluation using `repetition_count` independent
    /// repetitions.
    ///
    /// # Errors
    ///
    /// - [`MpcithError::InvalidRepetitionCount`] if the count is zero.
    /// - [`MpcithError::InvalidProtocolState`] if the challenge source
    ///   is exhausted before all repetitions complete.
    pub fn prove(&mut self, repetition_count: u32) -> Result<MpcithProof, MpcithError> {
        if repetition_count == 0 {
            return Err(MpcithError::InvalidRepetitionCount);
        }

        let mut repetitions = Vec::with_capacity(repetition_count as usize);
        for index in 0..repetition_count {
            repetitions.push(self.prove_repetition(RepetitionId::new(index))?);
        }
        Ok(MpcithProof { repetitions })
    }

    /// Executes one full repetition end-to-end.
    #[allow(clippy::too_many_lines)]
    fn prove_repetition(&mut self, id: RepetitionId) -> Result<Repetition, MpcithError> {
        // A fresh per-repetition sharing context (3 parties, execution
        // id bound to this repetition). Shares here are drawn directly
        // via share3(); the context documents the domain binding.
        let _ctx = ShareContext::new(
            usize::from(PARTY_COUNT),
            u64::from(id.get()),
            crate::VIEW_CONTEXT_DOMAIN,
        )
        .map_err(|_| MpcithError::InvalidProtocolState)?;

        let mut parties: Vec<PartyState> = (0..PARTY_COUNT)
            .map(|_| PartyState {
                input_shares: Vec::with_capacity(self.witness.len()),
                local_operations: Vec::new(),
                triple_shares: Vec::new(),
                opened_values: Vec::new(),
            })
            .collect();

        // 1. Fresh additive shares of every secret input.
        for i in 0..self.witness.len() {
            let secret = self.witness[i];
            let shares = self.share3(&secret);
            for (p, state) in parties.iter_mut().enumerate() {
                state.input_shares.push(shares[p]);
            }
        }

        let mut values: Vec<NodeVal> = Vec::with_capacity(self.circuit.nodes().len());
        let mut next_secret = 0usize;
        let mut next_public = 0usize;

        for (index, node) in self.circuit.nodes().iter().enumerate() {
            let out = NodeId::new(index as u32);
            let val = match node {
                Node::SecretInput => {
                    let mut shares = [FieldElement::zero(); 3];
                    for p in 0..3usize {
                        shares[p] = parties[p].input_shares[next_secret];
                    }
                    next_secret += 1;
                    NodeVal::Shared(shares)
                }
                Node::PublicInput => {
                    let v = *self.statement.public_inputs[next_public].value();
                    next_public += 1;
                    NodeVal::Public(v)
                }
                Node::Constant(c) => NodeVal::Public(*c.value()),
                Node::Add(a, b) => {
                    let (va, vb) = (&values[a.as_usize()], &values[b.as_usize()]);
                    if !va.shared() && !vb.shared() {
                        NodeVal::Public(va.public_part() + vb.public_part())
                    } else if va.shared() && vb.shared() {
                        // Fully shared: share-wise addition.
                        let mut shares = [FieldElement::zero(); 3];
                        for p in 0..3usize {
                            let sum = operand(va, p) + operand(vb, p);
                            parties[p].local_operations.push(LocalOperation::Add {
                                output: out,
                                share: sum,
                            });
                            shares[p] = sum;
                        }
                        NodeVal::Shared(shares)
                    } else {
                        // Mixed shared + public: the public value is
                        // absorbed by *one* party's share only, so the
                        // sum increases by exactly v (adding it to all
                        // three shares would inject 3·v).
                        let public_val = if va.shared() {
                            vb.public_part()
                        } else {
                            va.public_part()
                        };
                        let shared_val = if va.shared() { va } else { vb };
                        let mut shares = [FieldElement::zero(); 3];
                        for p in 0..3usize {
                            if p == 0 {
                                let sum = operand(shared_val, 0) + public_val;
                                parties[0].local_operations.push(LocalOperation::Add {
                                    output: out,
                                    share: sum,
                                });
                                shares[0] = sum;
                            } else {
                                shares[p] = operand(shared_val, p);
                            }
                        }
                        NodeVal::Shared(shares)
                    }
                }
                Node::Mul(a, b) => {
                    self.mul_gate(out, a.as_usize(), b.as_usize(), &values, &mut parties)?
                }
            };
            values.push(val);
        }

        // Capture output-node values for response assembly.
        let output_vals: Vec<(bool, [FieldElement; 3])> = self
            .circuit
            .outputs()
            .iter()
            .map(|id| match &values[id.as_usize()] {
                NodeVal::Public(_) => (false, [FieldElement::zero(); 3]),
                NodeVal::Shared(s) => (true, *s),
            })
            .collect();

        // 5. Commit every view with fresh randomness (pre-challenge).
        let mut commitments = Vec::with_capacity(usize::from(PARTY_COUNT));
        let mut randomness = Vec::with_capacity(usize::from(PARTY_COUNT));
        for p in 0..3usize {
            let view = build_view(id, p, &parties)?;
            let r = self.fresh_randomness()?;
            commitments.push(commit_view(&view, &r)?);
            randomness.push(r);
        }

        // 6. Challenge decides which single view stays hidden.
        let challenge = self.challenge_source.next_challenge()?;
        let hidden = challenge.hidden_party.get() as usize;

        // 7. Open the two non-hidden views with their randomness.
        let mut opened_views = Vec::with_capacity(2);
        for p in PartyId::new(challenge.hidden_party.get())?.others() {
            let idx = p.get() as usize;
            opened_views.push(OpenedView {
                view: build_view(id, idx, &parties)?,
                randomness: randomness[idx].clone(),
            });
        }
        opened_views.sort_by_key(|ov| ov.view.party_id.get());

        let hidden_output_shares = output_vals
            .iter()
            .map(|(shared, shares)| {
                if *shared {
                    shares[hidden]
                } else {
                    FieldElement::zero()
                }
            })
            .collect();

        Ok(Repetition {
            id,
            commitments,
            challenge,
            opened_views,
            hidden_output_shares,
        })
    }

    /// Evaluates one multiplication gate over the tracked values,
    /// recording per-party operations and openings.
    fn mul_gate(
        &mut self,
        out: NodeId,
        a_idx: usize,
        b_idx: usize,
        values: &[NodeVal],
        parties: &mut [PartyState],
    ) -> Result<NodeVal, MpcithError> {
        let (va, vb) = (&values[a_idx], &values[b_idx]);
        if !va.shared() && !vb.shared() {
            return Ok(NodeVal::Public(va.public_part() * vb.public_part()));
        }

        // Exactly one shared operand: local scalar multiplication.
        if va.shared() != vb.shared() {
            let (shared_val, scalar) = if va.shared() {
                (va, vb.public_part())
            } else {
                (vb, va.public_part())
            };
            let mut shares = [FieldElement::zero(); 3];
            for p in 0..3usize {
                let product = operand(shared_val, p) * scalar;
                parties[p].local_operations.push(LocalOperation::MulPublic {
                    output: out,
                    public: scalar,
                    share: product,
                });
                shares[p] = product;
            }
            return Ok(NodeVal::Shared(shares));
        }

        // Beaver multiplication of two shared values.
        let triple_index = parties[0].triple_shares.len();
        let (ta, tb, tc) = self.next_triple();

        let mut d = FieldElement::zero();
        let mut e = FieldElement::zero();
        for p in 0..3usize {
            d += operand(va, p) - ta[p];
            e += operand(vb, p) - tb[p];
        }

        let mut shares = [FieldElement::zero(); 3];
        for p in 0..3usize {
            let dp = operand(va, p) - ta[p];
            let ep = operand(vb, p) - tb[p];
            // The public constant d·e is folded into party 0's share
            // only; adding it everywhere would triple-count.
            let mut z = tc[p] + d * tb[p] + e * ta[p];
            if p == 0 {
                z += d * e;
            }
            parties[p].triple_shares.push(TripleShare {
                a: ta[p],
                b: tb[p],
                c: tc[p],
            });
            parties[p].opened_values.push(dp);
            parties[p].opened_values.push(ep);
            parties[p].local_operations.push(LocalOperation::BeaverMul {
                output: out,
                triple_index,
                d,
                e,
                share: z,
            });
            shares[p] = z;
        }
        Ok(NodeVal::Shared(shares))
    }

    /// Draws 32 fresh bytes of commitment randomness.
    fn fresh_randomness(&mut self) -> Result<SecretBytes, MpcithError> {
        use rand_core::RngCore;
        let mut bytes = vec![0u8; crate::types::RANDOMNESS_LEN_MPCITH];
        RngCore::fill_bytes(&mut self.rng, &mut bytes);
        Ok(SecretBytes::new(bytes))
    }
}

/// The value party `p` holds for a node (its share, or the plaintext).
fn operand(value: &NodeVal, p: usize) -> FieldElement {
    match value {
        NodeVal::Public(v) => *v,
        NodeVal::Shared(s) => s[p],
    }
}

/// Assembles party `p`'s view from accumulated per-party state.
fn build_view(
    id: RepetitionId,
    p: usize,
    parties: &[PartyState],
) -> Result<PartyView, MpcithError> {
    let state = parties.get(p).ok_or(MpcithError::InvalidProtocolState)?;
    Ok(PartyView {
        repetition_id: id,
        party_id: PartyId::new(p as u8)?,
        input_shares: state.input_shares.clone(),
        local_operations: state.local_operations.clone(),
        triple_shares: state.triple_shares.clone(),
        opened_values: state.opened_values.clone(),
    })
}
