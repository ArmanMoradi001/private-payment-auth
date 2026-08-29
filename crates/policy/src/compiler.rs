//! Deterministic compilation of [`Policy`] trees into arithmetic circuits.
//!
//! The target machine is the workspace's plain `{+, ×}` circuit
//! ([`circuit::CircuitBuilder`]); there are no comparison or hash gates.
//! Constraints are expressed with three arithmetic gadgets:
//!
//! **Exact zero-indicator (Fermat).** For `x` over the prime field,
//! `x^(p−1)` equals `1` when `x ≠ 0` and `0` when `x = 0`. A credential
//! match becomes the exact boolean wire
//! `match = 1 − (s − c)^(p−1)`.
//!
//! **Dual bit-decomposition range check** ([`crate::range_check`]).
//! Amount caps publish their booleanity/reconstruction constraint wires
//! (each expected to evaluate to zero), proving `0 ≤ amount ≤ limit`
//! over the integers with no field wrap-around escape.
//!
//! **Threshold via discriminant + booleanity.** A `k`-of-`n` threshold
//! emits `D = Π_{t=0}^{k−1}(sum − t)`, which vanishes exactly when fewer
//! than `k` members are satisfied, and the wire `w = D · aux`. An
//! explicit booleanity constraint `w·(1 − w) = 0` pins `w` to a boolean;
//! combined with `D`, `w` is `0` when the leaf fails and reachable to
//! exactly `1` when it holds.
//!
//! **Combinators.** `And` multiplies child wires; `Or` evaluates
//! `a + b − a·b`. Both preserve booleanity when their inputs are boolean.
//!
//! The amount leaf contributes the constant `1` to the boolean tree and
//! enforces its bound globally through the published range-check
//! constraint outputs (this is the proven Phase 8 approach and avoids
//! placing an in-circuit SHA-256 — see the module docs and
//! `docs/security/policy-security.md`). Traversal order, gate order, and
//! constants are fully determined by the policy, so equal (normalized)
//! policies yield structurally identical circuits and equal
//! [`circuit::CircuitId`]s.

use ark_ff::{BigInteger, One, PrimeField, Zero};
use circuit::{Circuit, CircuitBuilder, CircuitId, NodeId};

use crate::ast::{credential_commitment, AmountLimit, CredentialId, Policy};
use crate::error::PolicyError;
use crate::range_check::{prove_bounded_difference, RangeCheckBits, AMOUNT_BIT_LEN};
use crate::witness::PolicyWitness;

/// Which secret input a compiled circuit expects, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretSlot {
    /// Credential number `usize`: the commitment of the witness secret,
    /// read as a field element (the secret itself is never placed on the
    /// wire; only its commitment is).
    Credential(usize),
    /// The payment amount.
    Amount,
    /// Binary digit `usize` (little-endian) of the amount, claimed by
    /// the witness and proven boolean plus reconstructive in-circuit.
    AmountBit(usize),
    /// Binary digit `usize` (little-endian) of `limit − amount`.
    DifferenceBit(usize),
    /// A prover-chosen inversion witness for a threshold's discriminant
    /// (the `aux` of the module docs).
    Auxiliary,
}

/// Which public input a compiled circuit expects, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicSlot {
    /// Credential number `usize`: the expected commitment (the
    /// [`CredentialId`]) read as a field element.
    CredentialCommitment(usize),
    /// The spending limit of the enclosing `AmountAtMost`.
    AmountLimit,
}

/// Compilation statistics for introspection and benchmarking.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CompilationMetadata {
    /// Total circuit nodes (inputs, constants, and gates).
    pub node_count: usize,
    /// Number of secret inputs.
    pub secret_input_count: usize,
    /// Number of public inputs.
    pub public_input_count: usize,
    /// Number of multiplication gates.
    pub multiplication_count: usize,
}

/// A compiled policy: the circuit plus its input slot layouts.
///
/// Slots are listed in the exact order the corresponding leaf nodes
/// appear in the circuit, which is the order reference evaluation and
/// the proof layer consume inputs.
#[derive(Clone, Debug)]
pub struct CompiledPolicy<F> {
    /// The compiled circuit.
    pub circuit: Circuit<F>,
    /// Secret inputs in declaration order.
    pub secret_slots: Vec<SecretSlot>,
    /// Public inputs in declaration order.
    pub public_slots: Vec<PublicSlot>,
    /// For each `SecretSlot::Auxiliary` input, the discriminant wire it
    /// inverts (kept in declaration order of the auxiliary inputs).
    pub auxiliary_targets: Vec<NodeId>,
    /// Number of published constraint outputs (expected to evaluate to
    /// zero), which precede the root output in the output list.
    pub range_check_outputs: usize,
    /// Compilation statistics.
    pub metadata: CompilationMetadata,
}

impl<F> CompiledPolicy<F> {
    /// Semantic id of the compiled circuit.
    pub fn circuit_id(&self) -> CircuitId
    where
        F: PrimeField,
    {
        self.circuit.compute_id()
    }
}

/// Compiles a policy into a circuit over field `F`.
///
/// See [`compile_with_layout`] for the variant that also returns the
/// input slot layouts.
///
/// # Errors
///
/// Propagates [`PolicyError`] validation and compilation variants.
pub fn compile<F: PrimeField>(policy: &Policy) -> Result<Circuit<F>, PolicyError> {
    Ok(compile_with_layout::<F>(policy)?.circuit)
}

/// Compiles a policy into a circuit plus its input slot layouts.
///
/// The input policy is normalized first so compilation is a pure
/// function of the policy's canonical form.
///
/// # Errors
///
/// Returns [`PolicyError`] for invalid policies or compilation failures.
pub fn compile_with_layout<F: PrimeField>(
    policy: &Policy,
) -> Result<CompiledPolicy<F>, PolicyError> {
    let normalized = policy.normalize()?;
    normalized.validate()?;
    let mut compiler = Compiler::new();
    let root = compiler.emit_policy(&normalized)?;
    compiler.finish(root)
}

struct Compiler<F> {
    builder: CircuitBuilder<F>,
    secret_slots: Vec<SecretSlot>,
    public_slots: Vec<PublicSlot>,
    auxiliary_targets: Vec<NodeId>,
    constraint_outputs: Vec<NodeId>,
    multiplication_count: usize,
    credential_counter: usize,
}

impl<F: PrimeField> Compiler<F> {
    fn new() -> Self {
        Self {
            builder: CircuitBuilder::new(),
            secret_slots: Vec::new(),
            public_slots: Vec::new(),
            auxiliary_targets: Vec::new(),
            constraint_outputs: Vec::new(),
            multiplication_count: 0,
            credential_counter: 0,
        }
    }

    fn finish(mut self, root: NodeId) -> Result<CompiledPolicy<F>, PolicyError> {
        // Publish constraint outputs (expected zero), then the root.
        for node in &self.constraint_outputs {
            self.builder
                .output(*node)
                .map_err(|_| PolicyError::CircuitValidationFailure)?;
        }
        self.builder
            .output(root)
            .map_err(|_| PolicyError::CircuitValidationFailure)?;
        let circuit = self
            .builder
            .build()
            .map_err(|_| PolicyError::CircuitValidationFailure)?;
        let metadata = CompilationMetadata {
            node_count: circuit.nodes().len(),
            secret_input_count: circuit.num_secret_inputs(),
            public_input_count: circuit.num_public_inputs(),
            multiplication_count: self.multiplication_count,
        };
        Ok(CompiledPolicy {
            circuit,
            secret_slots: self.secret_slots,
            public_slots: self.public_slots,
            auxiliary_targets: self.auxiliary_targets,
            range_check_outputs: self.constraint_outputs.len(),
            metadata,
        })
    }

    /// Emits the boolean wire for `policy`.
    fn emit_policy(&mut self, policy: &Policy) -> Result<NodeId, PolicyError> {
        match policy {
            Policy::AmountAtMost(limit) => self.emit_amount(*limit),
            Policy::Credential(id) => self.emit_credential(*id),
            Policy::Threshold { k, members } => self.emit_threshold(*k, members),
            Policy::And(members) => self.combine(members, Combinator::And),
            Policy::Or(members) => self.combine(members, Combinator::Or),
        }
    }

    fn combine(
        &mut self,
        members: &[Policy],
        combinator: Combinator,
    ) -> Result<NodeId, PolicyError> {
        let mut wire = None;
        for sub in members {
            let sub_wire = self.emit_policy(sub)?;
            wire = Some(match wire {
                None => sub_wire,
                Some(prev) => match combinator {
                    Combinator::And => self.mul_gate(prev, sub_wire)?,
                    Combinator::Or => {
                        let prod = self.mul_gate(prev, sub_wire)?;
                        let summed = self.add_gate(prev, sub_wire)?;
                        self.sub_gate(summed, prod)?
                    }
                },
            });
        }
        wire.ok_or(PolicyError::EmptyPolicy)
    }

    /// Boolean `1` iff `SHA-256(secret) == id`, via the Fermat indicator.
    ///
    /// Booleanity holds by construction: `x^(p−1)` is exactly `0` or `1`
    /// for any field element `x`.
    fn emit_credential(&mut self, _id: CredentialId) -> Result<NodeId, PolicyError> {
        let index = self.credential_counter;
        self.credential_counter += 1;
        let secret = self.secret_input(SecretSlot::Credential(index));
        let commitment = self.public_input(PublicSlot::CredentialCommitment(index));
        let difference = self.sub_gate(secret, commitment)?;
        let nonzero = self.fermat_nonzero(difference)?;
        self.one_minus(nonzero)
    }

    /// Emits the amount cap as a *boolean* combinator wire.
    ///
    /// The dual bit-decomposition range check (see [`range_check`]) proves
    /// `amount ≤ limit` by enforcing four internal constraints `c₁..c₄`,
    /// all zero exactly when the bound holds. We turn those into a single
    /// boolean `b = ∏ (1 − cᵢ^(p−1))`:
    ///
    /// - `cᵢ^(p−1)` is `0` when `cᵢ = 0` and `1` otherwise (Fermat), so
    ///   each factor is a genuine boolean that is `1` iff `cᵢ = 0`;
    /// - their product `b` is therefore a boolean equal to `1` *iff* the
    ///   bound holds.
    ///
    /// Unlike a global "all bounds hold" assertion, this `b` is a first
    /// class boolean that participates in `And`/`Or`/`Threshold`
    /// composition exactly like a credential leaf: an `Or` authorizes
    /// when *any* branch's `b` is `1`, a `Threshold` counts how many are
    /// `1`, and a satisfied bound is the only way to make `b = 1`
    /// (because `b = 1` forces every `cᵢ = 0`). The four range-check
    /// constraints are consumed internally and need not be published as
    /// separate outputs.
    fn emit_amount(&mut self, _limit: AmountLimit) -> Result<NodeId, PolicyError> {
        let amount = self.secret_input(SecretSlot::Amount);
        let limit_node = self.public_input(PublicSlot::AmountLimit);

        let mut value_bits = Vec::with_capacity(AMOUNT_BIT_LEN);
        for index in 0..AMOUNT_BIT_LEN {
            value_bits.push(self.secret_input(SecretSlot::AmountBit(index)));
        }
        let mut difference_bits = Vec::with_capacity(AMOUNT_BIT_LEN);
        for index in 0..AMOUNT_BIT_LEN {
            difference_bits.push(self.secret_input(SecretSlot::DifferenceBit(index)));
        }
        let bits = RangeCheckBits {
            value_bits: value_bits.try_into().expect("declared AMOUNT_BIT_LEN"),
            difference_bits: difference_bits.try_into().expect("declared AMOUNT_BIT_LEN"),
        };

        let outputs = prove_bounded_difference::<F>(&mut self.builder, amount, limit_node, &bits)?;
        // b = ∏ (1 − cᵢ^(p−1)): boolean, 1 iff the bound holds.
        let mut b = self.constant(<F as One>::one());
        for c in outputs {
            let fermat = self.fermat_nonzero(c)?;
            let satisfied = self.one_minus(fermat)?;
            b = self.mul_gate(b, satisfied)?;
        }
        Ok(b)
    }

    /// Constraint wire for “at least `k` of `n` members are satisfied”.
    ///
    /// Booleanity is enforced explicitly via `w·(1 − w) = 0`; see the
    /// module documentation for why this is required and sound.
    fn emit_threshold(
        &mut self,
        k: crate::ast::ThresholdK,
        members: &[Policy],
    ) -> Result<NodeId, PolicyError> {
        let mut sum: Option<NodeId> = None;
        for member in members {
            let sub_wire = self.emit_policy(member)?;
            sum = Some(match sum {
                None => sub_wire,
                Some(prev) => self.add_gate(prev, sub_wire)?,
            });
        }
        let sum = sum.ok_or(PolicyError::EmptyPolicy)?;

        let mut discriminant: Option<NodeId> = None;
        for t in 0..k.get() {
            let offset = self.constant(negate_u64::<F>(u64::from(t)));
            let diff = self.add_gate(sum, offset)?;
            discriminant = Some(match discriminant {
                None => diff,
                Some(prev) => self.mul_gate(prev, diff)?,
            });
        }
        let discriminant = discriminant.ok_or(PolicyError::InvalidThreshold)?;

        // w = discriminant · aux; booleanity enforced below.
        let aux = self.auxiliary_input(discriminant);
        let w = self.mul_gate(discriminant, aux)?;
        let neg_one = self.constant(-<F as One>::one());
        let negated = self.mul_gate(w, neg_one)?;
        let one = self.constant(<F as One>::one());
        let one_minus = self.add_gate(negated, one)?;
        let booleanity = self.mul_gate(w, one_minus)?;
        self.constraint_outputs.push(booleanity);
        Ok(w)
    }

    /// Exact indicator `1 − x^(p−1)`: `1` when `x = 0`, else `0`.
    fn fermat_nonzero(&mut self, x: NodeId) -> Result<NodeId, PolicyError> {
        let bits = (-<F as One>::one()).into_bigint().to_bits_le();
        let highest = bits
            .iter()
            .rposition(|&bit| bit)
            .ok_or(PolicyError::CompilationFailure)?;
        let mut acc = x;
        for index in (0..highest).rev() {
            acc = self.mul_gate(acc, acc)?;
            if bits[index] {
                acc = self.mul_gate(acc, x)?;
            }
        }
        Ok(acc)
    }

    fn one_minus(&mut self, x: NodeId) -> Result<NodeId, PolicyError> {
        let neg_one = self.constant(-<F as One>::one());
        let negated = self.mul_gate(x, neg_one)?;
        let one = self.constant(<F as One>::one());
        self.add_gate(negated, one)
    }

    fn auxiliary_input(&mut self, target: NodeId) -> NodeId {
        self.secret_slots.push(SecretSlot::Auxiliary);
        self.auxiliary_targets.push(target);
        self.builder.secret_input()
    }

    fn secret_input(&mut self, slot: SecretSlot) -> NodeId {
        self.secret_slots.push(slot);
        self.builder.secret_input()
    }

    fn public_input(&mut self, slot: PublicSlot) -> NodeId {
        self.public_slots.push(slot);
        self.builder.public_input()
    }

    fn constant(&mut self, value: F) -> NodeId {
        self.builder.constant(value)
    }

    fn add_gate(&mut self, a: NodeId, b: NodeId) -> Result<NodeId, PolicyError> {
        self.builder
            .add(a, b)
            .map_err(|_| PolicyError::CompilationFailure)
    }

    fn mul_gate(&mut self, a: NodeId, b: NodeId) -> Result<NodeId, PolicyError> {
        self.multiplication_count += 1;
        self.builder
            .mul(a, b)
            .map_err(|_| PolicyError::CompilationFailure)
    }

    fn sub_gate(&mut self, a: NodeId, b: NodeId) -> Result<NodeId, PolicyError> {
        let neg_one = self.constant(-<F as One>::one());
        let neg_b = self.mul_gate(b, neg_one)?;
        self.add_gate(a, neg_b)
    }
}

#[derive(Clone, Copy)]
enum Combinator {
    And,
    Or,
}

/// `-t` in the field, so `add(x, const)` subtracts `t`.
fn negate_u64<F: PrimeField>(t: u64) -> F {
    -F::from(t)
}

impl<F: PrimeField> CompiledPolicy<F> {
    /// Builds the `(secret, public)` field-input vectors for
    /// `policy`/`witness`, solving the auxiliary inversion witnesses so
    /// every threshold discriminant reaches its forced boolean.
    ///
    /// Traversal order matches [`compile_with_layout`], so the produced
    /// vectors align exactly with [`Self::secret_slots`] and
    /// [`Self::public_slots`].
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::WitnessMismatch`] if a credential id has no
    /// secret in the witness.
    pub fn build_inputs(
        &self,
        policy: &Policy,
        witness: &PolicyWitness,
    ) -> Result<(Vec<F>, Vec<F>), PolicyError> {
        let mut secrets = Vec::with_capacity(self.secret_slots.len());
        let mut publics = Vec::with_capacity(self.public_slots.len());
        let mut aux_positions = Vec::new();
        // Compile normalizes the policy before emitting, so the slot order
        // follows the *normalized* traversal. Walk the same order here.
        let normalized = policy.normalize()?;
        self.fill(
            &normalized,
            witness,
            &mut secrets,
            &mut publics,
            &mut aux_positions,
        )?;

        // Solve auxiliary witnesses: for every threshold discriminant `D`,
        // `aux = D⁻¹` (or `0` when `D = 0`), which forces the boolean
        // `w = D·aux` to exactly `1` when the threshold is satisfied.
        //
        // The discriminants may depend on one another through nesting
        // (an outer threshold's sum includes an inner threshold's root,
        // which depends on the inner aux), so a single pass over a fresh
        // all-zero witness would solve the outer aux before the inner one
        // is known. Iterate to a fixpoint: re-evaluating after each round
        // propagates inner solutions outward. The process is monotonic
        // (aux wires flip `0 → 1` once their discriminant becomes `1`) and
        // bounded by the nesting depth, so it converges quickly.
        for _ in 0..=self.auxiliary_targets.len() {
            let values = eval_all_nodes(&self.circuit, &secrets, &publics)
                .map_err(|_| PolicyError::CircuitValidationFailure)?;
            let mut changed = false;
            for (position, target) in aux_positions.iter().zip(self.auxiliary_targets.iter()) {
                let desired = <F as ark_ff::Field>::inverse(&values[target.as_usize()])
                    .unwrap_or_else(<F as Zero>::zero);
                if secrets[*position] != desired {
                    secrets[*position] = desired;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
        Ok((secrets, publics))
    }

    fn fill(
        &self,
        policy: &Policy,
        witness: &PolicyWitness,
        secrets: &mut Vec<F>,
        publics: &mut Vec<F>,
        aux_positions: &mut Vec<usize>,
    ) -> Result<(), PolicyError> {
        match policy {
            Policy::Credential(id) => {
                let secret = witness.secret_for(id).ok_or(PolicyError::WitnessMismatch)?;
                let commitment = digest_to_field(&credential_commitment(secret));
                secrets.push(commitment);
                publics.push(digest_to_field(&crypto_core::Digest::new(*id.as_bytes())));
                Ok(())
            }
            Policy::AmountAtMost(limit) => {
                let amount = match witness.amount {
                    Some(amount) => amount.value(),
                    None => 0,
                };
                secrets.push(F::from(amount));
                publics.push(F::from(limit.value()));
                let value_bits = decompose(amount);
                let difference_bits = decompose(limit.value().wrapping_sub(amount));
                for bit in value_bits.iter().chain(difference_bits.iter()) {
                    secrets.push(F::from(u64::from(*bit)));
                }
                Ok(())
            }
            Policy::Threshold { members, .. } => {
                for member in members {
                    self.fill(member, witness, secrets, publics, aux_positions)?;
                }
                aux_positions.push(secrets.len());
                secrets.push(<F as Zero>::zero());
                Ok(())
            }
            Policy::And(members) | Policy::Or(members) => {
                for member in members {
                    self.fill(member, witness, secrets, publics, aux_positions)?;
                }
                Ok(())
            }
        }
    }

    /// Reference evaluation of the compiled circuit for `policy`/`witness`.
    ///
    /// Returns `true` exactly when the root output is `1` and every
    /// published constraint output is `0` — i.e. when the policy is
    /// authorized. This is the circuit-side ground truth and must equal
    /// [`crate::evaluator::evaluate`]'s `authorized` flag.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::WitnessMismatch`] if the witness does not
    /// match the policy, or [`PolicyError::CircuitValidationFailure`] if
    /// the circuit cannot be evaluated (an internal invariant).
    pub fn reference_evaluate(
        &self,
        policy: &Policy,
        witness: &PolicyWitness,
    ) -> Result<bool, PolicyError> {
        let (secrets, publics) = self.build_inputs(policy, witness)?;
        let values = eval_all_nodes(&self.circuit, &secrets, &publics)
            .map_err(|_| PolicyError::CircuitValidationFailure)?;
        for node in self.circuit.outputs().iter().take(self.range_check_outputs) {
            if values[node.as_usize()] != <F as Zero>::zero() {
                return Ok(false);
            }
        }
        let root = *self
            .circuit
            .outputs()
            .last()
            .ok_or(PolicyError::CircuitValidationFailure)?;
        Ok(values[root.as_usize()] == <F as One>::one())
    }
}

/// Evaluates every node of `circuit` over plaintext field elements,
/// returning the full value vector indexed by [`NodeId`]. Unlike
/// [`circuit::evaluate_reference`] (which returns only output values),
/// the auxiliary-witness solver needs intermediate node values.
fn eval_all_nodes<F: PrimeField>(
    circuit: &Circuit<F>,
    secrets: &[F],
    publics: &[F],
) -> Result<Vec<F>, PolicyError> {
    if secrets.len() != circuit.num_secret_inputs() || publics.len() != circuit.num_public_inputs()
    {
        return Err(PolicyError::CircuitValidationFailure);
    }
    let mut values: Vec<F> = Vec::with_capacity(circuit.nodes().len());
    let mut next_secret = 0usize;
    let mut next_public = 0usize;
    for node in circuit.nodes() {
        let value = match node {
            circuit::Node::SecretInput => {
                let v = secrets[next_secret];
                next_secret += 1;
                v
            }
            circuit::Node::PublicInput => {
                let v = publics[next_public];
                next_public += 1;
                v
            }
            circuit::Node::Constant(c) => *c.value(),
            circuit::Node::Add(a, b) => values[a.as_usize()] + values[b.as_usize()],
            circuit::Node::Mul(a, b) => values[a.as_usize()] * values[b.as_usize()],
        };
        values.push(value);
    }
    Ok(values)
}

/// Reads a digest as the canonical field element used for commitments.
fn digest_to_field<F: PrimeField>(digest: &crypto_core::Digest) -> F {
    F::from_le_bytes_mod_order(digest.as_bytes())
}

/// Returns the little-endian binary digits of `value`.
fn decompose(value: u64) -> [bool; AMOUNT_BIT_LEN] {
    let mut bits = [false; AMOUNT_BIT_LEN];
    for (index, slot) in bits.iter_mut().enumerate() {
        *slot = (value >> index) & 1 == 1;
    }
    bits
}
