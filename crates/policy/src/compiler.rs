//! Deterministic compilation of [`Policy`] trees into arithmetic circuits.
//!
//! The target machine is the workspace's plain `{+, ×}` circuit
//! ([`circuit::CircuitBuilder`]); there are no comparison or hash
//! gates, and the MPC/MPCitH layers evaluate only `Add`/`Mul` on
//! additive shares. Constraints are therefore expressed with three
//! arithmetic gadgets:
//!
//! **Exact zero-indicator (Fermat).** For `x` over the prime field,
//! `x^(p−1)` equals `1` when `x ≠ 0` and `0` when `x = 0`. Credential
//! matches become exact boolean wires:
//! `match_i = 1 − (s_i − c_i)^(p−1)`.
//!
//! **Inverted exclusion product.** Each threshold leaf emits the wire
//! `w = X · aux`, where `X = Π_{t=0}^{k-1} (Σ_i match_i − t)` vanishes
//! exactly on the violating set and `aux` is a fresh secret input.
//! Hence `w ≡ 0` when the leaf fails, and `w = 1` is reachable (via
//! `aux = X⁻¹`) exactly when it holds.
//!
//! **Dual bit-decomposition range check** ([`crate::range_check`]).
//! Amount caps publish four outputs — value/difference booleanity and
//! reconstruction sums — that must be **exactly zero**, proving
//! `0 ≤ amount ≤ limit < 2^64` over the integers with no field
//! wrap-around escape. See ADR 0009; this replaces the phase 7 window
//! product, which was unsound for large amounts.
//!
//! **Combinators.** `And` multiplies child wires; `Or` evaluates
//! `a + b − a·b`; an amount leaf contributes the constant-one wire
//! because its constraint is enforced globally by its published
//! outputs. Threshold soundness composes: a child wire is either
//! pinned to `0` (leaf violated) or settable to exactly `1`. Outputs
//! are, in emission order: four per `AmountAtMost` leaf (each expected
//! zero) followed by the root wire (expected one).
//!
//! Traversal order, gate order, and constants are fully determined by
//! the policy, so equal policies yield structurally identical circuits
//! and equal [`circuit::CircuitId`]s.

use ark_ff::{BigInteger, One, PrimeField};
use circuit::{Circuit, CircuitBuilder, CircuitId, NodeId};

use crate::error::PolicyError;
use crate::policy::Policy;
use crate::range_check::{prove_bounded_difference, RangeCheckBits, AMOUNT_BIT_LEN};

/// Which secret input a compiled circuit expects, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SecretSlot {
    /// Credential number `usize`: the secret whose commitment must match.
    Credential(usize),
    /// The payment amount.
    Amount,
    /// Binary digit `usize` (little-endian) of the amount, claimed by
    /// the witness and proven boolean plus reconstructive in-circuit.
    AmountBit(usize),
    /// Binary digit `usize` (little-endian) of `limit − amount`.
    DifferenceBit(usize),
    /// A prover-chosen inversion witness for a constraint-forcing
    /// gadget (the `aux` of the module docs).
    Auxiliary,
}

/// Which public input a compiled circuit expects, in declaration order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PublicSlot {
    /// Credential number `usize`: the expected commitment digest read
    /// as a field element.
    CredentialCommitment(usize),
    /// The spending limit of the enclosing `AmountAtMost`.
    AmountLimit,
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
    /// must invert (crate-invariant alignment with `secret_slots`).
    pub(crate) auxiliary_targets: Vec<NodeId>,
    /// Number of published range-check constraint outputs (four per
    /// `AmountAtMost` leaf), all expected to evaluate to zero. They
    /// precede the root wire in the output list.
    pub range_check_outputs: usize,
}

impl<F> CompiledPolicy<F> {
    /// Semantic id of the compiled circuit.
    pub fn circuit_id(&self) -> CircuitId
    where
        F: PrimeField,
    {
        self.circuit.compute_id()
    }

    /// Returns the discriminant wire each auxiliary input inverts, in
    /// declaration order of the auxiliary inputs.
    ///
    /// Witness builders set `aux = X⁻¹` (or `0` when `X = 0`) for the
    /// matching pair; see the module documentation.
    pub fn auxiliary_targets(&self) -> &[NodeId] {
        &self.auxiliary_targets
    }
}

/// Compiles a policy into a circuit over field `F`.
///
/// See [`compile_with_layout`] for the variant that also returns the
/// input slot layouts.
///
/// # Errors
///
/// Propagates the [`crate::PolicyError`] validation variants for
/// structurally invalid policies.
pub fn compile<F: PrimeField>(policy: &Policy) -> Result<Circuit<F>, PolicyError> {
    Ok(compile_with_layout::<F>(policy)?.circuit)
}

/// Compiles a policy into a circuit plus its input slot layouts.
///
/// # Errors
///
/// Same as [`compile`].
pub fn compile_with_layout<F: PrimeField>(
    policy: &Policy,
) -> Result<CompiledPolicy<F>, PolicyError> {
    policy.validate()?;
    let mut compiler = Compiler::new();
    let root = compiler.emit_policy(policy)?;
    compiler.finish(root)
}

struct Compiler<F> {
    builder: CircuitBuilder<F>,
    secret_slots: Vec<SecretSlot>,
    public_slots: Vec<PublicSlot>,
    auxiliary_targets: Vec<NodeId>,
    range_check_outputs: usize,
}

impl<F: PrimeField> Compiler<F> {
    fn new() -> Self {
        Self {
            builder: CircuitBuilder::new(),
            secret_slots: Vec::new(),
            public_slots: Vec::new(),
            auxiliary_targets: Vec::new(),
            range_check_outputs: 0,
        }
    }

    fn finish(mut self, root: NodeId) -> Result<CompiledPolicy<F>, PolicyError> {
        self.builder
            .output(root)
            .map_err(|_| PolicyError::CircuitCompilationFailed)?;
        let circuit = self
            .builder
            .build()
            .map_err(|_| PolicyError::CircuitCompilationFailed)?;
        Ok(CompiledPolicy {
            circuit,
            secret_slots: self.secret_slots,
            public_slots: self.public_slots,
            auxiliary_targets: self.auxiliary_targets,
            range_check_outputs: self.range_check_outputs,
        })
    }

    /// Emits the constraint wire for `policy`.
    fn emit_policy(&mut self, policy: &Policy) -> Result<NodeId, PolicyError> {
        match policy {
            Policy::Threshold { k, credentials } => self.emit_threshold(*k, credentials.len()),
            Policy::AmountAtMost { limit } => self.emit_amount(*limit),
            Policy::And { policies } => self.combine(policies, Combinator::And),
            Policy::Or { policies } => self.combine(policies, Combinator::Or),
        }
    }

    fn combine(
        &mut self,
        policies: &[Policy],
        combinator: Combinator,
    ) -> Result<NodeId, PolicyError> {
        let mut wire = None;
        for sub in policies {
            let sub_wire = self.emit_policy(sub)?;
            wire = Some(match wire {
                None => sub_wire,
                Some(prev) => match combinator {
                    Combinator::And => self.mul_gate(prev, sub_wire)?,
                    Combinator::Or => {
                        // OR: a + b − a·b.
                        let prod = self.mul_gate(prev, sub_wire)?;
                        let summed = self.add_gate(prev, sub_wire)?;
                        self.sub_gate(summed, prod)?
                    }
                },
            });
        }
        wire.ok_or(PolicyError::MalformedPolicy)
    }

    /// Constraint wire for “at least `k` of `n` credentials match”.
    fn emit_threshold(&mut self, k: usize, n: usize) -> Result<NodeId, PolicyError> {
        let mut sum: Option<NodeId> = None;
        for index in 0..n {
            let secret = self.secret_input(SecretSlot::Credential(index));
            let commitment = self.public_input(PublicSlot::CredentialCommitment(index));
            let difference = self.sub_gate(secret, commitment)?;
            let nonzero = self.fermat_nonzero(difference)?;
            let matched = self.one_minus(nonzero)?;
            sum = Some(match sum {
                None => matched,
                Some(prev) => self.add_gate(prev, matched)?,
            });
        }
        let sum = sum.ok_or(PolicyError::ZeroCredentials)?;

        // Discriminant: zero exactly when fewer than `k` match.
        let mut discriminant: Option<NodeId> = None;
        for t in 0..k {
            let offset = self.constant(negate_u64::<F>(t as u64));
            let diff = self.add_gate(sum, offset)?;
            discriminant = Some(match discriminant {
                None => diff,
                Some(prev) => self.mul_gate(prev, diff)?,
            });
        }
        let discriminant = discriminant.ok_or(PolicyError::InvalidThreshold)?;
        self.constrained_by_discriminant(discriminant)
    }

    /// Emits the amount cap via the dual bit-decomposition range
    /// check.
    ///
    /// Publishes four constraint outputs (booleanity and
    /// reconstruction sums for the amount and its difference to the
    /// limit), all of which honest executions pin to exactly zero.
    /// The returned combinator wire is the constant one: the cap is a
    /// *global* assertion enforced by its own outputs, so it behaves
    /// as a satisfied conjunct inside any `And`/`Or` composition.
    ///
    /// `_limit` is carried for signature symmetry with the policy
    /// tree; the enforced value flows through the public input.
    fn emit_amount(&mut self, _limit: u64) -> Result<NodeId, PolicyError> {
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
        for node in outputs {
            self.builder
                .output(node)
                .map_err(|_| PolicyError::CircuitCompilationFailed)?;
        }
        self.range_check_outputs += outputs.len();

        // Neutral combinator contribution; enforcement is global via
        // the published zero-constraints above.
        Ok(self.builder.constant(<F as One>::one()))
    }

    /// Wires `discriminant · aux`: pinned to `0` when the discriminant
    /// vanishes, settable to exactly `1` otherwise.
    fn constrained_by_discriminant(&mut self, discriminant: NodeId) -> Result<NodeId, PolicyError> {
        let aux = self.auxiliary_input(discriminant);
        self.mul_gate(discriminant, aux)
    }

    /// Exact indicator `1 − x^(p−1)`: `1` when `x = 0`, else `0`.
    fn fermat_nonzero(&mut self, x: NodeId) -> Result<NodeId, PolicyError> {
        let bits = (-<F as One>::one()).into_bigint().to_bits_le();
        let highest = bits
            .iter()
            .rposition(|&bit| bit)
            .ok_or(PolicyError::CircuitCompilationFailed)?;
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
        let negated = {
            let neg = self.constant(-<F as One>::one());
            self.mul_gate(x, neg)?
        };
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
            .map_err(|_| PolicyError::CircuitCompilationFailed)
    }

    fn mul_gate(&mut self, a: NodeId, b: NodeId) -> Result<NodeId, PolicyError> {
        self.builder
            .mul(a, b)
            .map_err(|_| PolicyError::CircuitCompilationFailed)
    }

    fn sub_gate(&mut self, a: NodeId, b: NodeId) -> Result<NodeId, PolicyError> {
        let neg_b = {
            let neg = self.constant(-<F as One>::one());
            self.mul_gate(b, neg)?
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{credential_commitment, CredentialPolicy};
    use ark_ed25519::Fr;
    use ark_ff::{Field, Zero};
    use crypto_core::{Digest, SecretBytes};

    /// Full wire evaluation, mirroring `circuit::eval_reference` so
    /// tests can read intermediate discriminant values.
    fn eval_all(circuit: &Circuit<Fr>, secrets: &[Fr], publics: &[Fr]) -> Vec<Fr> {
        let mut values = Vec::with_capacity(circuit.nodes().len());
        let mut next_secret = 0;
        let mut next_public = 0;
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
        values
    }

    fn digest_to_field(digest: &Digest) -> Fr {
        Fr::from_le_bytes_mod_order(digest.as_bytes())
    }

    fn credential(i: u8) -> (SecretBytes, CredentialPolicy) {
        let secret = SecretBytes::new(vec![i, 0x42, 0x17]);
        let policy = CredentialPolicy {
            expected_commitment: credential_commitment(&secret),
        };
        (secret, policy)
    }

    /// Builds a `k`-of-`n` threshold plus its honest credential secrets.
    fn threshold(k: usize, n: usize) -> (Policy, Vec<SecretBytes>) {
        let mut secrets = Vec::new();
        let credentials = (0..n)
            .map(|_| {
                let (secret, policy) = credential(secrets.len() as u8 + 1);
                secrets.push(secret);
                policy
            })
            .collect();
        (Policy::Threshold { k, credentials }, secrets)
    }

    /// Fills every auxiliary slot with the inverse of its target wire
    /// (zero when the target is zero), mirroring what a real witness
    /// builder computes. Converges quickly because targets never depend
    /// on auxiliary values except through earlier slots.
    fn solve_auxiliaries(compiled: &CompiledPolicy<Fr>, secrets: &mut [Fr], publics: &[Fr]) {
        for _ in 0..3 {
            let values = eval_all(&compiled.circuit, secrets, publics);
            let mut changed = false;
            let mut aux_index = 0;
            for (slot_index, slot) in compiled.secret_slots.iter().enumerate() {
                if !matches!(slot, SecretSlot::Auxiliary) {
                    continue;
                }
                let target = compiled.auxiliary_targets()[aux_index].as_usize();
                aux_index += 1;
                let desired = <Fr as Field>::inverse(&values[target]).unwrap_or_else(Fr::zero);
                if secrets[slot_index] != desired {
                    secrets[slot_index] = desired;
                    changed = true;
                }
            }
            if !changed {
                break;
            }
        }
    }

    fn publics_for(compiled: &CompiledPolicy<Fr>, secrets: &[SecretBytes], limit: u64) -> Vec<Fr> {
        compiled
            .public_slots
            .iter()
            .map(|slot| match slot {
                PublicSlot::CredentialCommitment(i) => {
                    digest_to_field(&credential_commitment(&secrets[*i]))
                }
                PublicSlot::AmountLimit => Fr::from(limit),
            })
            .collect()
    }

    fn decompose(value: u64) -> [bool; AMOUNT_BIT_LEN] {
        let mut bits = [false; AMOUNT_BIT_LEN];
        for (index, slot) in bits.iter_mut().enumerate() {
            *slot = (value >> index) & 1 == 1;
        }
        bits
    }

    /// Builds the secret vector for `amount` under a policy whose
    /// amount leaves all share `limit`; digit witnesses are the honest
    /// decompositions.
    fn secrets_for(
        compiled: &CompiledPolicy<Fr>,
        secrets: &[SecretBytes],
        limit: u64,
        amount: u64,
        wrong: impl Fn(usize) -> bool,
    ) -> Vec<Fr> {
        let value_bits = decompose(amount);
        let difference_bits = decompose(limit.wrapping_sub(amount));
        compiled
            .secret_slots
            .iter()
            .map(|slot| match slot {
                SecretSlot::Credential(i) => {
                    if wrong(*i) {
                        digest_to_field(&Digest::new([0xfe; 32]))
                    } else {
                        digest_to_field(&credential_commitment(&secrets[*i]))
                    }
                }
                SecretSlot::Amount => Fr::from(amount),
                SecretSlot::AmountBit(i) => Fr::from(u64::from(value_bits[*i])),
                SecretSlot::DifferenceBit(i) => Fr::from(u64::from(difference_bits[*i])),
                SecretSlot::Auxiliary => Fr::zero(),
            })
            .collect()
    }

    /// All published outputs of the circuit in order.
    fn output_values(compiled: &CompiledPolicy<Fr>, secrets: &[Fr], publics: &[Fr]) -> Vec<Fr> {
        let values = eval_all(&compiled.circuit, secrets, publics);
        compiled
            .circuit
            .outputs()
            .iter()
            .map(|id| values[id.as_usize()])
            .collect()
    }

    fn root_value(compiled: &CompiledPolicy<Fr>, secrets: &[Fr], publics: &[Fr]) -> Fr {
        let values = eval_all(&compiled.circuit, secrets, publics);
        let root = *compiled.circuit.outputs().last().expect("root output");
        values[root.as_usize()]
    }

    #[test]
    fn compilation_is_deterministic() {
        let (policy, _) = threshold(2, 3);
        let a = compile_with_layout::<Fr>(&policy).expect("compiles");
        let b = compile_with_layout::<Fr>(&policy).expect("compiles");
        assert_eq!(a.circuit_id(), b.circuit_id());
        assert_eq!(a.circuit.nodes(), b.circuit.nodes());
        assert_eq!(a.secret_slots, b.secret_slots);
        assert_eq!(a.public_slots, b.public_slots);

        // compile() agrees with compile_with_layout().
        assert_eq!(
            compile::<Fr>(&policy).expect("compiles").compute_id(),
            a.circuit_id()
        );
    }

    #[test]
    fn different_policies_compile_differently() {
        let (small, _) = threshold(2, 3);
        let (large, _) = threshold(2, 4);
        assert_ne!(
            compile::<Fr>(&small).expect("compiles").compute_id(),
            compile::<Fr>(&large).expect("compiles").compute_id()
        );
    }

    #[test]
    fn threshold_holds_when_enough_credentials_match() {
        let (policy, secrets) = threshold(2, 3);
        let compiled = compile_with_layout::<Fr>(&policy).expect("compiles");
        let publics = publics_for(&compiled, &secrets, 0);

        assert_eq!(compiled.circuit.outputs().len(), 1);
        let mut wit = secrets_for(&compiled, &secrets, 0, 0, |_| false);
        solve_auxiliaries(&compiled, &mut wit, &publics);
        assert_eq!(root_value(&compiled, &wit, &publics), Fr::from(1u64));
    }

    #[test]
    fn threshold_fails_when_too_few_match() {
        let (policy, secrets) = threshold(2, 3);
        let compiled = compile_with_layout::<Fr>(&policy).expect("compiles");
        let publics = publics_for(&compiled, &secrets, 0);

        // Exactly one valid credential: below threshold, the root is
        // pinned to zero regardless of the auxiliary witnesses.
        let mut wit = secrets_for(&compiled, &secrets, 0, 0, |i| i != 0);
        solve_auxiliaries(&compiled, &mut wit, &publics);
        assert_eq!(root_value(&compiled, &wit, &publics), Fr::zero());
    }

    #[test]
    fn threshold_counts_exact_matches_only() {
        let (policy, secrets) = threshold(3, 3);
        let compiled = compile_with_layout::<Fr>(&policy).expect("compiles");
        let publics = publics_for(&compiled, &secrets, 0);

        // All three correct: exactly at threshold.
        let mut wit = secrets_for(&compiled, &secrets, 0, 0, |_| false);
        solve_auxiliaries(&compiled, &mut wit, &publics);
        assert_eq!(root_value(&compiled, &wit, &publics), Fr::from(1u64));

        // Replacing one secret with another *valid* credential's value
        // does NOT count as a second match for that slot: d_1 ≠ 0
        // there, so only two genuine matches remain — below k = 3.
        let mut wit = secrets_for(&compiled, &secrets, 0, 0, |_| false);
        for (index, slot) in compiled.secret_slots.iter().enumerate() {
            if matches!(slot, SecretSlot::Credential(i) if i == &1) {
                wit[index] = digest_to_field(&credential_commitment(&secrets[0]));
            }
        }
        solve_auxiliaries(&compiled, &mut wit, &publics);
        assert_eq!(root_value(&compiled, &wit, &publics), Fr::zero());
    }

    #[test]
    fn amount_cap_accepts_boundaries_and_rejects_above() {
        let limit = 100u64;
        let policy = Policy::AmountAtMost { limit };
        let compiled = compile_with_layout::<Fr>(&policy).expect("compiles");
        assert_eq!(compiled.range_check_outputs, 4);
        let publics = publics_for(&compiled, &[], limit);

        for (amount, accepted) in [
            (0u64, true),
            (1, true),
            (50, true),
            (99, true),
            (100, true),
            (101, false),
            (150, false),
            (u64::MAX, false),
        ] {
            let wit = secrets_for(&compiled, &[], limit, amount, |_| false);
            let outputs = output_values(&compiled, &wit, &publics);
            let constraints_hold = outputs[..compiled.range_check_outputs]
                .iter()
                .all(|v| *v == Fr::zero());
            assert_eq!(constraints_hold, accepted, "{amount}");

            // The root wire is a satisfied conjunct by construction;
            // enforcement lives entirely in the zero-constraints.
            assert_eq!(*outputs.last().expect("root"), Fr::from(1u64));
        }
    }

    #[test]
    fn forged_digit_witnesses_cannot_hide_over_limit_amounts() {
        let limit = 100u64;
        let policy = Policy::AmountAtMost { limit };
        let compiled = compile_with_layout::<Fr>(&policy).expect("compiles");
        let publics = publics_for(&compiled, &[], limit);

        // Over-limit amount with forged low difference digits: the
        // field difference is huge, so reconstruction cannot vanish.
        let amount = u64::MAX;
        let mut wit = secrets_for(&compiled, &[], limit, amount, |_| false);
        for (index, slot) in compiled.secret_slots.iter().enumerate() {
            if matches!(slot, SecretSlot::DifferenceBit(i) if *i >= 8) {
                wit[index] = Fr::zero();
            }
        }
        let outputs = output_values(&compiled, &wit, &publics);
        assert!(outputs[..compiled.range_check_outputs]
            .iter()
            .any(|v| *v != Fr::zero()));
    }

    #[test]
    fn and_requires_both_branches_or_requires_one() {
        let (thr2of3, secrets) = threshold(2, 3);

        // AND: violating the amount cap surfaces in its published
        // zero-constraints (amount caps are global assertions)…
        let and_policy = Policy::And {
            policies: vec![thr2of3.clone(), Policy::AmountAtMost { limit: 50 }],
        };
        let compiled = compile_with_layout::<Fr>(&and_policy).expect("compiles");
        let publics = publics_for(&compiled, &secrets, 50);
        let mut wit = secrets_for(&compiled, &secrets, 50, 150, |_| false);
        solve_auxiliaries(&compiled, &mut wit, &publics);
        let outputs = output_values(&compiled, &wit, &publics);
        assert!(outputs[..compiled.range_check_outputs]
            .iter()
            .any(|v| *v != Fr::zero()));

        // …and satisfying both branches leaves every output clean.
        let mut wit = secrets_for(&compiled, &secrets, 50, 40, |_| false);
        solve_auxiliaries(&compiled, &mut wit, &publics);
        let outputs = output_values(&compiled, &wit, &publics);
        assert!(outputs.iter().all(|v| *v == Fr::one() || *v == Fr::zero()));
        assert_eq!(*outputs.last().expect("root"), Fr::from(1u64));

        // OR: an amount branch that itself satisfies keeps the
        // disjunction provable even when the threshold branch is unmet.
        let (unmet_threshold, or_secrets) = threshold(3, 3);
        let or_policy = Policy::Or {
            policies: vec![unmet_threshold, Policy::AmountAtMost { limit: 10 }],
        };
        let compiled = compile_with_layout::<Fr>(&or_policy).expect("compiles");
        let publics = publics_for(&compiled, &or_secrets, 10);
        let mut wit = secrets_for(&compiled, &or_secrets, 10, 5, |i| i != 0);
        solve_auxiliaries(&compiled, &mut wit, &publics);
        let outputs = output_values(&compiled, &wit, &publics);
        assert_eq!(*outputs.last().expect("root"), Fr::from(1u64));
    }

    #[test]
    fn invalid_policies_are_rejected_at_compile_time() {
        assert_eq!(
            compile::<Fr>(&Policy::Threshold {
                k: 0,
                credentials: vec![]
            })
            .unwrap_err(),
            PolicyError::InvalidThreshold
        );
        assert_eq!(
            compile::<Fr>(&Policy::Threshold {
                k: 2,
                credentials: vec![]
            })
            .unwrap_err(),
            PolicyError::ZeroCredentials
        );
        assert_eq!(
            compile::<Fr>(&threshold(3, 2).0).unwrap_err(),
            PolicyError::ThresholdExceedsCount
        );
        assert_eq!(
            compile::<Fr>(&Policy::And { policies: vec![] }).unwrap_err(),
            PolicyError::MalformedPolicy
        );
    }

    #[test]
    fn layouts_track_declaration_order() {
        let (thr, secrets) = threshold(1, 2);
        let policy = Policy::And {
            policies: vec![Policy::AmountAtMost { limit: 5 }, thr],
        };
        let compiled = compile_with_layout::<Fr>(&policy).expect("compiles");

        assert_eq!(
            compiled.public_slots,
            vec![
                PublicSlot::AmountLimit,
                PublicSlot::CredentialCommitment(0),
                PublicSlot::CredentialCommitment(1),
            ]
        );
        let credential_count = compiled
            .secret_slots
            .iter()
            .filter(|s| matches!(s, SecretSlot::Credential(_)))
            .count();
        assert_eq!(credential_count, 2);
        assert!(compiled
            .secret_slots
            .iter()
            .any(|s| matches!(s, SecretSlot::Amount)));
        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn all_zero_secret_still_yields_exact_match() {
        // A credential whose commitment maps into the field normally:
        // the match indicator must stay exact even for degenerate
        // low-entropy secrets.
        let secret = SecretBytes::new(vec![7u8; 32]);
        let policy = Policy::Threshold {
            k: 1,
            credentials: vec![CredentialPolicy {
                expected_commitment: credential_commitment(&secret),
            }],
        };
        let compiled = compile_with_layout::<Fr>(&policy).expect("compiles");
        let publics = publics_for(&compiled, &[secret], 0);
        let mut wit = secrets_for(&compiled, &[SecretBytes::new(vec![7u8; 32])], 0, 0, |_| {
            false
        });
        solve_auxiliaries(&compiled, &mut wit, &publics);
        assert_eq!(root_value(&compiled, &wit, &publics), Fr::from(1u64));
    }
}
