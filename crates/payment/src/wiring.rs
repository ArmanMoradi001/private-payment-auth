//! Field-element wiring between payment data and compiled circuits.
//!
//! Converts statements and witnesses into the secret/public input
//! vectors the compiled [`policy::CompiledPolicy`] circuits consume. The
//! policy crate owns witness construction (`build_inputs`); this module
//! adds the payment-binding leaves and reconciles types with the
//! payment [`PrivateWitness`].

use ark_ed25519::Fr;
use ark_ff::PrimeField;
use circuit::{evaluate_reference, Circuit, NodeId};
use policy::{compile_with_layout, Policy, PublicSlot};

use crate::error::PaymentError;
use crate::statement::PaymentStatement;
use crate::witness::PrivateWitness;

/// Compiles `policy`, mapping compilation failures onto
/// [`PaymentError::InvalidPolicy`].
pub(crate) fn compile(policy: &Policy) -> Result<policy::CompiledPolicy<Fr>, PaymentError> {
    compile_with_layout::<Fr>(policy).map_err(|_| PaymentError::InvalidPolicy)
}

/// Reads a digest as the canonical field element used for commitments.
pub(crate) fn digest_to_field(digest: &crypto_core::Digest) -> Fr {
    Fr::from_le_bytes_mod_order(digest.as_bytes())
}

/// The four public binding values tying a proof to its
/// [`PaymentStatement`]: amount, recipient commitment, nonce, and
/// payment id. They appear as extra public inputs multiplied into the
/// circuit's root, so the Fiat–Shamir transcript (which hashes the full
/// public input vector) commits to the exact payment being authorized.
pub(crate) fn binding_values(statement: &PaymentStatement) -> [Fr; 4] {
    [
        Fr::from(statement.amount.value),
        digest_to_field(&statement.recipient_commitment),
        digest_to_field(&crypto_core::Digest::new(statement.nonce)),
        digest_to_field(&statement.payment_id),
    ]
}

/// Extends a compiled policy circuit with [`binding_values`] leaves
/// multiplied into the root wire.
///
/// The resulting circuit has one output computing
/// `root_policy · b₁·b₂·b₃·b₄`. Its reference value is fully determined
/// by public data, which lets verifiers reconstruct the expected
/// outputs without any witness.
///
/// # Errors
///
/// Returns [`PaymentError::InvalidPolicy`] if the extended circuit fails
/// validation (an internal invariant).
pub(crate) fn bind_statement(
    compiled: &policy::CompiledPolicy<Fr>,
) -> Result<Circuit<Fr>, PaymentError> {
    use circuit::Node;

    let base = &compiled.circuit;
    let mut nodes: Vec<Node<Fr>> = base.nodes().to_vec();
    let num_secret = base.num_secret_inputs();
    let num_public = base.num_public_inputs();

    const BINDING_SLOTS: usize = 4;
    let leaves: Vec<NodeId> = (0..BINDING_SLOTS)
        .map(|_| {
            let id = NodeId::new(nodes.len() as u32);
            nodes.push(Node::PublicInput);
            id
        })
        .collect();
    let product = leaves.into_iter().reduce(|a, b| {
        let id = NodeId::new(nodes.len() as u32);
        nodes.push(Node::Mul(a, b));
        id
    });
    let binding_product = product.ok_or(PaymentError::InvalidPolicy)?;

    let old_root = *base.outputs().last().ok_or(PaymentError::InvalidPolicy)?;
    let final_node = NodeId::new(nodes.len() as u32);
    nodes.push(Node::Mul(old_root, binding_product));

    let mut outputs = base.outputs().to_vec();
    *outputs.last_mut().ok_or(PaymentError::InvalidPolicy)? = final_node;

    let bound = Circuit::new(nodes, num_secret, num_public + BINDING_SLOTS, outputs);
    bound.validate().map_err(|_| PaymentError::InvalidPolicy)?;
    Ok(bound)
}

/// Builds the public input vector for the bound circuit: the policy
/// slots followed by the statement binding values.
pub(crate) fn bound_public_inputs(
    compiled: &policy::CompiledPolicy<Fr>,
    policy: &Policy,
    statement: &PaymentStatement,
) -> Result<Vec<Fr>, PaymentError> {
    let mut publics = policy_public_inputs(compiled, policy)?;
    publics.extend(binding_values(statement));
    Ok(publics)
}

/// Builds the public input vector for the unbound policy circuit,
/// recomputed from `policy` (no witness needed).
///
/// The compiled circuit's public slots follow the *normalized* policy
/// traversal, so the credential ids and amount limits are collected from
/// the normalized policy to stay aligned with the prover's witness order.
pub(crate) fn policy_public_inputs(
    compiled: &policy::CompiledPolicy<Fr>,
    policy: &Policy,
) -> Result<Vec<Fr>, PaymentError> {
    let normalized = policy
        .normalize()
        .map_err(|_| PaymentError::InvalidPolicy)?;
    let ids = super::witness::policy_credential_ids(&normalized);
    let limits = limits_of(&normalized);

    let mut publics = Vec::with_capacity(compiled.public_slots.len());
    let mut next_credential = 0usize;
    let mut next_limit = 0usize;
    for slot in &compiled.public_slots {
        match slot {
            PublicSlot::CredentialCommitment(_) => {
                let id = ids
                    .get(next_credential)
                    .copied()
                    .ok_or(PaymentError::InvalidPolicy)?;
                next_credential += 1;
                publics.push(digest_to_field(&crypto_core::Digest::new(*id.as_bytes())));
            }
            PublicSlot::AmountLimit => {
                let limit = limits
                    .get(next_limit)
                    .copied()
                    .ok_or(PaymentError::InvalidPolicy)?;
                next_limit += 1;
                publics.push(Fr::from(limit));
            }
        }
    }
    Ok(publics)
}

/// Builds both input vectors for `statement`/`witness` under the
/// compiled `policy` circuit.
///
/// # Errors
///
/// Returns [`PaymentError::WitnessCountMismatch`] if the witness does
/// not cover the policy's credentials and [`PaymentError::InvalidPolicy`]
/// if compilation fails.
pub(crate) fn build_inputs(
    compiled: &policy::CompiledPolicy<Fr>,
    policy: &Policy,
    witness: &PrivateWitness,
) -> Result<(Vec<Fr>, Vec<Fr>), PaymentError> {
    let policy_witness = witness.to_policy_witness(policy)?;
    compiled
        .build_inputs(policy, &policy_witness)
        .map_err(|_| PaymentError::InvalidPolicy)
}

fn limits_of(policy: &Policy) -> Vec<u64> {
    fn walk(policy: &Policy, out: &mut Vec<u64>) {
        match policy {
            Policy::AmountAtMost(limit) => out.push(limit.value()),
            Policy::Credential(_) => {}
            Policy::Threshold { members, .. } => {
                for sub in members {
                    walk(sub, out);
                }
            }
            Policy::And(policies) | Policy::Or(policies) => {
                for sub in policies {
                    walk(sub, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(policy, &mut out);
    out
}

/// Convenience wrapper returning the reference evaluation outputs.
pub(crate) fn reference_outputs(
    circuit: &Circuit<Fr>,
    secrets: &[Fr],
    publics: &[Fr],
) -> Result<Vec<Fr>, PaymentError> {
    evaluate_reference(circuit, secrets, publics).map_err(|_| PaymentError::InvalidPolicy)
}
