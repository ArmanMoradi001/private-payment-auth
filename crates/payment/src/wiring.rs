//! Field-element wiring between payment data and compiled circuits.
//!
//! Converts statements and witnesses into the secret/public input
//! vectors the compiled [`policy::CompiledPolicy`] circuits consume,
//! including solving the auxiliary inversion witnesses described in
//! `policy::compiler`.

use ark_ed25519::Fr;
use ark_ff::{Field, One, PrimeField, Zero};
use circuit::{evaluate_reference, Circuit, NodeId};
use policy::{compile_with_layout, credential_commitment, CompiledPolicy, PublicSlot, SecretSlot};

use crate::error::PaymentError;
use crate::statement::PaymentStatement;
use crate::witness::PrivateWitness;

/// Compiles `policy`, mapping compilation failures onto
/// [`PaymentError::InvalidPolicy`].
pub(crate) fn compile(policy: &policy::Policy) -> Result<CompiledPolicy<Fr>, PaymentError> {
    compile_with_layout::<Fr>(policy).map_err(|_| PaymentError::InvalidPolicy)
}

/// Reads a digest as the canonical field element used for credential
/// commitments and secrets alike.
pub(crate) fn digest_to_field(digest: &crypto_core::Digest) -> Fr {
    Fr::from_le_bytes_mod_order(digest.as_bytes())
}

/// The three public binding values tying a proof to its
/// [`PaymentStatement`]: amount, recipient commitment, payment id.
///
/// They appear as extra public inputs multiplied into the circuit's
/// root, so the Fiat–Shamir transcript (which hashes the full public
/// input vector) commits to the exact payment being authorized.
pub(crate) fn binding_values(statement: &PaymentStatement) -> [Fr; 3] {
    [
        Fr::from(statement.amount.value),
        digest_to_field(&statement.recipient_commitment),
        digest_to_field(&statement.payment_id),
    ]
}

/// Extends a compiled policy circuit with [`binding_values`] leaves
/// multiplied into the root wire.
///
/// The resulting circuit has one output computing
/// `root_policy · b₁·b₂·b₃`. Its reference value is fully determined
/// by public data, which lets verifiers reconstruct the expected
/// outputs without any witness.
///
/// # Errors
///
/// Returns [`PaymentError::InvalidPolicy`] if the extended circuit
/// fails validation (an internal invariant).
pub(crate) fn bind_statement(
    compiled: &CompiledPolicy<Fr>,
    _statement: &PaymentStatement,
) -> Result<circuit::Circuit<Fr>, PaymentError> {
    use circuit::Node;

    let base = &compiled.circuit;
    let mut nodes: Vec<Node<Fr>> = base.nodes().to_vec();
    let num_secret = base.num_secret_inputs();
    let num_public = base.num_public_inputs();

    // Binding public leaves.
    let leaves: Vec<NodeId> = (0..3)
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

    // Multiply the binding product into the root wire.
    let old_root = *base.outputs().first().ok_or(PaymentError::InvalidPolicy)?;
    let final_node = NodeId::new(nodes.len() as u32);
    nodes.push(Node::Mul(old_root, binding_product));

    let bound = circuit::Circuit::new(nodes, num_secret, num_public + 3, vec![final_node]);
    bound.validate().map_err(|_| PaymentError::InvalidPolicy)?;
    Ok(bound)
}

/// Builds the public input vector for the bound circuit: the policy
/// slots followed by the statement binding values.
pub(crate) fn bound_public_inputs(
    compiled: &CompiledPolicy<Fr>,
    policy: &policy::Policy,
    statement: &PaymentStatement,
) -> Result<Vec<Fr>, PaymentError> {
    let mut publics = policy_public_inputs(compiled, policy)?;
    publics.extend(binding_values(statement));
    Ok(publics)
}

/// Builds the public input vector for the unbound policy circuit.
pub(crate) fn policy_public_inputs(
    compiled: &CompiledPolicy<Fr>,
    policy: &policy::Policy,
) -> Result<Vec<Fr>, PaymentError> {
    let mut commitments = Vec::new();
    let mut limits = Vec::new();
    gather_policy_data(policy, &mut commitments, &mut limits);

    let mut publics = Vec::with_capacity(compiled.public_slots.len());
    let mut next_limit = 0usize;
    for slot in &compiled.public_slots {
        match slot {
            PublicSlot::CredentialCommitment(i) => {
                let digest = commitments
                    .get(*i)
                    .copied()
                    .ok_or(PaymentError::InvalidPolicy)?;
                publics.push(digest_to_field(&digest));
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
/// compiled `policy` circuit, solving auxiliary witnesses so every
/// constraint wire reaches its forced value (`1` when satisfied).
///
/// # Errors
///
/// Returns [`PaymentError::WitnessCountMismatch`] if the witness does
/// not cover the policy's credentials and
/// [`PaymentError::InvalidPolicy`] if the layout is inconsistent.
pub(crate) fn build_inputs(
    compiled: &CompiledPolicy<Fr>,
    policy: &policy::Policy,
    statement: &PaymentStatement,
    witness: &PrivateWitness,
) -> Result<(Vec<Fr>, Vec<Fr>), PaymentError> {
    let publics = policy_public_inputs(compiled, policy)?;

    let mut secrets = Vec::with_capacity(compiled.secret_slots.len());
    let mut aux_positions = Vec::new();
    let mut next_credential = 0usize;
    for (index, slot) in compiled.secret_slots.iter().enumerate() {
        match slot {
            SecretSlot::Credential(_) => {
                let secret = witness
                    .credential_secrets
                    .get(next_credential)
                    .ok_or(PaymentError::WitnessCountMismatch)?;
                next_credential += 1;
                // The circuit compares field readings of commitment
                // digests; hashing happens here so an honest witness
                // always matches its expected commitment.
                secrets.push(digest_to_field(&credential_commitment(secret)));
            }
            SecretSlot::Amount => secrets.push(Fr::from(statement.amount.value)),
            SecretSlot::Auxiliary => {
                aux_positions.push(index);
                secrets.push(Fr::zero());
            }
        }
    }

    solve_auxiliaries(
        &compiled.circuit,
        &mut secrets,
        &publics,
        &aux_positions,
        compiled.auxiliary_targets(),
    );
    Ok((secrets, publics))
}

fn gather_policy_data(
    policy: &policy::Policy,
    commitments: &mut Vec<crypto_core::Digest>,
    limits: &mut Vec<u64>,
) {
    use policy::Policy;
    match policy {
        Policy::Threshold { credentials, .. } => {
            for credential in credentials {
                commitments.push(credential.expected_commitment);
            }
        }
        Policy::AmountAtMost { limit } => limits.push(*limit),
        Policy::And { policies } | Policy::Or { policies } => {
            for sub in policies {
                gather_policy_data(sub, commitments, limits);
            }
        }
    }
}

/// Solves each auxiliary slot as the inverse of its target wire (zero
/// when that wire is zero). Two sweeps suffice: discriminant wires do
/// not depend on auxiliary values except through earlier slots.
pub(crate) fn solve_auxiliaries(
    circuit: &Circuit<Fr>,
    secrets: &mut [Fr],
    publics: &[Fr],
    aux_positions: &[usize],
    targets: &[NodeId],
) {
    for _ in 0..3 {
        let values = eval_all(circuit, secrets, publics);
        let mut changed = false;
        for (&position, target) in aux_positions.iter().zip(targets) {
            let desired =
                <Fr as Field>::inverse(&values[target.as_usize()]).unwrap_or_else(Fr::zero);
            if secrets[position] != desired {
                secrets[position] = desired;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
}

/// Full-wire evaluation mirroring `circuit::eval_reference`.
pub(crate) fn eval_all(circuit: &Circuit<Fr>, secrets: &[Fr], publics: &[Fr]) -> Vec<Fr> {
    let mut values = Vec::with_capacity(circuit.nodes().len());
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
    values
}

/// Convenience wrapper returning the reference evaluation outputs.
pub(crate) fn reference_outputs(
    circuit: &Circuit<Fr>,
    secrets: &[Fr],
    publics: &[Fr],
) -> Result<Vec<Fr>, PaymentError> {
    evaluate_reference(circuit, secrets, publics).map_err(|_| PaymentError::InvalidPolicy)
}

/// The field element representing “constraint satisfied”.
pub(crate) fn satisfied() -> Fr {
    <Fr as One>::one()
}
