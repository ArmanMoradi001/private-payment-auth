//! End-to-end authorization: proving and verifying payments.
//!
//! [`authorize_payment`] compiles the policy, validates the payment
//! against the reference relation (including the plaintext range
//! check), binds the statement into the circuit transcript, and
//! produces a non-interactive proof carrying the payer's binary digit
//! witnesses. [`verify_payment_authorization`] independently rebuilds
//! everything public — circuit, public inputs, expected outputs — and
//! delegates to the generic Fiat–Shamir verifier. No witness material
//! is needed on the verification side.

use ark_ed25519::Fr;
use ark_ff::{One, Zero};
use mpc::PublicValue;
use policy::Policy;
use proof::{NonInteractiveProof, Statement, VerificationResult, Verifier};
use rand_core::CryptoRngCore;

use crate::error::PaymentError;
use crate::relation::AuthorizationRelation;
use crate::statement::PaymentStatement;
use crate::wiring;
use crate::witness::PrivateWitness;

/// MPCitH repetitions used for payment authorizations in this phase.
///
/// Soundness degrades as `(1/3)^repetitions`; production parameters
/// are deferred until the cost/parameter study phase.
pub const AUTHORIZATION_REPETITIONS: u32 = 12;

/// The circuit id a statement for `policy` must carry: the compiled
/// policy circuit with the four payment-binding leaves appended.
///
/// # Errors
///
/// Returns [`PaymentError::InvalidPolicy`] if compilation fails.
pub fn payment_circuit_id(policy: &Policy) -> Result<circuit::CircuitId, PaymentError> {
    let compiled = wiring::compile(policy)?;
    let bound = wiring::bind_statement(&compiled)?;
    Ok(bound.compute_id())
}

/// Produces a zero-knowledge proof that `statement`'s payment is
/// authorized under `policy` by `witness`.
///
/// The pipeline: validate against the plaintext relation (identity,
/// witness shape, range check, policy tree) → compile → bind the
/// statement into the circuit transcript → prove with
/// [`AUTHORIZATION_REPETITIONS`] repetitions.
///
/// # Errors
///
/// Any relation failure surfaces directly ([`crate::PaymentError`]
/// variants); a statement bound to a different circuit or protocol
/// version yields [`PaymentError::StatementMismatch`]; proof-layer
/// failures map to [`PaymentError::ProofGenerationFailed`].
pub fn authorize_payment(
    statement: &PaymentStatement,
    witness: &PrivateWitness,
    policy: &Policy,
    rng: &mut impl CryptoRngCore,
) -> Result<NonInteractiveProof, PaymentError> {
    // 0. Statement bindings must name this pipeline.
    check_statement_binding(statement, policy)?;

    // 1. Plaintext relation check.
    AuthorizationRelation::validate(statement, witness, policy)?;

    // 2. Compile and bind the statement into the transcript.
    let compiled = wiring::compile(policy)?;
    let bound_circuit = wiring::bind_statement(&compiled)?;
    let (secrets, mut publics) = wiring::build_inputs(&compiled, policy, witness)?;
    publics.extend(wiring::binding_values(statement));

    // 3. Reference outputs of the bound circuit: zeros for every
    //    range-check constraint, then root · b₁b₂b₃b₄ for the root.
    let outputs = wiring::reference_outputs(&bound_circuit, &secrets, &publics)?;
    let fs_statement = Statement {
        circuit_id: bound_circuit.compute_id(),
        public_inputs: publics.iter().map(|v| PublicValue::new(*v)).collect(),
        expected_outputs: outputs.iter().map(|v| PublicValue::new(*v)).collect(),
    };

    // 4. Prove.
    let mut prover = proof::Prover::new(
        &bound_circuit,
        &fs_statement,
        secrets,
        rng,
        proof::ProtocolConfig::<crypto_core::Sha256Backend>::default(),
    )
    .map_err(|_| PaymentError::ProofGenerationFailed)?;
    prover
        .prove(AUTHORIZATION_REPETITIONS)
        .map_err(|_| PaymentError::ProofGenerationFailed)
}

/// Verifies a payment authorization proof against the statement and
/// policy.
///
/// Returns `Ok(true)` only when the proof cryptographically attests
/// the exact statement/policy pair supplied: same circuit id, same
/// public inputs (including amount, recipient, nonce, and payment id),
/// all range-check constraints zero, and the bound root output equal
/// to the binding product.
///
/// # Errors
///
/// - [`PaymentError::InvalidPolicy`] for malformed policies.
/// - [`PaymentError::PolicyIdMismatch`] when statement and policy
///   disagree.
/// - [`PaymentError::StatementMismatch`] when the proof was generated
///   for a different statement or circuit.
/// - [`PaymentError::ProofRejected`] for structurally invalid proofs.
pub fn verify_payment_authorization(
    statement: &PaymentStatement,
    proof: &NonInteractiveProof,
    policy: &Policy,
) -> Result<bool, PaymentError> {
    check_statement_binding(statement, policy)?;

    let compiled = wiring::compile(policy)?;
    let bound_circuit = wiring::bind_statement(&compiled)?;
    let circuit_id = bound_circuit.compute_id();
    if proof.statement().circuit_id != circuit_id {
        return Err(PaymentError::StatementMismatch);
    }

    // Verifier-recomputable statement: binding values are public, so
    // the expected outputs are exactly the all-zero range-check
    // constraints plus the binding product on the root wire.
    let publics = wiring::bound_public_inputs(&compiled, policy, statement)?;
    let mut binding_product = <Fr as One>::one();
    for value in wiring::binding_values(statement) {
        binding_product *= value;
    }
    let mut expected_outputs =
        vec![PublicValue::new(<Fr as Zero>::zero()); compiled.range_check_outputs];
    expected_outputs.push(PublicValue::new(binding_product));
    let fs_statement = Statement {
        circuit_id,
        public_inputs: publics.iter().map(|v| PublicValue::new(*v)).collect(),
        expected_outputs,
    };

    match Verifier::<crypto_core::Sha256Backend>::new().verify(&bound_circuit, &fs_statement, proof)
    {
        Ok(VerificationResult::Valid) => Ok(true),
        Ok(VerificationResult::Invalid) => Ok(false),
        Err(proof::ProofError::InvalidStatement) => Err(PaymentError::StatementMismatch),
        Err(_) => Err(PaymentError::ProofRejected),
    }
}

/// Rejects statements whose circuit or protocol bindings cannot match
/// this pipeline.
fn check_statement_binding(
    statement: &PaymentStatement,
    policy: &Policy,
) -> Result<(), PaymentError> {
    if statement.protocol_version != proof::PROTOCOL_VERSION {
        return Err(PaymentError::StatementMismatch);
    }
    if policy.policy_id() != statement.policy_id {
        return Err(PaymentError::PolicyIdMismatch);
    }
    if payment_circuit_id(policy)? != statement.circuit_id {
        return Err(PaymentError::StatementMismatch);
    }
    Ok(())
}
