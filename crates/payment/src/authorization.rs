//! End-to-end authorization: proving and verifying payments.
//!
//! [`authorize`] compiles the policy, validates the payment against
//! the reference relation, binds the statement into the circuit
//! transcript (see [`crate::wiring`]), and produces a non-interactive
//! proof. [`verify_authorization`] independently rebuilds everything
//! public — circuit, public inputs, expected outputs — and delegates
//! to the generic Fiat–Shamir verifier. No witness material is needed
//! on the verification side.

use ark_ed25519::Fr;
use ark_ff::One;
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

/// Produces a zero-knowledge proof that `statement`'s payment is
/// authorized under `policy` by `witness`'s credentials.
///
/// The pipeline: validate against the plaintext relation → compile →
/// bind the statement into the circuit transcript → prove with
/// [`AUTHORIZATION_REPETITIONS`] repetitions.
///
/// # Errors
///
/// Any relation failure surfaces directly ([`crate::PaymentError`]
/// variants); proof-layer failures map to
/// [`PaymentError::ProofGenerationFailed`].
pub fn authorize(
    statement: &PaymentStatement,
    witness: &PrivateWitness,
    policy: &Policy,
    rng: &mut impl CryptoRngCore,
) -> Result<NonInteractiveProof, PaymentError> {
    // 1. Plaintext relation check (also validates policy shape/id).
    AuthorizationRelation::validate(statement, witness, policy)?;

    // 2. Compile and bind the statement into the transcript.
    let compiled = wiring::compile(policy)?;
    let bound_circuit = wiring::bind_statement(&compiled, statement)?;
    let (secrets, publics) = wiring::build_inputs(&compiled, policy, statement, witness)?;
    let mut publics = publics;
    publics.extend(wiring::binding_values(statement));

    // 3. Reference outputs of the bound circuit: root · b₁b₂b₃.
    let outputs = wiring::reference_outputs(&bound_circuit, &secrets, &publics)?;
    let fs_statement = Statement {
        circuit_id: bound_circuit.compute_id(),
        public_inputs: publics.iter().map(|v| PublicValue::new(*v)).collect(),
        expected_outputs: outputs.iter().map(|v| PublicValue::new(*v)).collect(),
    };

    // 4. Prove.
    let mut prover = proof::Prover::new(&bound_circuit, &fs_statement, secrets, rng)
        .map_err(|_| PaymentError::ProofGenerationFailed)?;
    prover
        .prove(AUTHORIZATION_REPETITIONS)
        .map_err(|_| PaymentError::ProofGenerationFailed)
}

/// Verifies a payment authorization proof against the statement and
/// policy.
///
/// Returns `Ok(true)` only when the proof cryptographically attests
/// the *exact* statement/policy pair supplied.
///
/// # Errors
///
/// - [`PaymentError::InvalidPolicy`] for malformed policies.
/// - [`PaymentError::PolicyIdMismatch`] when statement and policy
///   disagree.
/// - [`PaymentError::StatementMismatch`] when the proof was generated
///   for a different statement or circuit.
/// - [`PaymentError::ProofRejected`] for structurally invalid proofs.
pub fn verify_authorization(
    statement: &PaymentStatement,
    proof: &NonInteractiveProof,
    policy: &Policy,
) -> Result<bool, PaymentError> {
    policy.validate().map_err(|_| PaymentError::InvalidPolicy)?;
    if policy.policy_id() != statement.policy_id {
        return Err(PaymentError::PolicyIdMismatch);
    }

    let compiled = wiring::compile(policy)?;
    let bound_circuit = wiring::bind_statement(&compiled, statement)?;
    let circuit_id = bound_circuit.compute_id();
    if proof.statement().circuit_id != circuit_id {
        return Err(PaymentError::StatementMismatch);
    }

    // Verifier-recomputable statement: binding values are public, so
    // the expected output is exactly their product (the honest root is
    // forced to one by the relation).
    let publics = wiring::bound_public_inputs(&compiled, policy, statement)?;
    let mut binding_product = <Fr as One>::one();
    for value in wiring::binding_values(statement) {
        binding_product *= value;
    }
    let fs_statement = Statement {
        circuit_id,
        public_inputs: publics.iter().map(|v| PublicValue::new(*v)).collect(),
        expected_outputs: vec![PublicValue::new(binding_product)],
    };

    match Verifier::new().verify(&bound_circuit, &fs_statement, proof) {
        Ok(VerificationResult::Valid) => Ok(true),
        Ok(VerificationResult::Invalid) => Ok(false),
        Err(proof::ProofError::InvalidStatement) => Err(PaymentError::StatementMismatch),
        Err(_) => Err(PaymentError::ProofRejected),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_core::{Digest, SecretBytes};
    use policy::{credential_commitment, CredentialPolicy};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn fixture(n: usize) -> (Vec<SecretBytes>, Vec<CredentialPolicy>) {
        (0..n)
            .map(|i| {
                let secret = SecretBytes::new(vec![i as u8 + 1, 0x0c, 0x0d]);
                (
                    secret.clone(),
                    CredentialPolicy {
                        expected_commitment: credential_commitment(&secret),
                    },
                )
            })
            .unzip()
    }

    fn sample_statement(policy_id: policy::PolicyId, amount: u64) -> PaymentStatement {
        PaymentStatement {
            payment_id: Digest::new([5u8; 32]),
            amount: crate::amount::Amount {
                value: amount,
                unit: crate::amount::AmountUnit::Cents,
            },
            recipient_commitment: Digest::new([0xcd; 32]),
            policy_id,
            circuit_id: circuit::CircuitId::from_digest(Digest::new([0; 32])),
            protocol_version: proof::PROTOCOL_VERSION,
            nonce: [0u8; crate::payment::NONCE_LEN],
        }
    }

    #[test]
    fn authorize_and_verify_round_trip() {
        let (secrets, credentials) = fixture(3);
        let policy = Policy::And {
            policies: vec![
                Policy::Threshold { k: 2, credentials },
                Policy::AmountAtMost { limit: 100 },
            ],
        };
        let statement = sample_statement(policy.policy_id(), 42);
        let witness = PrivateWitness {
            credential_secrets: secrets,
        };
        let mut rng = ChaCha20Rng::seed_from_u64(7);

        let proof =
            authorize(&statement, &witness, &policy, &mut rng).expect("authorization proves");
        assert_eq!(verify_authorization(&statement, &proof, &policy), Ok(true));
    }
}
