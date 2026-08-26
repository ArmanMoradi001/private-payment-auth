//! Adversarial tests for cryptographic backend binding.
//!
//! A proof is bound to the backend that produced it via `proof.backend_id()`.
//! A verifier pinned to a *different* backend must reject the proof, and a
//! proof carrying an unknown `backend_id` (e.g. produced by tampering with
//! the serialized encoding) must be rejected as `UnsupportedBackend`. This
//! is the property that prevents cross-backend forgery: an adversary cannot
//! present a SHAKE256 proof to a SHA-256 verifier or relabel a proof's
//! backend after the fact.

use circuit::CircuitBuilder;
use crypto_core::backend::{BackendId, CryptoBackend, Sha256Backend, Shake256Backend};
use mpc::PublicValue;
use mpcith::FieldElement;
use proof::{NonInteractiveProof, ProofError, ProtocolConfig, Prover, Statement, Verifier};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

type Fr = FieldElement;

fn fixture() -> (circuit::Circuit<Fr>, Statement, Vec<Fr>) {
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    let c = b.constant(Fr::from(2u64));
    let t = b.add(x, c).expect("valid");
    let p = b.public_input();
    let s = b.mul(t, p).expect("valid");
    let s2 = b.add(s, x).expect("valid");
    b.output(s2).expect("valid");
    let circuit = b.build().expect("valid");

    let statement = Statement {
        circuit_id: circuit.compute_id(),
        public_inputs: vec![PublicValue::new(Fr::from(5u64))],
        expected_outputs: vec![PublicValue::new(Fr::from(52u64))],
    };
    (circuit, statement, vec![Fr::from(7u64)])
}

fn prove_with<B: CryptoBackend>(
    reps: u32,
) -> (circuit::Circuit<Fr>, Statement, NonInteractiveProof) {
    let (circuit, statement, witness) = fixture();
    let mut prover = Prover::new(
        &circuit,
        &statement,
        witness,
        ChaCha20Rng::seed_from_u64(99),
        ProtocolConfig::<B>::default(),
    )
    .expect("prover construction");
    let proof = prover.prove(reps).expect("honest proof");
    (circuit, statement, proof)
}

#[test]
fn sha256_proof_is_rejected_by_shake256_verifier() {
    let (circuit, statement, proof) = prove_with::<Sha256Backend>(8);
    assert_eq!(proof.backend_id(), Sha256Backend::ID);

    let result = Verifier::<Shake256Backend>::new().verify(&circuit, &statement, &proof);
    assert!(
        matches!(result, Err(ProofError::UnsupportedBackend)),
        "cross-backend proof must be rejected, got {result:?}"
    );
}

#[test]
fn shake256_proof_is_rejected_by_sha256_verifier() {
    let (circuit, statement, proof) = prove_with::<Shake256Backend>(8);
    assert_eq!(proof.backend_id(), Shake256Backend::ID);

    let result = Verifier::<Sha256Backend>::new().verify(&circuit, &statement, &proof);
    assert!(
        matches!(result, Err(ProofError::UnsupportedBackend)),
        "cross-backend proof must be rejected, got {result:?}"
    );
}

#[test]
fn matching_backend_accepts_proof() {
    for reps in [1u32, 4, 12] {
        let (circuit, statement, proof) = prove_with::<Sha256Backend>(reps);
        assert_eq!(
            Verifier::<Sha256Backend>::new()
                .verify(&circuit, &statement, &proof)
                .expect("verify"),
            proof::VerificationResult::Valid
        );

        let (circuit, statement, proof) = prove_with::<Shake256Backend>(reps);
        assert_eq!(
            Verifier::<Shake256Backend>::new()
                .verify(&circuit, &statement, &proof)
                .expect("verify"),
            proof::VerificationResult::Valid
        );
    }
}

#[test]
fn tampered_backend_id_is_rejected() {
    let (circuit, statement, valid) = prove_with::<Sha256Backend>(4);
    let tampered = NonInteractiveProof::new(
        valid.version(),
        valid.protocol_id(),
        BackendId::new([0xff; 16]),
        valid.statement().clone(),
        valid.repetitions().to_vec(),
    );

    let result = Verifier::<Sha256Backend>::new().verify(&circuit, &statement, &tampered);
    assert!(
        matches!(result, Err(ProofError::UnsupportedBackend)),
        "unknown backend id must be rejected, got {result:?}"
    );
}

#[test]
fn empty_or_unknown_backend_id_always_rejected() {
    let (circuit, statement, valid) = prove_with::<Sha256Backend>(4);
    for bad_id in [
        BackendId::new([0u8; 16]),
        BackendId::new(*b"unknown-backend!"),
    ] {
        let tampered = NonInteractiveProof::new(
            valid.version(),
            valid.protocol_id(),
            bad_id,
            valid.statement().clone(),
            valid.repetitions().to_vec(),
        );
        assert!(
            matches!(
                Verifier::<Sha256Backend>::new().verify(&circuit, &statement, &tampered),
                Err(ProofError::UnsupportedBackend)
            ),
            "bad id {bad_id:?} must be rejected"
        );
    }
}
