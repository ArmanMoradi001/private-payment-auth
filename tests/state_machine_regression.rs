//! State-machine / protocol-flow regression tests (Phase 10, Prompt 3,
//! Part C).
//!
//! Exercises the interactive MPCitH prover's ordered API
//! (`commit_phase` → `finish_repetition`) and its error paths. The public
//! API structurally prevents "respond before commit": a `Repetition` can
//! only be produced by `finish_repetition`, which requires a
//! `PartialRepetition` obtainable solely via `commit_phase` (the lower
//! `commit_repetition` helper is private). The atomic `prove` /
//! `prove_with` / `prove_joint_fs` drivers enforce the same ordering.

use ark_ed25519::Fr;
use circuit::{Circuit, CircuitBuilder};
use mpc::PublicValue;
use mpcith::{
    Challenge, DeterministicChallengeSource, MpcithError, MpcithProof, MpcithProver,
    MpcithVerifier, PartyId, Statement as MpcithStatement, VerificationResult,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn fixture() -> (Circuit<Fr>, MpcithStatement, Vec<Fr>) {
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    let c = b.constant(Fr::from(2u64));
    let t = b.add(x, c).expect("valid");
    let p = b.public_input();
    let m = b.mul(t, p).expect("valid");
    let s = b.add(m, x).expect("valid");
    b.output(s).expect("valid");
    let circuit = b.build().expect("valid");

    let statement = MpcithStatement {
        circuit_id: circuit.compute_id(),
        public_inputs: vec![PublicValue::new(Fr::from(5u64))],
        expected_outputs: vec![PublicValue::new(Fr::from(52u64))],
    };
    let witness = vec![Fr::from(7u64)];
    (circuit, statement, witness)
}

fn new_prover<'a>(
    circuit: &'a Circuit<Fr>,
    statement: &'a MpcithStatement,
    witness: Vec<Fr>,
) -> MpcithProver<'a, ChaCha20Rng> {
    MpcithProver::new(
        circuit,
        statement,
        witness,
        Box::new(DeterministicChallengeSource::default()) as Box<dyn mpcith::ChallengeSource>,
        ChaCha20Rng::seed_from_u64(7),
    )
    .expect("prover builds")
}

#[test]
fn commit_phase_zero_repetitions_is_rejected() {
    let (circuit, statement, witness) = fixture();
    let mut prover = new_prover(&circuit, &statement, witness);
    assert!(matches!(
        prover.commit_phase(0),
        Err(MpcithError::InvalidRepetitionCount)
    ));
}

#[test]
fn prove_zero_repetitions_is_rejected() {
    let (circuit, statement, witness) = fixture();
    let mut prover = new_prover(&circuit, &statement, witness);
    assert!(matches!(
        prover.prove(0),
        Err(MpcithError::InvalidRepetitionCount)
    ));
}

#[test]
fn challenge_source_failure_propagates() {
    let (circuit, statement, witness) = fixture();
    let mut prover = new_prover(&circuit, &statement, witness);
    let result = prover.prove_with(2, |_, _| Err(MpcithError::InvalidChallenge));
    assert!(matches!(result, Err(MpcithError::InvalidChallenge)));
}

#[test]
fn joint_fs_wrong_challenge_count_is_rejected() {
    let (circuit, statement, witness) = fixture();
    let mut prover = new_prover(&circuit, &statement, witness);
    // Return fewer challenges than repetitions.
    let result = prover.prove_joint_fs(3, |_sessions| Ok(vec![]));
    assert!(matches!(result, Err(MpcithError::InvalidProtocolState)));
}

#[test]
fn witness_length_mismatch_is_rejected() {
    let (circuit, statement, _witness) = fixture();
    let prover = MpcithProver::new(
        &circuit,
        &statement,
        vec![], // wrong length (circuit has one secret input)
        Box::new(DeterministicChallengeSource::default()),
        ChaCha20Rng::seed_from_u64(7),
    );
    assert!(matches!(prover, Err(MpcithError::InvalidStatement)));
}

#[test]
fn ordered_commit_then_finish_produces_valid_proof() {
    let (circuit, statement, witness) = fixture();
    let mut prover = new_prover(&circuit, &statement, witness);
    let partials = prover.commit_phase(3).expect("commit phase");

    // Explicitly drive the challenge/response ordering the API enforces.
    let mut repetitions = Vec::with_capacity(partials.len());
    for (i, partial) in partials.iter().enumerate() {
        let hidden = PartyId::new((i % 3) as u8).unwrap();
        let challenge = Challenge {
            hidden_party: hidden,
        };
        repetitions.push(
            prover
                .finish_repetition(partial, challenge)
                .expect("finish"),
        );
    }
    let proof = MpcithProof { repetitions };

    let result = MpcithVerifier::new()
        .verify(&statement, &proof, &circuit)
        .expect("verify runs");
    assert_eq!(result, VerificationResult::Valid);
}
