//! MPCitH security regression tests (Phase 10, Prompt 3, Part A).
//!
//! Proves the independent [`MpcithVerifier`] rejects forged / malformed
//! proofs: tampered commitments, tampered opened views, wrong challenges,
//! cross-repetition mixing, truncation, empty proofs, and inconsistent
//! hidden output shares.

use ark_ed25519::Fr;
use ark_ff::One;
use circuit::{Circuit, CircuitBuilder};
use mpc::PublicValue;
use mpcith::{
    Challenge, DeterministicChallengeSource, MpcithProof, MpcithProver, MpcithVerifier, PartyId,
    RepetitionId, Statement as MpcithStatement, VerificationResult,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

type Error = mpcith::MpcithError;

fn harness() -> (Circuit<Fr>, MpcithStatement, Vec<Fr>, MpcithProof) {
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

    let mut prover = MpcithProver::new(
        &circuit,
        &statement,
        witness,
        Box::new(DeterministicChallengeSource::repeating(
            PartyId::new(1).unwrap(),
            4,
        )),
        ChaCha20Rng::seed_from_u64(42),
    )
    .expect("prover builds");
    let proof = prover.prove(4).expect("proves");

    (circuit, statement, vec![Fr::from(7u64)], proof)
}

#[test]
fn honest_proof_verifies() {
    let (circuit, statement, _w, proof) = harness();
    let result = MpcithVerifier::new()
        .verify(&statement, &proof, &circuit)
        .expect("verify runs");
    assert_eq!(result, VerificationResult::Valid);
}

#[test]
fn tampered_commitment_is_rejected() {
    let (circuit, statement, _w, proof) = harness();
    let mut bad = proof.clone();
    // Pair each opened view with the wrong (other repetition's) commitment.
    bad.repetitions[0].commitments = proof.repetitions[1].commitments.clone();
    assert_eq!(
        MpcithVerifier::new().verify(&statement, &bad, &circuit),
        Err(Error::CommitmentMismatch)
    );
}

#[test]
fn tampered_opened_view_is_rejected() {
    let (circuit, statement, _w, mut proof) = harness();
    proof.repetitions[0].opened_views[0].view.input_shares[0] += Fr::one();
    // The tampered view no longer matches its stored commitment, so the
    // verifier rejects (commitment check precedes replay).
    assert!(matches!(
        MpcithVerifier::new().verify(&statement, &proof, &circuit),
        Err(Error::CommitmentMismatch) | Err(Error::InconsistentView)
    ));
}

#[test]
fn cross_repetition_view_mixing_is_rejected() {
    let (circuit, statement, _w, mut proof) = harness();
    // A view carrying the wrong repetition id must not verify.
    proof.repetitions[0].opened_views[0].view.repetition_id = RepetitionId::new(99);
    assert_eq!(
        MpcithVerifier::new().verify(&statement, &proof, &circuit),
        Err(Error::InconsistentView)
    );
}

#[test]
fn wrong_challenge_is_rejected() {
    let (circuit, statement, _w, mut proof) = harness();
    let cur = proof.repetitions[0].challenge.hidden_party.get();
    let flipped = PartyId::new((cur + 1) % 3).unwrap();
    proof.repetitions[0].challenge = Challenge {
        hidden_party: flipped,
    };
    // The opened views no longer correspond to the (flipped) hidden party.
    assert_eq!(
        MpcithVerifier::new().verify(&statement, &proof, &circuit),
        Err(Error::MissingResponse)
    );
}

#[test]
fn truncated_proof_is_rejected() {
    let (circuit, statement, _w, mut proof) = harness();
    proof.repetitions[0].opened_views.pop();
    assert_eq!(
        MpcithVerifier::new().verify(&statement, &proof, &circuit),
        Err(Error::MissingResponse)
    );
}

#[test]
fn empty_proof_is_rejected() {
    let (circuit, statement, _w, _proof) = harness();
    let empty = MpcithProof {
        repetitions: vec![],
    };
    assert_eq!(
        MpcithVerifier::new().verify(&statement, &empty, &circuit),
        Err(Error::InvalidProtocolState)
    );
}

#[test]
fn tampered_hidden_output_share_invalidates() {
    let (circuit, statement, _w, mut proof) = harness();
    if !proof.repetitions[0].hidden_output_shares.is_empty() {
        proof.repetitions[0].hidden_output_shares[0] += Fr::one();
        let result = MpcithVerifier::new()
            .verify(&statement, &proof, &circuit)
            .expect("verify runs");
        assert_eq!(result, VerificationResult::Invalid);
    }
}
