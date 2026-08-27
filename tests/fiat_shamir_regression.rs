//! Fiat–Shamir regression tests (Phase 10, Prompt 3, Part B).
//!
//! Verifies the Fiat–Shamir transform binds challenges to the statement,
//! the backend, and the full commitment transcript, and that the
//! proof-layer verifier rejects a proof whose stored challenge diverges
//! from the derived one or whose backend mismatches.

use ark_ed25519::Fr;
use circuit::{Circuit, CircuitBuilder};
use crypto_core::backend::{Sha256Backend, Shake256Backend};
use mpc::PublicValue;
use mpcith::{Challenge, PartyId, RepetitionId};
use proof::fiat_shamir::{FiatShamirChallengeGenerator, FsSession};
use proof::ChallengeGenerator;
use proof::{
    NonInteractiveProof, ProofError, ProofRepetition, Prover, ProtocolConfig, Statement, Verifier,
    VerificationResult,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn harness() -> (Circuit<Fr>, Statement, Vec<Fr>, NonInteractiveProof) {
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    let c = b.constant(Fr::from(2u64));
    let t = b.add(x, c).expect("valid");
    let p = b.public_input();
    let m = b.mul(t, p).expect("valid");
    let s = b.add(m, x).expect("valid");
    b.output(s).expect("valid");
    let circuit = b.build().expect("valid");

    let statement = Statement {
        circuit_id: circuit.compute_id(),
        public_inputs: vec![PublicValue::new(Fr::from(5u64))],
        expected_outputs: vec![PublicValue::new(Fr::from(52u64))],
    };
    let witness = vec![Fr::from(7u64)];

    let mut prover = Prover::<_, Sha256Backend>::new(
        &circuit,
        &statement,
        witness,
        ChaCha20Rng::seed_from_u64(13),
        ProtocolConfig::<Sha256Backend>::default(),
    )
    .expect("prover builds");
    let proof = prover.prove(4).expect("proves");

    (circuit, statement, vec![Fr::from(7u64)], proof)
}

#[test]
fn honest_proof_verifies() {
    let (circuit, statement, _w, proof) = harness();
    assert_eq!(
        Verifier::<Sha256Backend>::new()
            .verify(&circuit, &statement, &proof)
            .expect("verify runs"),
        VerificationResult::Valid
    );
}

#[test]
fn stored_challenge_matches_fs_derivation() {
    let (_c, statement, _w, proof) = harness();
    let sessions = vec![FsSession::new(
        RepetitionId::new(0),
        proof.repetitions()[0].commitments(),
    )];
    let derived = FiatShamirChallengeGenerator::<Sha256Backend>::default()
        .derive_all(&statement, &sessions)
        .expect("derive");
    assert_eq!(
        derived[0].hidden_party,
        proof.repetitions()[0].challenge().hidden_party
    );
}

#[test]
fn challenge_depends_on_statement() {
    let (circuit, statement, _w, proof) = harness();
    let sessions = vec![FsSession::new(
        RepetitionId::new(0),
        proof.repetitions()[0].commitments(),
    )];
    let base = FiatShamirChallengeGenerator::<Sha256Backend>::default()
        .derive_all(&statement, &sessions)
        .expect("derive");

    let mut other = statement.clone();
    other.expected_outputs[0] = PublicValue::new(Fr::from(0u64));
    let changed = FiatShamirChallengeGenerator::<Sha256Backend>::default()
        .derive_all(&other, &sessions)
        .expect("derive");

    assert_ne!(base[0].hidden_party, changed[0].hidden_party);
    let _ = circuit;
}

#[test]
fn challenge_depends_on_backend() {
    let (_c, statement, _w, proof) = harness();
    let sessions = vec![FsSession::new(
        RepetitionId::new(0),
        proof.repetitions()[0].commitments(),
    )];
    // The raw FS transcript input includes the backend id, so SHA-256 and
    // SHAKE-256 produce distinct inputs (and therefore, in general,
    // distinct challenges).
    let sha_input = FiatShamirChallengeGenerator::<Sha256Backend>::default()
        .fs_input(&statement, &sessions, 0)
        .expect("fs_input");
    let shake_input = FiatShamirChallengeGenerator::<Shake256Backend>::default()
        .fs_input(&statement, &sessions, 0)
        .expect("fs_input");
    assert_ne!(sha_input, shake_input);
}

#[test]
fn tampered_challenge_is_rejected() {
    let (circuit, statement, _w, proof) = harness();
    let cur = proof.repetitions()[0].challenge().hidden_party.get();
    let flipped = PartyId::new((cur + 1) % 3).unwrap();
    let rep = proof.repetitions()[0].clone();
    let fixed = ProofRepetition::new(
        rep.commitments().to_vec(),
        Challenge {
            hidden_party: flipped,
        },
        rep.opened_views().to_vec(),
        rep.opening_randomness().to_vec(),
        rep.hidden_broadcasts().to_vec(),
        rep.hidden_output_shares().to_vec(),
    );
    let rebuilt = NonInteractiveProof::new(
        proof.version(),
        proof.protocol_id(),
        proof.backend_id(),
        statement.clone(),
        vec![fixed],
    );
    assert_eq!(
        Verifier::<Sha256Backend>::new().verify(&circuit, &statement, &rebuilt),
        Err(ProofError::ChallengeMismatch)
    );
}

#[test]
fn backend_mismatch_is_rejected() {
    let (circuit, statement, _w, proof) = harness();
    // Proof was produced under SHA-256; verifying under SHAKE-256 must fail.
    assert_eq!(
        Verifier::<Shake256Backend>::new().verify(&circuit, &statement, &proof),
        Err(ProofError::UnsupportedBackend)
    );
}
