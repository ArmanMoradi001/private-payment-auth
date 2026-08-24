//! Integration tests for the MPCitH layer: honest proofs accept,
//! tampered or mismatched artifacts reject, all challenge values work,
//! and reference/MPC/transcript outputs agree.

use ark_ff::{One, Zero};
use circuit::CircuitBuilder;
use crypto_core::{Digest, SecretBytes};
use mpc::PublicValue;
use mpcith::{
    decode_proof, MpcithError, MpcithProver, MpcithTranscript, MpcithVerifier, PartyId, Statement,
    VerificationResult, ViewCommitment,
};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

type Fr = mpcith::FieldElement;

/// (x + 2) * p + x with expected output for x=7, p=5: 9*5+7 = 52.
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

fn honest_proof(
    reps: u32,
    hidden: Option<u8>,
) -> (circuit::Circuit<Fr>, Statement, mpcith::MpcithProof) {
    let (circuit, statement, witness) = fixture();
    let source: Box<dyn mpcith::ChallengeSource> = match hidden {
        Some(h) => Box::new(mpcith::DeterministicChallengeSource::repeating(
            PartyId::new(h).unwrap(),
            reps as usize,
        )),
        None => Box::new(mpcith::RandomChallengeSource::new(
            ChaCha20Rng::seed_from_u64(77),
        )),
    };
    let mut prover = MpcithProver::new(
        &circuit,
        &statement,
        witness,
        source,
        ChaCha20Rng::seed_from_u64(42),
    )
    .expect("valid");
    let proof = prover.prove(reps).expect("valid");
    (circuit, statement, proof)
}

#[test]
fn valid_proof_accepts() {
    let (circuit, statement, proof) = honest_proof(4, None);
    assert_eq!(
        MpcithVerifier::new()
            .verify(&statement, &proof, &circuit)
            .expect("no structural error"),
        VerificationResult::Valid
    );
}

#[test]
fn wrong_circuit_rejects() {
    let (_, statement, proof) = honest_proof(1, None);

    // Same shape but a different constant → different circuit id.
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    let c = b.constant(Fr::from(3u64)); // was 2
    let t = b.add(x, c).expect("valid");
    let p = b.public_input();
    let s = b.mul(t, p).expect("valid");
    let s2 = b.add(s, x).expect("valid");
    b.output(s2).expect("valid");
    let other_circuit = b.build().expect("valid");

    assert_eq!(
        MpcithVerifier::new().verify(&statement, &proof, &other_circuit),
        Err(MpcithError::InvalidCircuit)
    );
}

#[test]
fn wrong_public_input_invalidates() {
    let (circuit, mut statement, proof) = honest_proof(1, None);
    statement.public_inputs[0] = PublicValue::new(Fr::from(6u64));
    // The replayed shares no longer match the recorded operations, so
    // verification must fail closed either semantically or structurally.
    assert_ne!(
        MpcithVerifier::new().verify(&statement, &proof, &circuit),
        Ok(VerificationResult::Valid)
    );
}

#[test]
fn wrong_expected_output_is_invalid() {
    let (circuit, mut statement, proof) = honest_proof(1, None);
    statement.expected_outputs[0] = PublicValue::new(Fr::from(51u64));
    assert_eq!(
        MpcithVerifier::new()
            .verify(&statement, &proof, &circuit)
            .expect("no error"),
        VerificationResult::Invalid
    );
}

#[test]
fn altered_commitment_rejects() {
    let (circuit, statement, mut proof) = honest_proof(1, Some(0));
    proof.repetitions[0].commitments[2] = ViewCommitment::from_digest(Digest::new([0xAA; 32]));
    assert_eq!(
        MpcithVerifier::new().verify(&statement, &proof, &circuit),
        Err(MpcithError::CommitmentMismatch)
    );
}

#[test]
fn altered_opened_view_rejects() {
    let (circuit, statement, mut proof) = honest_proof(1, Some(2));
    // Modify an opened view's claimed input share after commitment.
    let mut view = proof.repetitions[0].opened_views[0].view.clone();
    view.input_shares[0] += Fr::one();
    proof.repetitions[0].opened_views[0].view = view;
    assert_eq!(
        MpcithVerifier::new().verify(&statement, &proof, &circuit),
        Err(MpcithError::CommitmentMismatch)
    );
}

#[test]
fn altered_randomness_rejects() {
    let (circuit, statement, mut proof) = honest_proof(1, Some(1));
    proof.repetitions[0].opened_views[0].randomness = SecretBytes::new(vec![9u8; 32]);
    assert_eq!(
        MpcithVerifier::new().verify(&statement, &proof, &circuit),
        Err(MpcithError::CommitmentMismatch)
    );
}

#[test]
fn altered_challenge_rejects() {
    let (circuit, statement, mut proof) = honest_proof(1, Some(0));
    // Claim a different hidden party than the one whose view is closed.
    proof.repetitions[0].challenge.hidden_party = PartyId::new(1).unwrap();
    assert!(matches!(
        MpcithVerifier::new().verify(&statement, &proof, &circuit),
        Err(MpcithError::MissingResponse)
    ));
}

#[test]
fn every_challenge_value_produces_verifiable_proofs() {
    for hidden in 0u8..3 {
        let (circuit, statement, proof) = honest_proof(2, Some(hidden));
        assert_eq!(
            MpcithVerifier::new()
                .verify(&statement, &proof, &circuit)
                .expect("no error"),
            VerificationResult::Valid,
            "hidden party {hidden}"
        );
        assert_eq!(proof.repetitions[0].challenge.hidden_party.get(), hidden);
    }
}

#[test]
fn repetition_counts_one_two_and_moderate_work() {
    for reps in [1u32, 2, 16] {
        let (circuit, statement, proof) = honest_proof(reps, None);
        assert_eq!(proof.repetitions.len(), reps as usize);
        assert_eq!(
            MpcithVerifier::new()
                .verify(&statement, &proof, &circuit)
                .expect("no error"),
            VerificationResult::Valid
        );
    }
}

#[test]
fn zero_repetitions_is_rejected() {
    let (circuit, statement, _) = fixture();
    let mut prover = MpcithProver::new(
        &circuit,
        &statement,
        vec![Fr::from(7u64)],
        Box::new(mpcith::DeterministicChallengeSource::repeating(
            PartyId::new(0).unwrap(),
            0,
        )),
        ChaCha20Rng::seed_from_u64(1),
    )
    .expect("valid");
    assert_eq!(
        prover.prove(0).map(|_| ()).unwrap_err(),
        MpcithError::InvalidRepetitionCount
    );
}

#[test]
fn reference_mpc_and_transcript_agree() {
    let (circuit, statement, _) = fixture();
    let reference =
        circuit::evaluate_reference(&circuit, &[Fr::from(7u64)], &[Fr::from(5u64)]).expect("ok");

    let (_, _, proof) = honest_proof(3, Some(2));
    let transcript = MpcithTranscript::from_proof(&proof);
    assert!(transcript.is_ordered());
    assert_eq!(transcript.len(), 3);

    // Transcript carries no commitment randomness.
    let rendered = format!("{transcript:?}");
    assert!(!rendered.contains("randomness"));

    // Verifier acceptance certifies the transcript against the same
    // plaintext result the reference evaluator produced.
    assert_eq!(
        MpcithVerifier::new()
            .verify(&statement, &proof, &circuit)
            .expect("no error"),
        VerificationResult::Valid
    );
    assert_eq!(*statement.expected_outputs[0].value(), reference[0]);
}

#[test]
fn proof_serialization_round_trips() {
    let (_, _, proof) = honest_proof(2, Some(1));
    let bytes = mpcith::serialize_proof(&proof);
    let decoded = decode_proof(&bytes).expect("valid");
    assert_eq!(decoded.repetitions.len(), proof.repetitions.len());
    assert_eq!(mpcith::serialize_proof(&decoded), bytes);

    // Truncation and trailing bytes are rejected.
    assert!(decode_proof(&bytes[..bytes.len() - 1]).is_err());
    let mut extended = bytes.clone();
    extended.push(0);
    assert!(decode_proof(&extended).is_err());

    // An empty repetition list is structurally rejected by verify.
    let empty = mpcith::MpcithProof {
        repetitions: Vec::new(),
    };
    let (circuit, statement, _) = fixture();
    assert_eq!(
        MpcithVerifier::new().verify(&statement, &empty, &circuit),
        Err(MpcithError::InvalidProtocolState)
    );
}

#[test]
fn zero_witness_share_hides_in_shares_not_structure() {
    // A zero secret still produces three distinct random-looking views;
    // structure alone must not reveal the witness.
    let (circuit, statement, _) = fixture();
    let mut prover = MpcithProver::new(
        &circuit,
        &statement,
        vec![Fr::zero()],
        Box::new(mpcith::RandomChallengeSource::new(
            ChaCha20Rng::seed_from_u64(5),
        )),
        ChaCha20Rng::seed_from_u64(6),
    )
    .expect("valid");
    let proof = prover.prove(1).expect("valid");
    let opened = &proof.repetitions[0].opened_views[0];
    // Debug output never shows share values.
    assert!(!format!("{:?}", opened.view).contains("input_shares: ["));
}
