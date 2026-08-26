//! Integration tests: proof generation/verification, FS mutation
//! sensitivity, adversarial tampering, and circuit/statement binding.

use ark_ff::{One, Zero};
use circuit::CircuitBuilder;
use crypto_core::{Digest, HashFunction as _};
use mpc::PublicValue;
use mpcith::{FieldElement, PartyId, ViewCommitment};
use proof::{
    deserialize_proof, NonInteractiveProof, ProofError, ProofRepetition, ProtocolConfig, Prover,
    Statement, VerificationResult, Verifier,
};
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

fn honest_proof(reps: u32) -> (circuit::Circuit<Fr>, Statement, NonInteractiveProof) {
    let (circuit, statement, witness) = fixture();
    let mut prover = Prover::new(
        &circuit,
        &statement,
        witness,
        ChaCha20Rng::seed_from_u64(99),
        ProtocolConfig::<crypto_core::Sha256Backend>::default(),
    )
    .unwrap();
    let proof = prover.prove(reps).expect("valid");
    (circuit, statement, proof)
}

#[test]
fn valid_proof_verifies() {
    for reps in [1u32, 2, 8] {
        let (circuit, statement, proof) = honest_proof(reps);
        assert_eq!(
            Verifier::<crypto_core::Sha256Backend>::new()
                .verify(&circuit, &statement, &proof)
                .expect("no error"),
            VerificationResult::Valid,
            "reps={reps}"
        );
    }
}

#[test]
fn fs_challenge_mutations_change_derivation() {
    use proof::{ChallengeGenerator as _, FiatShamirChallengeGenerator, FsSession};
    let gen = FiatShamirChallengeGenerator::<crypto_core::Sha256Backend>::default();
    let (_circuit, statement, _) = fixture();
    let (_, _, proof) = honest_proof(2);

    fn make_sessions(p: &NonInteractiveProof) -> Vec<FsSession<'_>> {
        p.repetitions()
            .iter()
            .enumerate()
            .map(|(i, rep)| FsSession::new(mpcith::RepetitionId::new(i as u32), rep.commitments()))
            .collect()
    }

    let base_digests: Vec<_> = {
        let sessions = make_sessions(&proof);
        (0..sessions.len())
            .map(|r| gen.fs_digest(&statement, &sessions, r).unwrap())
            .collect()
    };
    let base_challenges: Vec<_> = gen.derive_all(&statement, &make_sessions(&proof)).unwrap();

    // The stored challenges equal the jointly derived ones.
    let stored: Vec<_> = proof
        .repetitions()
        .iter()
        .map(|rep| *rep.challenge())
        .collect();
    assert_eq!(stored, base_challenges);

    // Changed public input changes every derivation.
    let mut st2 = statement.clone();
    st2.public_inputs[0] = PublicValue::new(Fr::from(6u64));
    for (r, base) in base_digests.iter().enumerate() {
        assert_ne!(
            base,
            &gen.fs_digest(&st2, &make_sessions(&proof), r).unwrap()
        );
    }

    // Changed expected output changes every derivation.
    let mut st3 = statement.clone();
    st3.expected_outputs[0] = PublicValue::new(<Fr as One>::one());
    for (r, base) in base_digests.iter().enumerate() {
        assert_ne!(
            base,
            &gen.fs_digest(&st3, &make_sessions(&proof), r).unwrap()
        );
    }

    // Changing ANY repetition's commitments changes EVERY digest
    // (joint binding across the transcript).
    let mut cms1 = proof.repetitions()[1].commitments().to_vec();
    cms1[2] = ViewCommitment::from_digest(Digest::new([0x42; 32]));
    let tampered_proof = rebuild_with(&proof, 1, |rep| {
        (
            cms1,
            *rep.challenge(),
            rep.opened_views().to_vec(),
            rep.opening_randomness().to_vec(),
            rep.hidden_broadcasts().to_vec(),
            rep.hidden_output_shares().to_vec(),
        )
    });
    for (r, base) in base_digests.iter().enumerate() {
        let d = gen
            .fs_digest(&statement, &make_sessions(&tampered_proof), r)
            .unwrap();
        assert_ne!(base, &d, "rep {r} digest not bound to rep 1 commitments");
    }
}

#[test]
fn modified_commitment_rejects() {
    let (circuit, statement, proof) = honest_proof(1);

    // Tamper the commitment of a party that is *opened* under the
    // stored challenge: either the recomputed FS challenge diverges
    // (ChallengeMismatch) or it coincides and the decommitment fails
    // (VerificationFailed). Either way the proof is rejected.
    let rep = &proof.repetitions()[0];
    let opened_party = rep.challenge().hidden_party.others()[0].get() as usize;
    let rebuilt = rebuild_with(&proof, 0, |rep| {
        let mut cms = rep.commitments().to_vec();
        cms[opened_party] = ViewCommitment::from_digest(Digest::new([9; 32]));
        (
            cms,
            *rep.challenge(),
            rep.opened_views().to_vec(),
            rep.opening_randomness().to_vec(),
            rep.hidden_broadcasts().to_vec(),
            rep.hidden_output_shares().to_vec(),
        )
    });

    assert!(matches!(
        Verifier::<crypto_core::Sha256Backend>::new().verify(&circuit, &statement, &rebuilt),
        Err(ProofError::ChallengeMismatch) | Err(ProofError::VerificationFailed)
    ));
}

#[test]
fn modified_hidden_party_commitment_cannot_be_smuggled_past_challenge_check() {
    // Tampering a *hidden* party's commitment is caught when the
    // recomputed joint challenge diverges from the stored one; when the
    // two coincide (~1/3 of inputs for the 3-value challenge space) the
    // hidden commitment is never opened, which is why the verifier's
    // independent challenge recomputation is mandatory, why the raw FS
    // digest is exposed for auditing, and why proofs should carry
    // external integrity (e.g. `proof_id`) in transit. This test pins
    // the divergence branch deterministically by searching seeds until
    // the recomputed challenge differs from the stored one.
    use proof::{ChallengeGenerator as _, FiatShamirChallengeGenerator, FsSession};
    let gen = FiatShamirChallengeGenerator::<crypto_core::Sha256Backend>::default();

    for seed in 0..32u64 {
        let (circuit, statement, witness) = fixture();
        let mut prover = Prover::new(
            &circuit,
            &statement,
            witness,
            ChaCha20Rng::seed_from_u64(seed),
            ProtocolConfig::<crypto_core::Sha256Backend>::default(),
        )
        .unwrap();
        let proof = prover.prove(2).expect("valid");
        let rep_index = 1;
        let rep = &proof.repetitions()[rep_index];
        let hidden = rep.challenge().hidden_party.get() as usize;
        let mut cms = rep.commitments().to_vec();
        cms[hidden] = ViewCommitment::from_digest(Digest::new([0xEE; 32]));
        let rebuilt = rebuild_with(&proof, rep_index, |r| {
            (
                cms.clone(),
                *r.challenge(),
                r.opened_views().to_vec(),
                r.opening_randomness().to_vec(),
                r.hidden_broadcasts().to_vec(),
                r.hidden_output_shares().to_vec(),
            )
        });

        let sessions: Vec<FsSession<'_>> = rebuilt
            .repetitions()
            .iter()
            .enumerate()
            .map(|(i, r)| FsSession::new(mpcith::RepetitionId::new(i as u32), r.commitments()))
            .collect();
        let derived = gen.derive_all(&statement, &sessions).unwrap();
        if derived[rep_index] == *rep.challenge() {
            continue; // collision case: nothing to assert here
        }

        assert_eq!(
            Verifier::<crypto_core::Sha256Backend>::new().verify(&circuit, &statement, &rebuilt),
            Err(ProofError::ChallengeMismatch)
        );
        return;
    }
    panic!("no seed produced a diverging challenge; derivation suspect");
}

#[test]
fn modified_opened_view_rejects() {
    use ark_ff::One;
    let (circuit, statement, proof) = honest_proof(1);
    let rebuilt = rebuild_with(&proof, 0, |rep| {
        let mut views = rep.opened_views().to_vec();
        views[0].input_shares[0] += Fr::one();
        (
            rep.commitments().to_vec(),
            *rep.challenge(),
            views,
            rep.opening_randomness().to_vec(),
            rep.hidden_broadcasts().to_vec(),
            rep.hidden_output_shares().to_vec(),
        )
    });
    assert!(!matches!(
        Verifier::<crypto_core::Sha256Backend>::new().verify(&circuit, &statement, &rebuilt),
        Ok(VerificationResult::Valid)
    ));
}

#[test]
fn modified_randomness_rejects() {
    use crypto_core::SecretBytes;
    let (circuit, statement, proof) = honest_proof(1);
    let rebuilt = rebuild_with(&proof, 0, |rep| {
        let mut rs = rep.opening_randomness().to_vec();
        rs[0] = SecretBytes::new(vec![1u8; 32]);
        (
            rep.commitments().to_vec(),
            *rep.challenge(),
            rep.opened_views().to_vec(),
            rs,
            rep.hidden_broadcasts().to_vec(),
            rep.hidden_output_shares().to_vec(),
        )
    });
    assert!(matches!(
        Verifier::<crypto_core::Sha256Backend>::new().verify(&circuit, &statement, &rebuilt),
        Err(ProofError::ChallengeMismatch) | Err(ProofError::VerificationFailed)
    ));
}

#[test]
fn removed_and_reordered_repetitions_reject() {
    let (circuit, statement, _) = honest_proof(3);

    // Remove the middle repetition of a 3-rep proof: the challenges
    // committed under old positions no longer match their new ones.
    let (_, _, proof) = honest_proof(3);
    let kept: Vec<ProofRepetition> = proof
        .repetitions()
        .iter()
        .enumerate()
        .filter(|(i, _)| *i != 1)
        .map(|(_, rep)| rep.clone())
        .collect();
    let removed = NonInteractiveProof::new(
        proof.version(),
        proof.protocol_id(),
        proof.backend_id(),
        statement.clone(),
        kept,
    );
    assert!(Verifier::<crypto_core::Sha256Backend>::new()
        .verify(&circuit, &statement, &removed)
        .is_err());

    // Reordered repetitions fail the same way.
    let (_, _, proof2) = honest_proof(3);
    let reordered = NonInteractiveProof::new(
        proof2.version(),
        proof2.protocol_id(),
        proof2.backend_id(),
        statement.clone(),
        proof2.repetitions().iter().rev().cloned().collect(),
    );
    assert!(Verifier::<crypto_core::Sha256Backend>::new()
        .verify(&circuit, &statement, &reordered)
        .is_err());
}

#[test]
fn canonical_serialization_round_trip_is_byte_exact() {
    let (_, statement, proof) = honest_proof(3);
    let bytes = proof::serialize_proof(&proof);

    let decoded = deserialize_proof(&bytes).expect("decodes");
    assert_eq!(decoded.statement(), &statement);
    assert_eq!(decoded.repetitions().len(), proof.repetitions().len());
    // Canonical: re-encoding the decode reproduces identical bytes, so
    // proof identity is stable across serialization round-trips.
    assert_eq!(
        proof::serialize_proof(&decoded),
        bytes,
        "serialization must be canonical"
    );
    assert_eq!(decoded.proof_id().unwrap(), proof.proof_id().unwrap());

    // A decoded proof still verifies against its circuit.
    let (circuit, statement2, _) = fixture();
    assert_eq!(statement, statement2);
    assert_eq!(
        Verifier::<crypto_core::Sha256Backend>::new()
            .verify(&circuit, &statement, &decoded)
            .expect("no error"),
        VerificationResult::Valid
    );
}

#[test]
fn malformed_serialization_rejects() {
    let (circuit, _, proof) = honest_proof(2);
    let bytes = proof::serialize_proof(&proof);
    assert_eq!(
        Verifier::<crypto_core::Sha256Backend>::new()
            .verify(
                &circuit,
                proof.statement(),
                &deserialize_proof(&bytes).unwrap()
            )
            .expect("no error"),
        VerificationResult::Valid
    );

    // Wrong version.
    let mut bad = bytes.clone();
    bad[0] = 200;
    assert!(matches!(
        deserialize_proof(&bad),
        Err(ProofError::InvalidVersion)
    ));
    // Wrong protocol id.
    let mut bad_proto = bytes.clone();
    bad_proto[1] = 7;
    assert!(matches!(
        deserialize_proof(&bad_proto),
        Err(ProofError::InvalidVersion)
    ));
    // Truncation.
    assert!(matches!(
        deserialize_proof(&bytes[..bytes.len() - 3]),
        Err(ProofError::MalformedEncoding)
    ));
    // Trailing bytes.
    let mut long = bytes.clone();
    long.push(0);
    assert!(matches!(
        deserialize_proof(&long),
        Err(ProofError::MalformedEncoding)
    ));
}

#[test]
fn circuit_binding_holds() {
    let (_, statement, proof) = honest_proof(2);

    // A different circuit must not verify a foreign proof.
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    let c = b.constant(Fr::from(3u64));
    let t = b.add(x, c).expect("valid");
    let p = b.public_input();
    let s = b.mul(t, p).expect("valid");
    let s2 = b.add(s, x).expect("valid");
    b.output(s2).expect("valid");
    let other_circuit = b.build().expect("valid");

    assert!(matches!(
        Verifier::<crypto_core::Sha256Backend>::new().verify(&other_circuit, &statement, &proof),
        Err(ProofError::CircuitIdMismatch)
    ));
}

#[test]
fn statement_binding_holds() {
    let (circuit, statement, proof) = honest_proof(2);
    let mut tampered = statement.clone();
    tampered.expected_outputs[0] = PublicValue::new(Fr::zero());
    assert_eq!(
        Verifier::<crypto_core::Sha256Backend>::new().verify(&circuit, &tampered, &proof),
        Err(ProofError::InvalidStatement)
    );
}

#[test]
fn cross_protocol_reuse_is_prevented_by_domain_separation() {
    // The same committed bytes under the proof-id domain and the FS
    // domain must yield different digests.
    let data = [7u8; 40];
    let fs_digest = crypto_core::Sha256Hash::hash_domain(proof::FS_DOMAIN, &data);
    let id_digest = crypto_core::Sha256Hash::hash_domain(proof::PROOF_ID_DOMAIN, &data);
    assert_ne!(fs_digest, id_digest);
    let _ = <Fr as Zero>::zero();
    let _ = PartyId::new(0);
}

// ---------------------------------------------------------------------

/// Rebuilds an immutable proof replacing repetition `index` through
/// `f` (test helper; mutation is only possible via reconstruction).
fn rebuild_with(
    proof: &NonInteractiveProof,
    index: usize,
    f: impl FnOnce(
        &ProofRepetition,
    ) -> (
        Vec<ViewCommitment>,
        mpcith::Challenge,
        Vec<mpcith::PartyView>,
        Vec<crypto_core::SecretBytes>,
        Vec<FieldElement>,
        Vec<FieldElement>,
    ),
) -> NonInteractiveProof {
    let mut repetitions = proof.repetitions().to_vec();
    let old = repetitions[index].clone();
    let (
        commitments,
        challenge,
        opened_views,
        opening_randomness,
        hidden_broadcasts,
        hidden_output_shares,
    ) = f(&old);
    repetitions[index] = ProofRepetition::new(
        commitments,
        challenge,
        opened_views,
        opening_randomness,
        hidden_broadcasts,
        hidden_output_shares,
    );
    NonInteractiveProof::new(
        proof.version(),
        proof.protocol_id(),
        proof.backend_id(),
        proof.statement().clone(),
        repetitions,
    )
}
