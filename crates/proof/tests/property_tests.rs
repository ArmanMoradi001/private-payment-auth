//! Property-based tests for the non-interactive proof layer.
//!
//! Invariants that hold for every well-formed proof, regardless of
//! circuit shape, witness, or statement values:
//!
//! 1. Canonical serialization: decoding a serialized proof and
//!    re-encoding reproduces identical bytes, and the decoded proof
//!    still verifies against its circuit.
//! 2. Tamper evidence: flipping any single byte of a serialized proof
//!    either breaks decoding, breaks verification against the
//!    verifier's own statement, or — only when the flip lands in a
//!    never-opened view commitment *and* the recomputed challenge
//!    coincides (~1/3 of inputs for the 3-value challenge space) — is
//!    confined to commitments no verifier ever opens. In every case
//!    the canonical bytes change, so [`proof::NonInteractiveProof::proof_id`]
//!    detects the mutation deterministically.
//! 3. Grinding resistance: because challenges are derived jointly from
//!    ALL repetitions' commitments, changing one repetition's
//!    commitments changes every challenge (covered by unit tests); here
//!    we additionally check proofs remain valid only as committed.

use circuit::CircuitBuilder;
use mpc::PublicValue;
use mpcith::FieldElement;
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

type Fr = FieldElement;

/// Builds a small circuit `((x + c) · p) + x`, together with its
/// statement and witness.
fn build_case(x: u64, p: u64, c: u64) -> (circuit::Circuit<Fr>, proof::Statement, Vec<Fr>) {
    let mut b = CircuitBuilder::<Fr>::new();
    let sx = b.secret_input();
    let sc = b.constant(Fr::from(c));
    let t = b.add(sx, sc).expect("valid");
    let sp = b.public_input();
    let m = b.mul(t, sp).expect("valid");
    let s = b.add(m, sx).expect("valid");
    b.output(s).expect("valid");
    let circuit = b.build().expect("valid");

    let expected = (x + c) * p + x;
    let statement = proof::Statement {
        circuit_id: circuit.compute_id(),
        public_inputs: vec![PublicValue::new(Fr::from(p))],
        expected_outputs: vec![PublicValue::new(Fr::from(expected))],
    };
    (circuit, statement, vec![Fr::from(x)])
}

fn honest_proof(
    seed: u64,
    x: u64,
    p: u64,
    c: u64,
) -> (
    circuit::Circuit<Fr>,
    proof::Statement,
    proof::NonInteractiveProof,
) {
    let (circuit, statement, witness) = build_case(x, p, c);
    let mut prover = proof::Prover::new(
        &circuit,
        &statement,
        witness,
        ChaCha20Rng::seed_from_u64(seed),
    )
    .expect("valid");
    let prf = prover.prove(2).expect("valid");
    (circuit, statement, prf)
}

/// Whether `flip` landed exclusively in commitments of parties that are
/// hidden under their repetition's stored challenge — the only bytes a
/// verifier never opens, where coincidental acceptance is unavoidable.
fn confined_to_hidden_commitments(
    original: &proof::NonInteractiveProof,
    tampered: &proof::NonInteractiveProof,
) -> bool {
    for (orig_rep, tamp_rep) in original.repetitions().iter().zip(tampered.repetitions()) {
        let hidden = orig_rep.challenge().hidden_party.get() as usize;
        for (party, (o, t)) in orig_rep
            .commitments()
            .iter()
            .zip(tamp_rep.commitments())
            .enumerate()
        {
            if o != t && party != hidden {
                return false;
            }
        }
        // Everything else must be untouched.
        if orig_rep.challenge() != tamp_rep.challenge()
            || orig_rep.opened_views() != tamp_rep.opened_views()
            || orig_rep
                .opening_randomness()
                .iter()
                .zip(tamp_rep.opening_randomness())
                .any(|(a, b)| a.as_bytes() != b.as_bytes())
            || orig_rep.hidden_broadcasts() != tamp_rep.hidden_broadcasts()
            || orig_rep.hidden_output_shares() != tamp_rep.hidden_output_shares()
        {
            return false;
        }
    }
    true
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(24))]

    #[test]
    fn round_trip_is_canonical_and_verifies(
        seed in 0u64..1000,
        x in 1u64..500,
        p in 1u64..500,
        c in 0u64..500,
    ) {
        let (circuit, statement, prf) = honest_proof(seed, x, p, c);
        let bytes = proof::serialize_proof(&prf);

        let decoded = proof::deserialize_proof(&bytes).expect("well-formed encoding");
        prop_assert_eq!(proof::serialize_proof(&decoded), bytes);
        prop_assert_eq!(decoded.proof_id().unwrap(), prf.proof_id().unwrap());
        prop_assert_eq!(
            proof::Verifier::new()
                .verify(&circuit, &statement, &decoded)
                .expect("no error"),
            proof::VerificationResult::Valid
        );
    }

    #[test]
    fn any_single_byte_flip_breaks_validity(
        seed in 0u64..1000,
        x in 1u64..500,
        p in 1u64..500,
        c in 0u64..500,
        byte_index in 0usize..4000,
    ) {
        let (circuit, statement, prf) = honest_proof(seed, x, p, c);
        let mut bytes = proof::serialize_proof(&prf);
        let i = byte_index % bytes.len();
        bytes[i] = !bytes[i];

        // Tamper evidence holds unconditionally: any accepted mutation
        // changes the canonical encoding, hence the proof identity.
        match proof::deserialize_proof(&bytes) {
            // Tamper broke the encoding: rejected outright.
            Err(_) => {}
            Ok(decoded) => {
                let verdict =
                    proof::Verifier::new().verify(&circuit, &statement, &decoded);
                let valid = matches!(verdict, Ok(proof::VerificationResult::Valid));
                if valid {
                    // Only tolerable inside never-opened commitments.
                    prop_assert!(
                        confined_to_hidden_commitments(&prf, &decoded),
                        "byte {} flip survived outside hidden commitments",
                        i
                    );
                }
                prop_assert_ne!(
                    decoded.proof_id().unwrap(),
                    prf.proof_id().unwrap(),
                    "byte {} flip did not change the proof id",
                    i
                );
            }
        }
    }
}

#[test]
fn statement_shape_mismatch_is_rejected_before_proving() {
    // A statement whose counts disagree with the circuit is rejected
    // before any proving happens.
    let (circuit, _, witness) = build_case(7, 5, 3);
    let bad = proof::Statement {
        circuit_id: circuit.compute_id(),
        public_inputs: vec![
            PublicValue::new(Fr::from(5u64)),
            PublicValue::new(Fr::from(6u64)),
        ],
        expected_outputs: vec![PublicValue::new(Fr::from(52u64))],
    };
    assert!(matches!(
        proof::Prover::new(&circuit, &bad, witness, ChaCha20Rng::seed_from_u64(1)),
        Err(proof::ProofError::InvalidStatement)
    ));
}
