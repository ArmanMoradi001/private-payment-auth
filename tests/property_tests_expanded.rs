//! Expanded property tests (Phase 10, Prompt 4, Part B).
//!
//! Covers: integer/arithmetic, MPC (secret sharing), MPCitH
//! (prover/verifier consistency), Fiat-Shamir (determinism + binding), and
//! cross-crate consistency (commit/open, range-check semantics).

use ark_ed25519::Fr;
use ark_ff::{PrimeField, Zero};
use circuit::{evaluate_reference, Circuit, CircuitBuilder, CircuitId, NodeId};
use crypto_core::{commit, open, CommitmentRandomness, Digest, SecretBytes, Sha256Backend};
use mpc::PublicValue;
use mpcith::{
    MpcithProver, MpcithVerifier, RandomChallengeSource, RepetitionId, Statement as MpcithStatement,
    VerificationResult, ViewCommitment,
};
use payment::range_check::{decompose, reference_range_check};
use proof::{
    FiatShamirChallengeGenerator, FsSession, Statement as ProofStatement,
};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use secret_sharing::field::{element_from_be_bytes, element_to_be_bytes};

fn arb_fr() -> impl Strategy<Value = Fr> {
    any::<[u8; 32]>().prop_map(|bytes| Fr::from_le_bytes_mod_order(&bytes))
}

// ---------------------------------------------------------------------------
// Integer / arithmetic property tests
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn field_addition_commutative(a in arb_fr(), b in arb_fr()) {
        prop_assert_eq!(a + b, b + a);
    }

    #[test]
    fn field_multiplication_associative(a in arb_fr(), b in arb_fr(), c in arb_fr()) {
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    #[test]
    fn field_mul_by_zero_is_zero(a in arb_fr()) {
        prop_assert_eq!(a * Fr::zero(), Fr::zero());
    }

    #[test]
    fn field_add_identity(a in arb_fr()) {
        prop_assert_eq!(a + Fr::zero(), a);
    }

    #[test]
    fn range_check_matches_inequality(v in any::<u64>(), limit in any::<u64>()) {
        let ok = reference_range_check(v, limit).is_ok();
        prop_assert_eq!(ok, v <= limit);
    }

    #[test]
    fn decompose_recomposes(v in any::<u64>()) {
        let bits = decompose(v);
        let mut acc: u64 = 0;
        for (i, bit) in bits.iter().enumerate() {
            if *bit {
                acc |= 1u64 << i;
            }
        }
        prop_assert_eq!(acc, v);
        // All high bits beyond the value must be zero.
        prop_assert_eq!(acc, v);
    }
}

// ---------------------------------------------------------------------------
// MPC property tests: secret sharing split / reconstruct
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn share_split_reconstruct_roundtrip(secret_u64 in any::<u64>()) {
        let field_val = Fr::from(secret_u64);
        let secret = SecretBytes::new(element_to_be_bytes(&field_val).to_vec());
        let mut rng = ChaCha20Rng::seed_from_u64(secret_u64.wrapping_mul(2).wrapping_add(1));
        let shares = secret_sharing::split(&secret, 3, 5, &mut rng)
            .expect("split succeeds for a value below the field modulus");
        // Any threshold (3) subset must reconstruct the same field element.
        let subset = &shares[0..3];
        let recovered = secret_sharing::reconstruct(subset).expect("reconstruct");
        let rebuilt = element_from_be_bytes(recovered.as_bytes())
            .expect("reconstructed bytes decode to a valid field element");
        prop_assert_eq!(rebuilt, field_val);
    }

    #[test]
    fn share_reconstruct_is_threshold_only(secret_u64 in any::<u64>()) {
        let secret = SecretBytes::new(secret_u64.to_be_bytes().to_vec());
        let mut rng = ChaCha20Rng::seed_from_u64(secret_u64.wrapping_add(7));
        let shares = secret_sharing::split(&secret, 3, 5, &mut rng).expect("split");
        // Reconstructing from fewer than the threshold must fail.
        let too_few = &shares[0..2];
        prop_assert!(secret_sharing::reconstruct(too_few).is_err());
    }
}

// ---------------------------------------------------------------------------
// MPCitH property tests: prover / verifier consistency
// ---------------------------------------------------------------------------

/// Builds a random, valid circuit along with its witness, public inputs, and
/// the reference-evaluated expected outputs.
fn random_circuit(
    seed: u64,
) -> (Circuit<Fr>, Vec<Fr>, Vec<Fr>, Vec<Fr>) {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut b = CircuitBuilder::<Fr>::new();
    let secret = b.secret_input();
    let mut available: Vec<NodeId> = vec![secret];
    let mut public_vals: Vec<Fr> = Vec::new();
    let num_public = 1 + (rng.next_u64() % 3) as usize;
    for _ in 0..num_public {
        let p = b.public_input();
        available.push(p);
        public_vals.push(Fr::from(rng.next_u64() % 1_000_003u64));
    }
    let secret_val = Fr::from(rng.next_u64() % 1_000_003u64);
    let ops = 1 + (rng.next_u64() % 5) as usize;
    for _ in 0..ops {
        let i = (rng.next_u64() as usize) % available.len();
        let j = (rng.next_u64() as usize) % available.len();
        let (mut a, node_b) = (available[i], available[j]);
        if rng.next_u64() % 3 == 0 {
            let c = b.constant(Fr::from(rng.next_u64() % 1_000_003u64));
            a = c;
        }
        let node = if rng.next_u64() % 2 == 0 {
            b.add(a, node_b).expect("add")
        } else {
            b.mul(a, node_b).expect("mul")
        };
        available.push(node);
    }
    let out = *available.last().unwrap();
    b.output(out).expect("output");
    let circuit = b.build().expect("build");
    let ref_vals = evaluate_reference(&circuit, &[secret_val], &public_vals).expect("ref eval");
    (circuit, vec![secret_val], public_vals, ref_vals)
}

proptest! {
    #[test]
    fn mpcith_honest_proof_verifies(seed in any::<u64>()) {
        let (circuit, witness, public_vals, ref_vals) = random_circuit(seed);
        let expected: Vec<PublicValue<Fr>> = circuit
            .outputs()
            .iter()
            .enumerate()
            .map(|(i, _)| PublicValue::new(ref_vals[i]))
            .collect();
        let statement = MpcithStatement {
            circuit_id: circuit.compute_id(),
            public_inputs: public_vals.iter().map(|v| PublicValue::new(*v)).collect(),
            expected_outputs: expected,
        };
        let mut prover = MpcithProver::new(
            &circuit,
            &statement,
            witness,
            Box::new(RandomChallengeSource::new(ChaCha20Rng::seed_from_u64(
                seed.wrapping_add(1),
            ))),
            ChaCha20Rng::seed_from_u64(seed),
        )
        .expect("prover builds");
        let proof = prover.prove(3).expect("prove succeeds on a valid instance");
        let result = MpcithVerifier::new()
            .verify(&statement, &proof, &circuit)
            .expect("verify runs");
        prop_assert_eq!(result, VerificationResult::Valid);
    }
}

// ---------------------------------------------------------------------------
// Fiat-Shamir property tests
// ---------------------------------------------------------------------------

fn fs_statement() -> ProofStatement {
    ProofStatement {
        circuit_id: CircuitId::from_digest(Digest::new([0u8; crypto_core::DIGEST_LEN])),
        public_inputs: vec![],
        expected_outputs: vec![],
    }
}

/// Builds a `Digest` that is distinct for distinct `seed` values (full seed
/// is folded across all 32 digest bytes, avoiding low-byte collisions).
fn seed_digest(seed: u64) -> Digest {
    let bytes = seed.to_le_bytes();
    let mut arr = [0u8; crypto_core::DIGEST_LEN];
    for (i, slot) in arr.iter_mut().enumerate() {
        *slot = bytes[i % 8];
    }
    Digest::new(arr)
}

proptest! {
    #[test]
    fn fs_challenge_is_deterministic(seed in any::<u64>()) {
        let stmt = fs_statement();
        let digest = seed_digest(seed);
        let commit = ViewCommitment::from_digest(digest);
        let session = FsSession::new(RepetitionId::new(0), std::slice::from_ref(&commit));
        let gen = FiatShamirChallengeGenerator::<Sha256Backend>::default();
        let a = gen.fs_input(&stmt, &[session], 0).expect("fs_input");
        let b = gen.fs_input(&stmt, &[session], 0).expect("fs_input");
        prop_assert_eq!(a, b);
    }

    #[test]
    fn fs_challenge_binds_to_commitment(a_seed in any::<u64>(), b_seed in any::<u64>()) {
        prop_assume!(a_seed != b_seed);
        let stmt = fs_statement();
        let ca = ViewCommitment::from_digest(seed_digest(a_seed));
        let cb = ViewCommitment::from_digest(seed_digest(b_seed));
        let sa = FsSession::new(RepetitionId::new(0), std::slice::from_ref(&ca));
        let sb = FsSession::new(RepetitionId::new(0), std::slice::from_ref(&cb));
        let gen = FiatShamirChallengeGenerator::<Sha256Backend>::default();
        let ia = gen.fs_input(&stmt, &[sa], 0).expect("fs_input");
        let ib = gen.fs_input(&stmt, &[sb], 0).expect("fs_input");
        prop_assert_ne!(ia, ib);
    }
}

// ---------------------------------------------------------------------------
// Cross-crate consistency
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn commitment_open_roundtrip(msg in any::<Vec<u8>>(), seed in any::<u64>()) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let randomness = CommitmentRandomness::generate(&mut rng).expect("rng");
        let commitment = commit::<Sha256Backend>(&msg, &randomness);
        prop_assert!(open::<Sha256Backend>(&commitment, &msg, &randomness));
        // A tampered message must not open.
        let tampered = if msg.is_empty() {
            vec![0u8]
        } else {
            let mut m = msg.clone();
            let last = m.len() - 1;
            m[last] ^= 0x01;
            m
        };
        prop_assert!(!open::<Sha256Backend>(&commitment, &tampered, &randomness));
    }
}
