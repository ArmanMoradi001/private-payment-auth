//! Panic-free parser / decoder audit (Phase 10, Part B).
//!
//! Every decoder in the workspace must reject malformed input by
//! returning an error, never by panicking. This file feeds malformed
//! and random bytes into each decoder and asserts that no panic occurs.
//! It also verifies the explicit resource bounds added during Phase 10
//! (circuit nodes, proof repetitions, share count, policy depth,
//! credential count).

use std::panic::{self, AssertUnwindSafe};

use ark_ed25519::Fr;
use circuit::{deserialize, CircuitBuilder};
use crypto_core::backend::{BackendId, Sha256Backend};
use crypto_core::Digest;
use mpc::PublicValue as MpcPublicValue;
use mpcith::{decode_proof, decode_view, encoding::decode_challenge, encoding::decode_repetition};
use payment::{Amount, AmountUnit, PaymentStatement};
use policy::{CredentialPolicy, Policy};
use proof::{deserialize_proof, serialize_proof, Prover, ProtocolConfig, Statement as ProofStatement};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use secret_sharing::Share;

/// Runs `f` and returns `true` iff it did NOT panic.
fn does_not_panic(f: impl FnOnce() + std::panic::UnwindSafe) -> bool {
    panic::catch_unwind(AssertUnwindSafe(f)).is_ok()
}

/// A corpus of clearly malformed byte sequences.
fn malformed_inputs() -> Vec<Vec<u8>> {
    let mut v = Vec::new();
    v.push(Vec::new());
    v.push(vec![0u8]);
    v.push(vec![99u8]);
    for base in [
        vec![1u8, 0, 0, 0],
        vec![1u8, 0, 0, 0, 0],
        vec![1u8, 0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        v.push(base.clone());
        let mut ext = base;
        ext.extend_from_slice(&[0u8; 64]);
        v.push(ext);
    }
    for seed in 0u8..16 {
        let mut blob = vec![seed; 1 + usize::from(seed) * 7];
        blob.push(255);
        v.push(blob);
    }
    v
}

/// Exercises every decoder on `bytes`, asserting none of them panic.
fn exercise_all_decoders(bytes: &[u8]) {
    assert!(does_not_panic(|| {
        let _ = Share::decode(bytes);
    }));
    assert!(does_not_panic(|| {
        let _ = deserialize::<Fr>(bytes);
    }));
    assert!(does_not_panic(|| {
        let _ = decode_view(bytes);
    }));
    assert!(does_not_panic(|| {
        let _ = decode_repetition(bytes);
    }));
    assert!(does_not_panic(|| {
        let _ = decode_challenge(bytes);
    }));
    assert!(does_not_panic(|| {
        let _ = decode_proof(bytes);
    }));
    assert!(does_not_panic(|| {
        let _ = deserialize_proof(bytes);
    }));
    assert!(does_not_panic(|| {
        let _ = ProofStatement::decode(bytes);
    }));
    assert!(does_not_panic(|| {
        let _ = Amount::decode(bytes);
    }));
    assert!(does_not_panic(|| {
        let _ = PaymentStatement::decode(bytes);
    }));
}

#[test]
fn all_decoders_reject_empty_input_without_panic() {
    for bytes in malformed_inputs() {
        exercise_all_decoders(&bytes);
        if bytes.is_empty() {
            assert!(Share::decode(&bytes).is_err());
            assert!(deserialize::<Fr>(&bytes).is_err());
            assert!(decode_view(&bytes).is_err());
            assert!(decode_repetition(&bytes).is_err());
            assert!(decode_challenge(&bytes).is_err());
            assert!(decode_proof(&bytes).is_err());
            assert!(deserialize_proof(&bytes).is_err());
            assert!(ProofStatement::decode(&bytes).is_err());
            assert!(Amount::decode(&bytes).is_err());
            assert!(PaymentStatement::decode(&bytes).is_err());
        }
    }
}

proptest! {
    /// Random bytes must never cause a decoder to panic.
    #[test]
    fn random_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1024)) {
        exercise_all_decoders(&bytes);
    }
}

// ---------------------------------------------------------------------
// Explicit resource bounds (Phase 10)
// ---------------------------------------------------------------------

#[test]
fn circuit_node_bound_is_enforced() {
    // version(1) || num_nodes = 2_000_000 (> MAX_CIRCUIT_NODES = 1_000_000)
    let mut bytes = vec![circuit::encoding::ENCODING_VERSION];
    bytes.extend_from_slice(&2_000_000u32.to_be_bytes());
    let err = deserialize::<Fr>(&bytes).expect_err("must reject oversized circuit");
    assert!(matches!(err, circuit::CircuitError::ExcessiveSize));
}

#[test]
fn share_count_bound_is_enforced() {
    // Build a structurally valid share, then inflate its share_count.
    let good = Share::new(
        2,
        3,
        1,
        secret_sharing::field::element_from_be_bytes(&[7u8; 32]).unwrap(),
    )
    .expect("valid");
    let mut bytes = Share::encode(&good);
    // share_count occupies offset 5..9.
    bytes[5..9].copy_from_slice(&2000u32.to_be_bytes());
    assert!(Share::decode(&bytes).is_err());
}

#[test]
fn policy_depth_bound_is_enforced() {
    // Build a linear And-chain far deeper than MAX_POLICY_DEPTH (100).
    let mut policy = Policy::AmountAtMost { limit: 1 };
    for _ in 0..150 {
        policy = Policy::And {
            policies: vec![policy],
        };
    }
    assert_eq!(
        policy.validate(),
        Err(policy::PolicyError::ExcessivePolicyDepth)
    );
}

#[test]
fn policy_credential_count_bound_is_enforced() {
    let policy = Policy::Threshold {
        k: 1,
        credentials: (0..1001)
            .map(|_| CredentialPolicy {
                expected_commitment: Digest::new([0u8; 32]),
            })
            .collect(),
    };
    assert_eq!(
        policy.validate(),
        Err(policy::PolicyError::ExcessiveCredentials)
    );
}

#[test]
fn proof_repetition_bound_is_enforced() {
    // Generate a small valid proof, then inflate its repetition count.
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    let c = b.constant(Fr::from(2u64));
    let t = b.add(x, c).expect("valid");
    let p = b.public_input();
    let m = b.mul(t, p).expect("valid");
    let s = b.add(m, x).expect("valid");
    b.output(s).expect("valid");
    let circuit = b.build().expect("valid");
    let statement = ProofStatement {
        circuit_id: circuit.compute_id(),
        public_inputs: vec![MpcPublicValue::new(Fr::from(5u64))],
        expected_outputs: vec![MpcPublicValue::new(Fr::from(52u64))],
    };
    let mut prover = Prover::<_, Sha256Backend>::new(
        &circuit,
        &statement,
        vec![Fr::from(7u64)],
        ChaCha20Rng::seed_from_u64(13),
        ProtocolConfig::<Sha256Backend>::default(),
    )
    .expect("valid");
    let proof = prover.prove(4).expect("valid");
    let mut bytes = serialize_proof(&proof);

    // n_reps sits at offset 2 (version+protocol) + BACKEND_ID_LEN + statement_len.
    let backend_len = BackendId::new([0u8; crypto_core::backend::BACKEND_ID_LEN])
        .as_bytes()
        .len();
    let stmt_len = proof.statement().encode().len();
    let pos = 2 + backend_len + stmt_len;
    bytes[pos..pos + 4].copy_from_slice(&20_000u32.to_be_bytes());

    assert!(matches!(
        deserialize_proof(&bytes),
        Err(proof::ProofError::ExcessiveRepetitions)
    ));
}

#[test]
fn payment_amount_decode_bounds() {
    // Wrong version and trailing bytes must be rejected, not panic.
    let amount = Amount {
        value: 1234,
        unit: AmountUnit::Cents,
    };
    let mut bytes = amount.encode().to_vec();
    bytes.push(0u8);
    assert!(Amount::decode(&bytes).is_err());
    let mut bad = amount.encode();
    bad[0] = 99;
    assert!(Amount::decode(&bad).is_err());
}
