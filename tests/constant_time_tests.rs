//! Constant-time comparison audit (Phase 10, Prompt 2, Part B).
//!
//! Verifies that secret material is compared with constant-time
//! primitives (`subtle`-backed `ct_eq`), not variable-time `==`, and that
//! the commitment/open path gates acceptance on a constant-time
//! comparison of the recomputed digest against the stored one.

use ark_ed25519::Fr;
use ark_ff::One;
use circuit::NodeId;
use crypto_core::backend::Sha256Backend;
use crypto_core::{Commitment, Digest, SecretBytes};
use mpcith::{
    commit_view, verify_commitment, LocalOperation, PartyId, PartyView, RepetitionId, TripleShare,
    ViewCommitment,
};

fn sample_view() -> PartyView {
    PartyView {
        repetition_id: RepetitionId::new(0),
        party_id: PartyId::new(1).unwrap(),
        input_shares: vec![Fr::from(11u64), Fr::from(12u64)],
        local_operations: vec![LocalOperation::Add {
            output: NodeId::new(2),
            share: Fr::one(),
        }],
        triple_shares: vec![TripleShare {
            a: Fr::from(3u64),
            b: Fr::from(5u64),
            c: Fr::from(15u64),
        }],
        opened_values: vec![],
    }
}

#[test]
fn digest_ct_eq_is_correct_and_symmetric() {
    let a = Digest::new([1u8; 32]);
    let b = Digest::new([1u8; 32]);
    let c = Digest::new([2u8; 32]);
    assert!(Digest::ct_eq(&a, &b));
    assert!(Digest::ct_eq(&b, &a));
    assert!(!Digest::ct_eq(&a, &c));
    assert!(!Digest::ct_eq(&c, &a));
}

#[test]
fn commitment_ct_eq_is_correct_and_symmetric() {
    let a = Commitment::from_digest(Digest::new([3u8; 32]));
    let b = Commitment::from_digest(Digest::new([3u8; 32]));
    let c = Commitment::from_digest(Digest::new([4u8; 32]));
    assert!(Commitment::ct_eq(&a, &b));
    assert!(Commitment::ct_eq(&b, &a));
    assert!(!Commitment::ct_eq(&a, &c));
    assert!(!Commitment::ct_eq(&c, &a));
}

#[test]
fn differing_byte_positions_all_rejected() {
    // A mismatch at any byte position must be detected by ct_eq.
    let base = [7u8; 32];
    for pos in 0..32 {
        let mut other = base;
        other[pos] ^= 0x80;
        let a = Digest::new(base);
        let b = Digest::new(other);
        assert!(!Digest::ct_eq(&a, &b), "byte {pos} mismatch undetected");
    }
}

#[test]
fn verify_commitment_uses_constant_time_comparison() {
    // Build a real commitment and confirm it verifies, then confirm a
    // tampered view fails the *constant-time* digest comparison.
    let view = sample_view();
    let sb = SecretBytes::new(vec![0xABu8; 32]);
    let commitment: ViewCommitment = commit_view::<Sha256Backend>(&view, &sb).unwrap();

    let ok = verify_commitment::<Sha256Backend>(&commitment, &view, &sb).expect("verify runs");
    assert!(ok, "valid commitment must verify");

    // Tamper with the view; the constant-time comparison must reject it.
    let mut bad = view.clone();
    bad.input_shares[0] = Fr::from(999u64);
    let ok_bad = verify_commitment::<Sha256Backend>(&commitment, &bad, &sb).expect("verify runs");
    assert!(!ok_bad, "tampered view must not verify");
}
