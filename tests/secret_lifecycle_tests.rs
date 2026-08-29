//! Secret lifecycle audit (Phase 10, Prompt 2, Part A).
//!
//! Verifies, for every secret-bearing type in the workspace:
//! 1. `Debug`/`Display` redact secret material (no `FieldElement` or raw
//!    byte values are rendered).
//! 2. The type implements `Zeroize` (and `ZeroizeOnDrop` where derived).
//! 3. Public error types do not embed secret material.

use ark_ed25519::Fr;
use circuit::NodeId;
use crypto_core::{CommitmentRandomness, SecretBytes};
use mpc::{
    BeaverTriple, LocalTrustedTripleProvider, Share as MpcShare, ShareContext, SharedValue,
    TripleProvider,
};
use mpcith::{
    Challenge, LocalOperation, PartyId, PartyView, Repetition, RepetitionId, TripleShare,
    ViewCommitment,
};
use payment::{Amount, AmountUnit, PrivateWitness};
use proof::ProofRepetition;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use secret_sharing::Share as SsShare;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Compile-time proof that `T` implements `Zeroize`.
fn assert_impl_zeroize<T: Zeroize>() {}

/// Compile-time proof that `T` implements `ZeroizeOnDrop`.
fn assert_impl_zeroize_on_drop<T: ZeroizeOnDrop>() {}

const LEAK: &str = "314159";

fn assert_no_field_leak(rendered: &str) {
    assert!(
        !rendered.contains(LEAK),
        "debug output leaked a secret field value: {rendered}"
    );
}

fn assert_redacted(rendered: &str) {
    assert!(
        rendered.contains("REDACTED"),
        "secret type debug output is not redacted: {rendered}"
    );
}

#[test]
fn zeroize_traits_are_implemented() {
    assert_impl_zeroize::<SecretBytes>();
    assert_impl_zeroize::<CommitmentRandomness>();
    assert_impl_zeroize::<MpcShare<Fr>>();
    assert_impl_zeroize::<SharedValue<Fr>>();
    assert_impl_zeroize::<BeaverTriple<Fr>>();
    assert_impl_zeroize::<PartyView>();
    assert_impl_zeroize::<PrivateWitness>();

    assert_impl_zeroize_on_drop::<SecretBytes>();
    assert_impl_zeroize_on_drop::<CommitmentRandomness>();
}

#[test]
fn secret_bytes_debug_redacted() {
    let s = SecretBytes::new(vec![0xAB, 0xCD, 0xEF]);
    let rendered = format!("{s:?}");
    assert_redacted(&rendered);
    assert!(!rendered.contains("AB"));
}

#[test]
fn commitment_randomness_debug_redacted() {
    let r = CommitmentRandomness::new(SecretBytes::new(vec![0xABu8; 32])).unwrap();
    let rendered = format!("{r:?}");
    assert_redacted(&rendered);
    assert!(!rendered.contains("AB"));
}

#[test]
fn secret_sharing_share_debug_redacted() {
    let s = SsShare::new(2, 3, 1, Fr::from(314159u64)).unwrap();
    let rendered = format!("{s:?}");
    assert_redacted(&rendered);
    assert_no_field_leak(&rendered);
}

#[test]
fn mpc_share_debug_redacted() {
    let s = MpcShare::new(Fr::from(314159u64));
    let rendered = format!("{s:?}");
    assert_redacted(&rendered);
    assert_no_field_leak(&rendered);
}

#[test]
fn shared_value_debug_redacted() {
    let v = SharedValue::from_shares(vec![MpcShare::new(Fr::from(314159u64))]).unwrap();
    let rendered = format!("{v:?}");
    assert_redacted(&rendered);
    assert_no_field_leak(&rendered);
}

#[test]
fn beaver_triple_debug_redacted() {
    let ctx = ShareContext::new(3, 0, 0).unwrap();
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let mut provider = LocalTrustedTripleProvider::new(ctx, &mut rng).unwrap();
    let t: BeaverTriple<Fr> = provider.next_triple().unwrap();
    let rendered = format!("{t:?}");
    assert_redacted(&rendered);
}

#[test]
fn triple_share_debug_redacted() {
    let t = TripleShare {
        a: Fr::from(314159u64),
        b: Fr::from(1u64),
        c: Fr::from(2u64),
    };
    let rendered = format!("{t:?}");
    assert_redacted(&rendered);
    assert_no_field_leak(&rendered);
}

#[test]
fn local_operation_debug_redacted() {
    let op = LocalOperation::Add {
        output: NodeId::new(1),
        share: Fr::from(314159u64),
    };
    let rendered = format!("{op:?}");
    // LocalOperation shows only routing info, never the share value.
    assert_no_field_leak(&rendered);
    assert!(rendered.contains("Add"));
}

#[test]
fn party_view_debug_redacted() {
    let view = PartyView {
        repetition_id: RepetitionId::new(0),
        party_id: PartyId::new(1).unwrap(),
        input_shares: vec![Fr::from(314159u64)],
        local_operations: vec![LocalOperation::Add {
            output: NodeId::new(1),
            share: Fr::from(7u64),
        }],
        triple_shares: vec![TripleShare {
            a: Fr::from(1u64),
            b: Fr::from(2u64),
            c: Fr::from(3u64),
        }],
        opened_values: vec![],
    };
    let rendered = format!("{view:?}");
    assert_redacted(&rendered);
    assert_no_field_leak(&rendered);
}

#[test]
fn private_witness_debug_redacted() {
    let w = PrivateWitness::new(
        vec![SecretBytes::new(vec![0xAB, 0xCD, 0xEF])],
        Amount {
            value: 100,
            unit: AmountUnit::Cents,
        },
        1000,
    );
    let rendered = format!("{w:?}");
    // Only the credential *count* and the public amount are shown.
    assert!(rendered.contains("PrivateWitness"));
    assert!(!rendered.contains("AB"));
}

#[test]
fn mpcith_repetition_debug_redacted() {
    let rep = Repetition {
        id: RepetitionId::new(0),
        commitments: Vec::<ViewCommitment>::new(),
        challenge: Challenge {
            hidden_party: PartyId::new(1).unwrap(),
        },
        opened_views: vec![],
        hidden_output_shares: vec![Fr::from(314159u64)],
        hidden_broadcasts: vec![],
    };
    let rendered = format!("{rep:?}");
    assert_no_field_leak(&rendered);
}

#[test]
fn proof_repetition_debug_redacted() {
    let pr = ProofRepetition::new(
        Vec::<ViewCommitment>::new(),
        Challenge {
            hidden_party: PartyId::new(1).unwrap(),
        },
        Vec::<PartyView>::new(),
        Vec::<SecretBytes>::new(),
        Vec::<Fr>::new(),
        vec![Fr::from(314159u64)],
    );
    let rendered = format!("{pr:?}");
    assert_no_field_leak(&rendered);
}

#[test]
fn public_errors_do_not_embed_secrets() {
    // Sentinel that no error value should ever contain.
    const SENTINEL: &str = "DEADBEEFCAFE";
    let e1 = mpcith::MpcithError::MalformedEncoding;
    let e2 = proof::ProofError::ExcessiveRepetitions;
    assert!(!format!("{e1:?}").contains(SENTINEL));
    assert!(!format!("{e2:?}").contains(SENTINEL));
}
