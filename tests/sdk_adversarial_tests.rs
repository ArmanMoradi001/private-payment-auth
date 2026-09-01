//! Adversarial SDK tests.
//!
//! These tests are the "adversary holds the wire format and tries
//! every mutation they can think of" half of the SDK test suite. They
//! complement `sdk_e2e_tests.rs` (which exercises the legitimate
//! happy-path workflows) and `sdk_serialization_tests.rs` (which
//! stresses the byte-level encoding) with mutations applied directly
//! to authorization artifacts and the public data they bind to.
//!
//! Each test isolates one attack class:
//!
//! - tampering with a single binding field on the artifact;
//! - deserializing tampered bytes;
//! - replaying an artifact against a different `(payment, policy)`
//!   context to check that binding checks refuse it.

use crypto_core::{CryptoBackend, Digest, SecretBytes, Sha256Backend};
use payment::{Amount, AmountUnit, Payment, PrivateWitness};
use policy::{credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sdk::{
    deserialize, serialize, Authorization, Sdk, SdkConfig, SdkError, VerificationFailure,
    VerificationResult,
};

fn fixture() -> (Payment, Policy, PrivateWitness, Vec<SecretBytes>) {
    let secrets: Vec<SecretBytes> = (0..3)
        .map(|i| SecretBytes::new(vec![(i as u8) + 1, 0x0c, 0x0d]))
        .collect();
    let members: Vec<Policy> = secrets
        .iter()
        .map(|s| Policy::Credential(CredentialId::from_commitment(credential_commitment(s))))
        .collect();
    let policy = Policy::And(vec![
        Policy::Threshold {
            k: ThresholdK::new(2),
            members,
        },
        Policy::AmountAtMost(AmountLimit::new(100)),
    ]);

    let payment = Payment {
        version: 1,
        payment_id: [0x42; 32],
        amount: Amount {
            value: 75,
            unit: AmountUnit::Cents,
        },
        recipient_commitment: Digest::new([0x11; 32]),
        nonce: [0x33; 32],
    };
    let witness = PrivateWitness::new(secrets.clone(), payment.amount, 100);
    (payment, policy, witness, secrets)
}

fn build_authorization(
    payment: &Payment,
    policy: &Policy,
    witness: &PrivateWitness,
) -> Authorization {
    let sdk = Sdk::new(SdkConfig::default());
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    sdk.authorize(payment, policy, witness, &mut rng)
        .expect("fixture must authorize")
}

/// Adversarial baseline: replace the proof with a freshly built proof
/// from a *different* statement. The mutation must be rejected by the
/// cryptographic check, never silently accepted.
#[test]
fn replacing_proof_invalidates_verification() {
    let (payment, policy, witness, secrets) = fixture();
    let original = build_authorization(&payment, &policy, &witness);

    // Build a different authorization for a different statement; the
    // payment is distinct, so its binding triple is distinct.
    let alt_payment = Payment {
        payment_id: [0x55; 32],
        ..payment
    };
    let alt_witness = PrivateWitness::new(secrets.clone(), alt_payment.amount, 100);
    let alt = build_authorization(&alt_payment, &policy, &alt_witness);

    // Stitch: keep the original's bindings, swap in the alt's proof.
    let swapped = Authorization::new(
        original.version(),
        original.protocol_version(),
        original.backend_id(),
        *original.payment_id(),
        original.policy_id(),
        original.circuit_id(),
        alt.proof().clone(),
    );

    let sdk = Sdk::new(SdkConfig::default());
    let result = sdk
        .verify(&payment, &policy, &swapped)
        .expect("verify must surface a failure");
    assert!(!result.is_valid(), "replaced proof must not verify");
}

/// Mutating the `payment_id` recorded on the artifact must surface as
/// `PaymentMismatch`: the artifact's payment binding disagrees with
/// the supplied payment.
#[test]
fn replacing_payment_id_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let original = build_authorization(&payment, &policy, &witness);
    let swapped = Authorization::new(
        original.version(),
        original.protocol_version(),
        original.backend_id(),
        [0x99; 32],
        original.policy_id(),
        original.circuit_id(),
        original.proof().clone(),
    );

    let sdk = Sdk::new(SdkConfig::default());
    let result = sdk
        .verify(&payment, &policy, &swapped)
        .expect("verify must surface a failure");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::PaymentMismatch)
    );
}

/// Mutating the `policy_id` recorded on the artifact must surface as
/// `PolicyMismatch`.
#[test]
fn replacing_policy_id_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let original = build_authorization(&payment, &policy, &witness);
    let swapped = Authorization::new(
        original.version(),
        original.protocol_version(),
        original.backend_id(),
        *original.payment_id(),
        Digest::new([0xee; 32]),
        original.circuit_id(),
        original.proof().clone(),
    );

    let sdk = Sdk::new(SdkConfig::default());
    let result = sdk
        .verify(&payment, &policy, &swapped)
        .expect("verify must surface a failure");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::PolicyMismatch)
    );
}

/// Mutating the `circuit_id` recorded on the artifact must surface as
/// `CircuitMismatch`.
#[test]
fn replacing_circuit_id_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let original = build_authorization(&payment, &policy, &witness);
    let swapped = Authorization::new(
        original.version(),
        original.protocol_version(),
        original.backend_id(),
        *original.payment_id(),
        original.policy_id(),
        Digest::new([0xdd; 32]),
        original.proof().clone(),
    );

    let sdk = Sdk::new(SdkConfig::default());
    let result = sdk
        .verify(&payment, &policy, &swapped)
        .expect("verify must surface a failure");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::CircuitMismatch)
    );
}

/// Mutating the artifact's bound backend id must surface as
/// `BackendMismatch` (a configuration error, not a cryptographic
/// failure).
#[test]
fn changing_backend_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let original = build_authorization(&payment, &policy, &witness);
    let swapped = Authorization::new(
        original.version(),
        original.protocol_version(),
        crypto_core::Shake256Backend::ID,
        *original.payment_id(),
        original.policy_id(),
        original.circuit_id(),
        original.proof().clone(),
    );

    let sdk = Sdk::new(SdkConfig::default());
    let err = sdk
        .verify(&payment, &policy, &swapped)
        .expect_err("backend mismatch must error");
    assert_eq!(err, SdkError::BackendMismatch);
}

/// Mutating the artifact's encoding version must surface as
/// `VersionMismatch`.
#[test]
fn changing_version_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let original = build_authorization(&payment, &policy, &witness);
    let swapped = Authorization::new(
        99,
        original.protocol_version(),
        original.backend_id(),
        *original.payment_id(),
        original.policy_id(),
        original.circuit_id(),
        original.proof().clone(),
    );

    let sdk = Sdk::new(SdkConfig::default());
    let result = sdk
        .verify(&payment, &policy, &swapped)
        .expect("verify must surface a failure");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::VersionMismatch)
    );
}

/// Mutating the payment's nonce used to derive the verifier's
/// statement must surface as a cryptographic failure: the proof was
/// Fiat–Shamir-bound to the *original* nonce-derived statement, and
/// the verifier rebuilds the statement off the tampered nonce.
#[test]
fn changing_payment_nonce_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let original = build_authorization(&payment, &policy, &witness);

    let mut tampered = payment;
    tampered.nonce = [0x77; 32];
    let sdk = Sdk::new(SdkConfig::default());
    let result = sdk
        .verify(&tampered, &policy, &original)
        .expect("verify must surface a failure");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::ProofInvalid)
    );
}

/// Truncating the serialized artifact must be rejected by the
/// canonical decoder.
#[test]
fn truncating_authorization_fails_to_deserialize() {
    let (payment, policy, witness, _secrets) = fixture();
    let auth = build_authorization(&payment, &policy, &witness);
    let bytes = serialize(&auth);

    // Drop the last byte repeatedly across the header, the statement
    // boundary, the repetition-count word, the first byte of the
    // first repetition, and a random middle cut. Every truncation
    // must reject. We avoid iterating every byte of a multi-KB
    // proof to keep the test fast; the proof decoder is exercised
    // end-to-end by `sdk_serialization_tests` and by the fuzz
    // target `fuzz_authorization_decode`.
    const HEADER_LEN: usize = 1 + 1 + 16 + 32 + 32 + 32;
    let statement_start = HEADER_LEN;
    let cuts = [
        0usize,
        1,
        HEADER_LEN - 1,
        statement_start,
        statement_start + 1,
        bytes.len() / 2,
        bytes.len() - 1,
    ];
    for cut in cuts {
        assert!(
            deserialize(&bytes[..cut]).is_err(),
            "cut at {cut} must be rejected"
        );
    }
}

/// Appending any byte to a well-formed serialization must be rejected:
/// the decoder is strict and refuses trailing bytes.
#[test]
fn appending_bytes_fails_to_deserialize() {
    let (payment, policy, witness, _secrets) = fixture();
    let auth = build_authorization(&payment, &policy, &witness);
    let mut bytes = serialize(&auth);

    for tail in [0x00u8, 0x01, 0x55, 0xff] {
        bytes.push(tail);
        assert!(
            deserialize(&bytes).is_err(),
            "trailing {tail:#x} must be rejected"
        );
        bytes.pop();
    }
}

/// Replay attack: an authorization produced for one payment must not
/// verify when presented under a *different* payment record. The
/// payment_id check trips first.
#[test]
fn replaying_artifact_against_another_payment_fails() {
    let (payment, policy, witness, _secrets) = fixture();
    let auth = build_authorization(&payment, &policy, &witness);

    // Distinct payment record: same shape, different id and nonce.
    let other_payment = Payment {
        payment_id: [0xaa; 32],
        nonce: [0xbb; 32],
        ..payment
    };

    let sdk = Sdk::new(SdkConfig::default());
    let result = sdk
        .verify(&other_payment, &policy, &auth)
        .expect("verify must surface a failure");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::PaymentMismatch)
    );
}

/// Defense-in-depth: the SDK never silently picks a backend. An
/// authorization produced under SHA-256 must not verify under a
/// SHAKE256 configuration even when *no* field is mutated.
#[test]
fn cross_backend_verification_is_a_hard_rejection() {
    let (payment, policy, witness, _secrets) = fixture();
    let auth = build_authorization(&payment, &policy, &witness);

    let shake_cfg = SdkConfig::new(
        SdkConfig::default().protocol_version(),
        crypto_core::Shake256Backend::ID,
        SdkConfig::default().repetitions(),
        false,
    );
    let shake_sdk = Sdk::new(shake_cfg);
    let err = shake_sdk
        .verify(&payment, &policy, &auth)
        .expect_err("cross-backend verification must error");
    assert_eq!(err, SdkError::BackendMismatch);
}

/// An authorization produced under SHA-256 also cannot be deserialized
/// as if it were an unsupported backend; we flip the backend id bytes
/// inside the encoding and confirm `deserialize` rejects with the
/// `BackendUnsupported` mapping.
#[test]
fn deserializer_rejects_unknown_backend_in_bytes() {
    let (payment, policy, witness, _secrets) = fixture();
    let auth = build_authorization(&payment, &policy, &witness);
    let mut bytes = serialize(&auth);

    // Header layout: backend_id occupies bytes [2..18].
    bytes[2..18].copy_from_slice(b"unknown-v99\0\0\0\0\0");
    assert!(matches!(
        deserialize(&bytes),
        Err(SdkError::BackendUnsupported)
    ));
}

/// An artifact bearing an unsupported version byte must be rejected
/// by the decoder with `VersionUnsupported`.
#[test]
fn deserializer_rejects_unknown_artifact_version_in_bytes() {
    let (payment, policy, witness, _secrets) = fixture();
    let auth = build_authorization(&payment, &policy, &witness);
    let mut bytes = serialize(&auth);
    bytes[0] = sdk::AUTHORIZATION_VERSION.wrapping_add(1);
    assert!(matches!(
        deserialize(&bytes),
        Err(SdkError::VersionUnsupported)
    ));
}

/// An artifact bearing an unsupported protocol version byte must be
/// rejected by the decoder with `VersionUnsupported`.
#[test]
fn deserializer_rejects_unknown_protocol_version_in_bytes() {
    let (payment, policy, witness, _secrets) = fixture();
    let auth = build_authorization(&payment, &policy, &witness);
    let mut bytes = serialize(&auth);
    bytes[1] = 99;
    assert!(matches!(
        deserialize(&bytes),
        Err(SdkError::VersionUnsupported)
    ));
}

/// Round-trip via serialize → deserialize must reproduce an
/// authorization that verifies against the same `(payment, policy)`.
#[test]
fn serialize_deserialize_round_trip_verifies() {
    let (payment, policy, witness, _secrets) = fixture();
    let auth = build_authorization(&payment, &policy, &witness);

    let bytes = serialize(&auth);
    let recovered = deserialize(&bytes).expect("well-formed bytes must decode");
    let sdk = Sdk::new(SdkConfig::default());
    let result = sdk
        .verify(&payment, &policy, &recovered)
        .expect("verify must succeed");
    assert!(result.is_valid(), "round-tripped artifact must verify");

    // And the identity must be stable.
    assert_eq!(
        sdk::authorization_id(&auth),
        sdk::authorization_id(&recovered)
    );
}

/// The SDK must bound decoder work. A crafted input claiming an
/// enormous repetition count must be rejected without panic.
#[test]
fn deserializer_bounded_against_oversize_repetitions() {
    let (payment, policy, witness, _secrets) = fixture();
    let auth = build_authorization(&payment, &policy, &witness);
    let mut bytes = serialize(&auth);

    // After the header (114 bytes) the proof bytes start. We replace
    // the proof-region with a minimal header containing an absurd
    // repetition count. The deserializer must reject — never panic.
    let header_len = 114;
    let proof_header = &mut bytes[header_len..];
    // Truncate to a single proof header byte (version) plus 5 bytes
    // for protocol + backend + 4-byte repetition count.
    proof_header[..1].copy_from_slice(&[proof::encoding::ENCODING_VERSION]);
    proof_header[1] = proof::encoding::PROTOCOL_ID;
    proof_header[2..18].copy_from_slice(Sha256Backend::ID.as_bytes());
    proof_header[18..22].copy_from_slice(&u32::MAX.to_be_bytes());
    // Trim the trailing bytes (the real proof) so the total length
    // matches what we wrote.
    bytes.truncate(header_len + 22);

    assert!(deserialize(&bytes).is_err());
}
