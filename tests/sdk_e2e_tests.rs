//! End-to-end SDK workflow tests.
//!
//! These tests exercise the public API the way an external consumer
//! would: build `(Payment, Policy, PrivateWitness)`, run `authorize`,
//! then `verify`. They live outside the `sdk` crate so they cannot
//! reach into private internals and so they remain a faithful check on
//! the documented public surface.

use crypto_core::{CryptoBackend, Digest, SecretBytes, Sha256Backend};
use payment::{Amount, AmountUnit, Payment, PrivateWitness};
use policy::{credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sdk::{serialize, Sdk, SdkConfig, SdkError, VerificationFailure, VerificationResult};

/// Builds a sample 2-of-3 threshold policy together with a valid
/// witness for a 75-cent payment against a 100-cent cap. Mirrors the
/// fixture used by the in-crate tests so we exercise the same
/// `authorize → verify` round-trip from a public-API viewpoint.
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

fn sdk_default() -> Sdk {
    Sdk::new(SdkConfig::default())
}

#[test]
fn valid_payment_policy_witness_authorizes_and_verifies() {
    let (payment, policy, witness, _secrets) = fixture();
    let sdk = sdk_default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);

    let auth = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("valid input must authorize");

    let result = sdk
        .verify(&payment, &policy, &auth)
        .expect("verify must not error on well-formed authorization");
    assert!(result.is_valid(), "expected Valid, got {result:?}");
}

#[test]
fn invalid_credential_secret_fails_authorization() {
    // Build a witness whose preimage does NOT match the policy's
    // declared credential commitments. The plaintext relation must
    // reject before any proof work.
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

    // Wrong preimage → does not match the commitment inside `policy`.
    let bogus_secret = SecretBytes::new(vec![0xee; 32]);
    let witness = PrivateWitness::new(vec![bogus_secret], payment.amount, 100);

    let sdk = sdk_default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let err = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect_err("bad credential must fail authorization");
    assert_eq!(err, SdkError::InvalidWitness);
}

#[test]
fn amount_exceeding_limit_fails_authorization() {
    // Policy: amount must be ≤ 100 cents.
    let (payment, policy, _witness_unused, _secrets) = fixture();
    let over_amount = Amount {
        value: 250,
        unit: AmountUnit::Cents,
    };
    let over_payment = Payment {
        amount: over_amount,
        ..payment
    };
    // Witness limit equals the policy cap (100) so the only failing
    // predicate is `amount > limit`.
    let witness = PrivateWitness::new(
        vec![SecretBytes::new(vec![1, 0x0c, 0x0d])],
        over_amount,
        100,
    );

    let sdk = sdk_default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let err = sdk
        .authorize(&over_payment, &policy, &witness, &mut rng)
        .expect_err("amount > cap must fail authorization");
    assert_eq!(err, SdkError::InvalidWitness);
}

#[test]
fn payment_id_mutation_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let sdk = sdk_default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("authorize");

    let mut tampered = payment;
    tampered.payment_id = [0x99; 32];
    let result = sdk
        .verify(&tampered, &policy, &auth)
        .expect("verify must surface a failure, not an error");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::PaymentMismatch)
    );
}

#[test]
fn amount_mutation_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let sdk = sdk_default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("authorize");

    let mut tampered = payment;
    tampered.amount = Amount {
        value: 99,
        unit: AmountUnit::Cents,
    };
    let result = sdk
        .verify(&tampered, &policy, &auth)
        .expect("verify must surface a failure");
    // The verifier only short-circuits on the explicit `payment_id`
    // binding; other field mutations are caught by the cryptographic
    // statement-binding check inside the proof verifier.
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::ProofInvalid)
    );
}

#[test]
fn recipient_mutation_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let sdk = sdk_default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("authorize");

    let mut tampered = payment;
    tampered.recipient_commitment = Digest::new([0xab; 32]);
    let result = sdk
        .verify(&tampered, &policy, &auth)
        .expect("verify must surface a failure");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::ProofInvalid)
    );
}

#[test]
fn nonce_mutation_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let sdk = sdk_default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("authorize");

    let mut tampered = payment;
    tampered.nonce = [0x77; 32];
    let result = sdk
        .verify(&tampered, &policy, &auth)
        .expect("verify must surface a failure");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::ProofInvalid)
    );
}

#[test]
fn policy_mutation_invalidates_verification() {
    let (payment, policy, witness, _secrets) = fixture();
    let sdk = sdk_default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("authorize");

    let tampered_policy = Policy::AmountAtMost(AmountLimit::new(200));
    let result = sdk
        .verify(&payment, &tampered_policy, &auth)
        .expect("verify must surface a failure");
    assert_eq!(
        result,
        VerificationResult::Invalid(VerificationFailure::PolicyMismatch)
    );
}

#[test]
fn wrong_backend_config_rejects_sha256_artifact() {
    let (payment, policy, witness, _secrets) = fixture();
    let mut rng = ChaCha20Rng::seed_from_u64(7);

    // Authorize under the default (SHA-256) SDK.
    let default_sdk = Sdk::default();
    let auth = default_sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("authorize");

    // A verifier configured for SHAKE256 must refuse — never silently
    // re-encode the artifact.
    let shake_cfg = SdkConfig::new(
        default_sdk.config().protocol_version(),
        crypto_core::Shake256Backend::ID,
        default_sdk.config().repetitions(),
        false,
    );
    let shake_sdk = Sdk::new(shake_cfg);
    let err = shake_sdk
        .verify(&payment, &policy, &auth)
        .expect_err("verifier config mismatch must error");
    assert_eq!(err, SdkError::BackendMismatch);
}

#[test]
fn serialization_round_trip_then_verify_is_valid() {
    let (payment, policy, witness, _secrets) = fixture();
    let sdk = sdk_default();
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("authorize");

    let bytes = serialize(&auth);
    let recovered = sdk::deserialize(&bytes).expect("deserialize");
    let result = sdk.verify(&payment, &policy, &recovered).expect("verify");
    assert!(result.is_valid(), "round-tripped authorization must verify");
}

#[test]
fn self_verification_default_catches_pipeline_bugs() {
    let (payment, policy, witness, _secrets) = fixture();
    let sdk = sdk_default();
    assert!(sdk.config().self_verify(), "self-verify must default on");

    let mut rng = ChaCha20Rng::seed_from_u64(7);
    // The default pipeline includes self-verification; an internal
    // pipeline bug would surface as SdkError::SelfVerificationFailed.
    let _ = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("authorize must succeed for valid inputs");
}

#[test]
fn self_verification_disabled_skips_double_check() {
    let (payment, policy, witness, _secrets) = fixture();
    let cfg = SdkConfig::new(
        SdkConfig::default().protocol_version(),
        Sha256Backend::ID,
        SdkConfig::default().repetitions(),
        false,
    );
    let sdk = Sdk::new(cfg);

    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk
        .authorize(&payment, &policy, &witness, &mut rng)
        .expect("authorize must succeed");

    // Manual verification still validates the artifact.
    let result = sdk
        .verify(&payment, &policy, &auth)
        .expect("verify must surface a failure as Ok");
    assert!(result.is_valid());
}

#[test]
fn authorization_id_is_deterministic_for_same_inputs() {
    let (payment, policy, witness, _secrets) = fixture();
    let sdk = sdk_default();
    let mut rng1 = ChaCha20Rng::seed_from_u64(7);
    let mut rng2 = ChaCha20Rng::seed_from_u64(7);

    let a = sdk
        .authorize(&payment, &policy, &witness, &mut rng1)
        .expect("authorize");
    let b = sdk
        .authorize(&payment, &policy, &witness, &mut rng2)
        .expect("authorize");

    assert_eq!(sdk::authorization_id(&a), sdk::authorization_id(&b));
}
