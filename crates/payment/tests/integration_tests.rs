//! End-to-end payment authorization tests.
//!
//! Covers the Phase 7 matrix: threshold/amount satisfaction, partial
//! credential validity, insufficient credentials, over-limit amounts,
//! and tamper detection after proof generation.

use crypto_core::{Digest, SecretBytes};
use payment::{authorize, verify_authorization, PaymentError, PaymentStatement, PrivateWitness};
use policy::{credential_commitment, CredentialPolicy, Policy};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Builds `n` credential pairs (secret + matching commitment).
fn fixture(n: usize) -> (Vec<SecretBytes>, Vec<CredentialPolicy>) {
    (0..n)
        .map(|i| {
            let secret = SecretBytes::new(vec![i as u8 + 1, 0xbe, 0xef]);
            (
                secret.clone(),
                CredentialPolicy {
                    expected_commitment: credential_commitment(&secret),
                },
            )
        })
        .unzip()
}

fn witness(secrets: &[SecretBytes]) -> PrivateWitness {
    PrivateWitness {
        credential_secrets: secrets.to_vec(),
    }
}

fn statement(policy: &Policy, amount: u64) -> PaymentStatement {
    PaymentStatement {
        payment_id: Digest::new([11; 32]),
        amount: payment::Amount {
            value: amount,
            unit: payment::AmountUnit::Cents,
        },
        recipient_commitment: Digest::new([0x77; 32]),
        policy_id: policy.policy_id(),
        circuit_id: circuit::CircuitId::from_digest(Digest::new([0; 32])),
        protocol_version: payment::PROTOCOL_VERSION,
        nonce: [0u8; 32],
    }
}

/// 2-of-3 policy with a comfortable cap.
fn policy_2_of_3(credentials: Vec<CredentialPolicy>) -> Policy {
    Policy::And {
        policies: vec![
            Policy::Threshold { k: 2, credentials },
            Policy::AmountAtMost { limit: 100 },
        ],
    }
}

#[test]
fn test_a_two_of_three_with_amount_under_limit_verifies() {
    let (secrets, credentials) = fixture(3);
    let policy = policy_2_of_3(credentials);
    let statement = statement(&policy, 50);

    let mut rng = ChaCha20Rng::seed_from_u64(0xA);
    let proof = authorize(&statement, &witness(&secrets), &policy, &mut rng).expect("proves");
    assert_eq!(verify_authorization(&statement, &proof, &policy), Ok(true));
}

#[test]
fn test_b_one_invalid_plus_two_valid_verifies_for_two_of_three() {
    let (mut secrets, credentials) = fixture(3);
    // Corrupt exactly one credential: two valid remain.
    secrets[1] = SecretBytes::new(vec![0xde, 0xad, 0xbe, 0xef]);
    let policy = policy_2_of_3(credentials);
    let statement = statement(&policy, 60);

    let mut rng = ChaCha20Rng::seed_from_u64(0xB);
    let proof = authorize(&statement, &witness(&secrets), &policy, &mut rng)
        .expect("two valid of three suffice");
    assert_eq!(verify_authorization(&statement, &proof, &policy), Ok(true));
}

#[test]
fn test_c_only_one_valid_credential_fails() {
    let (mut secrets, credentials) = fixture(3);
    // Two corrupted: only one valid remains, below k = 2.
    secrets[1] = SecretBytes::new(vec![0xde, 0xad, 0xbe, 0xef]);
    secrets[2] = SecretBytes::new(vec![0xfe, 0xed, 0xfa, 0xce]);
    let policy = policy_2_of_3(credentials);
    let statement = statement(&policy, 50);

    let mut rng = ChaCha20Rng::seed_from_u64(0xC);
    let result = authorize(&statement, &witness(&secrets), &policy, &mut rng);
    assert!(
        matches!(result, Err(PaymentError::CredentialCommitmentMismatch)),
        "expected credential failure, got {result:?}"
    );
}

#[test]
fn test_d_amount_over_limit_fails() {
    let (secrets, credentials) = fixture(3);
    let policy = policy_2_of_3(credentials);
    let statement = statement(&policy, 101); // limit is 100

    let mut rng = ChaCha20Rng::seed_from_u64(0xD);
    let result = authorize(&statement, &witness(&secrets), &policy, &mut rng);
    assert!(
        matches!(result, Err(PaymentError::AmountExceedsLimit)),
        "expected amount failure, got {result:?}"
    );
}

#[test]
fn test_e_tampered_public_field_breaks_verification() {
    let (secrets, credentials) = fixture(3);
    let policy = policy_2_of_3(credentials);
    let statement = statement(&policy, 42);

    let mut rng = ChaCha20Rng::seed_from_u64(0xE);
    let proof = authorize(&statement, &witness(&secrets), &policy, &mut rng).expect("proves");

    // Tamper with the public amount after proof generation.
    let tampered_amount = PaymentStatement {
        amount: payment::Amount {
            value: 43,
            unit: payment::AmountUnit::Cents,
        },
        ..statement
    };
    let verdict = verify_authorization(&tampered_amount, &proof, &policy);
    assert_ne!(verdict, Ok(true), "amount tampering must be detected");
    assert_eq!(
        verdict,
        Err(PaymentError::StatementMismatch),
        "bound transcript must mismatch"
    );

    // Tamper with the recipient binding as well.
    let tampered_recipient = PaymentStatement {
        recipient_commitment: Digest::new([0x99; 32]),
        ..statement
    };
    assert_eq!(
        verify_authorization(&tampered_recipient, &proof, &policy),
        Err(PaymentError::StatementMismatch)
    );

    // Tamper with the policy id.
    let tampered_policy_id = PaymentStatement {
        policy_id: policy::PolicyId::from_digest(Digest::new([0x31; 32])),
        ..statement
    };
    assert_eq!(
        verify_authorization(&tampered_policy_id, &proof, &policy),
        Err(PaymentError::PolicyIdMismatch)
    );
}

#[test]
fn proofs_are_nondeterministic_but_independently_verifiable() {
    let (secrets, credentials) = fixture(3);
    let policy = policy_2_of_3(credentials);
    let statement = statement(&policy, 25);

    let p1 = authorize(
        &statement,
        &witness(&secrets),
        &policy,
        &mut ChaCha20Rng::seed_from_u64(1),
    )
    .expect("proves");
    let p2 = authorize(
        &statement,
        &witness(&secrets),
        &policy,
        &mut ChaCha20Rng::seed_from_u64(2),
    )
    .expect("proves");

    // Fresh randomness per repetition yields distinct artifacts…
    assert_ne!(format!("{p1:?}"), format!("{p2:?}"));

    // …both verify, and each verifies under any RNG state.
    assert_eq!(verify_authorization(&statement, &p1, &policy), Ok(true));
    assert_eq!(verify_authorization(&statement, &p2, &policy), Ok(true));
}
