//! End-to-end payment authorization tests for the phase 8 domain:
//! bounded amounts, boundary values, wrap-around rejection, and
//! statement mutation binding.

use crypto_core::{Digest, SecretBytes};
use payment::{
    authorize_payment, decompose, payment_circuit_id, verify_payment_authorization, Amount,
    AmountUnit, AuthorizationRelation, PaymentError, PaymentStatement, PrivateWitness,
    PROTOCOL_VERSION,
};
use policy::{credential_commitment, CredentialPolicy, Policy};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const LIMIT: u64 = 100;

fn rng(seed: u64) -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(seed)
}

struct Fixture {
    policy: Policy,
    statement: PaymentStatement,
    witness: PrivateWitness,
}

fn fixture(amount: u64) -> Fixture {
    let mut secrets = Vec::new();
    let credentials = (0..3)
        .map(|_| {
            let secret = SecretBytes::new(vec![secrets.len() as u8 + 1, 0xbe, 0xef]);
            secrets.push(secret.clone());
            CredentialPolicy {
                expected_commitment: credential_commitment(&secret),
            }
        })
        .collect();
    let policy = Policy::And {
        policies: vec![
            Policy::Threshold { k: 2, credentials },
            Policy::AmountAtMost { limit: LIMIT },
        ],
    };
    let statement = PaymentStatement {
        payment_id: Digest::new([9u8; 32]),
        amount: Amount {
            value: amount,
            unit: AmountUnit::Cents,
        },
        recipient_commitment: Digest::new([0xabu8; 32]),
        policy_id: policy.policy_id(),
        circuit_id: payment_circuit_id(&policy).expect("compiles"),
        protocol_version: PROTOCOL_VERSION,
        nonce: [0x5au8; 32],
    };
    let witness = PrivateWitness::new(secrets, statement.amount, LIMIT);
    Fixture {
        policy,
        statement,
        witness,
    }
}

#[test]
fn valid_two_of_three_with_amount_under_limit_verifies() {
    let f = fixture(42);
    let proof =
        authorize_payment(&f.statement, &f.witness, &f.policy, &mut rng(1)).expect("proves");
    assert_eq!(
        verify_payment_authorization(&f.statement, &proof, &f.policy),
        Ok(true)
    );
}

#[test]
fn boundary_amounts_all_verify() {
    // 0, 1, limit − 1, and exactly limit are all within range.
    for amount in [0u64, 1, LIMIT - 1, LIMIT] {
        let f = fixture(amount);
        let proof = authorize_payment(&f.statement, &f.witness, &f.policy, &mut rng(2))
            .unwrap_or_else(|e| panic!("amount {amount} must authorize: {e:?}"));
        assert_eq!(
            verify_payment_authorization(&f.statement, &proof, &f.policy),
            Ok(true),
            "amount {amount}"
        );
    }
}

#[test]
fn amounts_above_the_limit_fail_generation() {
    for amount in [LIMIT + 1, 1_000, u64::MAX] {
        let f = fixture(amount);
        let result = authorize_payment(&f.statement, &f.witness, &f.policy, &mut rng(3));
        assert!(
            matches!(result, Err(PaymentError::AmountExceedsLimit)),
            "amount {amount} must fail generation, got {result:?}"
        );
    }
}

#[test]
fn lying_digit_witnesses_are_rejected() {
    // A witness claiming a difference decomposition inconsistent with
    // (limit − amount) is caught before any proving work happens.
    let f = fixture(40);
    let mut lying = f.witness.clone();
    lying.difference_bits = decompose(LIMIT - 39);
    assert_eq!(
        AuthorizationRelation::validate(&f.statement, &lying, &f.policy),
        Err(PaymentError::InvalidBitWitness)
    );

    // Non-canonical value digits likewise.
    let mut lying = f.witness.clone();
    lying.amount_bits[0] = !lying.amount_bits[0];
    assert_eq!(
        AuthorizationRelation::validate(&f.statement, &lying, &f.policy),
        Err(PaymentError::InvalidBitWitness)
    );
}

#[test]
fn statement_mutations_break_verification() {
    let f = fixture(42);
    let proof =
        authorize_payment(&f.statement, &f.witness, &f.policy, &mut rng(4)).expect("proves");

    let mutations: Vec<(&str, PaymentStatement)> = vec![
        (
            "payment_id",
            PaymentStatement {
                payment_id: Digest::new([0xffu8; 32]),
                ..f.statement
            },
        ),
        (
            "amount",
            PaymentStatement {
                amount: Amount {
                    value: 43,
                    unit: AmountUnit::Cents,
                },
                ..f.statement
            },
        ),
        (
            "recipient",
            PaymentStatement {
                recipient_commitment: Digest::new([0xfeu8; 32]),
                ..f.statement
            },
        ),
        (
            "nonce",
            PaymentStatement {
                nonce: [0x01u8; 32],
                ..f.statement
            },
        ),
        (
            "policy_id",
            PaymentStatement {
                policy_id: policy::PolicyId::from_digest(Digest::new([0xfdu8; 32])),
                ..f.statement
            },
        ),
        (
            "circuit_id",
            PaymentStatement {
                circuit_id: circuit::CircuitId::from_digest(Digest::new([0xfcu8; 32])),
                ..f.statement
            },
        ),
        (
            "version",
            PaymentStatement {
                protocol_version: PROTOCOL_VERSION + 1,
                ..f.statement
            },
        ),
    ];

    for (name, mutated) in &mutations {
        let verdict = verify_payment_authorization(mutated, &proof, &f.policy);
        assert_ne!(
            verdict,
            Ok(true),
            "mutation of {name} must break verification"
        );
    }

    // The untouched statement still verifies after all this tampering.
    assert_eq!(
        verify_payment_authorization(&f.statement, &proof, &f.policy),
        Ok(true)
    );
}
