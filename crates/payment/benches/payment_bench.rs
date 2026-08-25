//! Criterion benchmarks for the phase 8 payment domain: range-check
//! circuit construction, statement construction and id hashing, and
//! end-to-end proving/verification with the bounded amount constraint.

use ark_ed25519::Fr;
use circuit::CircuitBuilder;
use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::SecretBytes;
use payment::{
    authorize_payment, payment_circuit_id, verify_payment_authorization, Amount, AmountUnit,
    PaymentStatement, PrivateWitness, PROTOCOL_VERSION,
};
use policy::{credential_commitment, CredentialPolicy, Policy};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

const LIMIT: u64 = 100;

fn policy_2_of_3() -> (Policy, Vec<SecretBytes>) {
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
    (policy, secrets)
}

fn statement(policy: &Policy) -> PaymentStatement {
    PaymentStatement {
        payment_id: crypto_core::Digest::new([9; 32]),
        amount: Amount {
            value: 42,
            unit: AmountUnit::Cents,
        },
        recipient_commitment: crypto_core::Digest::new([0xab; 32]),
        policy_id: policy.policy_id(),
        circuit_id: payment_circuit_id(policy).expect("compiles"),
        protocol_version: PROTOCOL_VERSION,
        nonce: [0x5au8; 32],
    }
}

/// Range-check circuit construction alone (the `policy::range_check`
/// gadget over a fresh builder).
fn bench_range_check_construction(c: &mut Criterion) {
    c.bench_function("payment/range_check_circuit_construction", |b| {
        b.iter(|| {
            let mut builder = CircuitBuilder::<Fr>::new();
            let amount = builder.secret_input();
            let limit = builder.constant(Fr::from(LIMIT));
            let bits = policy::range_check::RangeCheckBits::declare(&mut builder);
            let outputs = policy::range_check::prove_bounded_difference::<Fr>(
                &mut builder,
                amount,
                limit,
                &bits,
            )
            .expect("wires");
            for node in outputs {
                builder.output(node).expect("marks");
            }
            builder.build().expect("valid")
        })
    });
}

fn bench_statement_construction(c: &mut Criterion) {
    let (policy, _) = policy_2_of_3();
    let circuit_id = payment_circuit_id(&policy).expect("compiles");

    // Statement assembly + semantic id hashing.
    c.bench_function("payment/statement_and_payment_id", |b| {
        b.iter(|| {
            let statement = statement(std::hint::black_box(&policy));
            std::hint::black_box(statement.encode());
            std::hint::black_box(
                <crypto_core::Sha256Hash as crypto_core::HashFunction>::hash_domain(
                    payment::PAYMENT_ID_DOMAIN,
                    &[7u8; 32],
                ),
            );
            std::hint::black_box(circuit_id);
        })
    });
}

fn bench_prove(c: &mut Criterion) {
    let (policy, secrets) = policy_2_of_3();
    let stmt = statement(&policy);
    let witness = PrivateWitness::new(secrets, stmt.amount, LIMIT);

    c.bench_function("payment/prove_2of3_bounded_amount", |b| {
        b.iter(|| {
            authorize_payment(
                std::hint::black_box(&stmt),
                &witness,
                &policy,
                &mut ChaCha20Rng::seed_from_u64(1),
            )
            .expect("proves")
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let (policy, secrets) = policy_2_of_3();
    let stmt = statement(&policy);
    let witness = PrivateWitness::new(secrets, stmt.amount, LIMIT);
    let proof = authorize_payment(&stmt, &witness, &policy, &mut ChaCha20Rng::seed_from_u64(2))
        .expect("proves");

    c.bench_function("payment/verify_2of3_bounded_amount", |b| {
        b.iter(|| {
            verify_payment_authorization(
                std::hint::black_box(&stmt),
                std::hint::black_box(&proof),
                &policy,
            )
            .expect("verifies")
        })
    });
}

criterion_group!(
    benches,
    bench_range_check_construction,
    bench_statement_construction,
    bench_prove,
    bench_verify
);
criterion_main!(benches);
