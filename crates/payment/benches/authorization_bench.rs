//! Criterion benchmarks for the payment authorization pipeline:
//! policy compilation, proof generation, and verification for a small
//! (2-of-3 + amount cap) authorization.

use ark_ed25519::Fr;
use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::SecretBytes;
use payment::{authorize, verify_authorization, PaymentStatement, PrivateWitness};
use policy::{compile, credential_commitment, CredentialPolicy, Policy};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

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
            Policy::AmountAtMost { limit: 100 },
        ],
    };
    (policy, secrets)
}

fn statement(policy_id: policy::PolicyId) -> PaymentStatement {
    PaymentStatement {
        payment_id: crypto_core::Digest::new([9; 32]),
        amount: payment::Amount {
            value: 42,
            unit: payment::AmountUnit::Cents,
        },
        recipient_commitment: crypto_core::Digest::new([0xab; 32]),
        policy_id,
        circuit_id: circuit::CircuitId::from_digest(crypto_core::Digest::new([0; 32])),
        protocol_version: payment::PROTOCOL_VERSION,
        nonce: [0u8; 32],
    }
}

fn bench_compile(c: &mut Criterion) {
    let (policy, _) = policy_2_of_3();
    c.bench_function("authorization/compile_2of3_amount", |b| {
        b.iter(|| compile::<Fr>(std::hint::black_box(&policy)).expect("compiles"))
    });
}

fn bench_prove(c: &mut Criterion) {
    let (policy, secrets) = policy_2_of_3();
    let stmt = statement(policy.policy_id());
    let witness = PrivateWitness {
        credential_secrets: secrets,
    };

    c.bench_function("authorization/prove_2of3_reps12", |b| {
        b.iter(|| {
            authorize(
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
    let stmt = statement(policy.policy_id());
    let witness = PrivateWitness {
        credential_secrets: secrets,
    };
    let proof =
        authorize(&stmt, &witness, &policy, &mut ChaCha20Rng::seed_from_u64(2)).expect("proves");

    c.bench_function("authorization/verify_2of3_reps12", |b| {
        b.iter(|| {
            verify_authorization(std::hint::black_box(&stmt), &proof, &policy).expect("verifies")
        })
    });
}

criterion_group!(benches, bench_compile, bench_prove, bench_verify);
criterion_main!(benches);
