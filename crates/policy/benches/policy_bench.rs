//! Benchmarks for the policy pipeline: validation, normalization, encoding,
//! `PolicyId` derivation, compilation, and reference evaluation.
//!
//! Run with `cargo bench -p policy`.

use ark_ed25519::Fr;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto_core::SecretBytes;
use policy::{
    compile_with_layout, credential_commitment, normalize, policy_id, validate, AmountLimit,
    CredentialId, Policy, PolicyWitness, ThresholdK,
};

fn sample_credential(id: u64) -> CredentialId {
    let mut bytes = [0u8; 32];
    bytes[..8].copy_from_slice(&id.to_le_bytes());
    let secret = SecretBytes::new(bytes.to_vec());
    CredentialId::from_commitment(credential_commitment(&secret))
}

fn build_policy(depth: usize) -> Policy {
    let leaf = Policy::Credential(sample_credential(1));
    let mut node = leaf;
    for i in 0..depth {
        let cred = Policy::Credential(sample_credential(2 + i as u64));
        if i % 2 == 0 {
            node = Policy::And(vec![node, cred]);
        } else {
            node = Policy::Or(vec![node, cred]);
        }
    }
    let threshold = Policy::Threshold {
        k: ThresholdK::new(2),
        members: vec![
            node,
            Policy::Credential(sample_credential(99)),
            Policy::AmountAtMost(AmountLimit::new(1_000_000)),
        ],
    };
    Policy::Or(vec![threshold, Policy::AmountAtMost(AmountLimit::new(500))])
}

fn satisfying_witness(policy: &Policy) -> PolicyWitness {
    let mut w = PolicyWitness::new();
    let ids = {
        fn collect(p: &Policy, out: &mut Vec<CredentialId>) {
            match p {
                Policy::Credential(id) => out.push(*id),
                Policy::AmountAtMost(_) => {}
                Policy::Threshold { members, .. } | Policy::And(members) | Policy::Or(members) => {
                    for m in members {
                        collect(m, out);
                    }
                }
            }
        }
        let mut v = Vec::new();
        collect(policy, &mut v);
        v
    };
    for id in ids {
        w = w.with_credential(id, SecretBytes::new(vec![0u8; 32]));
    }
    w.with_amount(AmountLimit::new(0))
}

fn bench_pipeline(c: &mut Criterion) {
    let policy = build_policy(6);

    c.bench_function("validate", |b| {
        b.iter(|| validate(black_box(&policy)).unwrap())
    });

    c.bench_function("normalize", |b| {
        b.iter(|| normalize(black_box(&policy)).unwrap())
    });

    c.bench_function("encode", |b| b.iter(|| black_box(&policy).encode()));

    c.bench_function("policy_id", |b| b.iter(|| policy_id(black_box(&policy))));

    let compiled = compile_with_layout::<Fr>(&policy).unwrap();
    let witness = satisfying_witness(&policy);

    c.bench_function("compile", |b| {
        b.iter(|| compile_with_layout::<Fr>(black_box(&policy)).unwrap())
    });

    c.bench_function("compiled_stats", |b| {
        b.iter(|| black_box(&compiled).metadata.node_count)
    });

    c.bench_function("reference_evaluate", |b| {
        b.iter(|| {
            compiled
                .reference_evaluate(black_box(&policy), &witness)
                .unwrap()
        })
    });
}

criterion_group!(benches, bench_pipeline);
criterion_main!(benches);
