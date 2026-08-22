//! Criterion benchmarks for hashing and commitments.

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::{commit, CommitmentRandomness, HashFunction, Sha256Hash};

fn bench_sha256_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    for size in [0usize, 64, 1024, 65536] {
        let data = vec![0xAB_u8; size];
        group.throughput(criterion::Throughput::Bytes(size as u64));
        group.bench_with_input(format!("hash_{size}_bytes"), &data, |b, d| {
            b.iter(|| Sha256Hash::hash(std::hint::black_box(d)))
        });
    }
    group.finish();
}

fn bench_commit_open(c: &mut Criterion) {
    let randomness = CommitmentRandomness::new(vec![7u8; 32].into()).expect("32 bytes");
    let message = vec![0x5A_u8; 256];
    let commitment = commit::<Sha256Hash>(&message, &randomness);

    let mut group = c.benchmark_group("commitment");
    group.bench_function("commit_256b", |b| {
        b.iter(|| commit::<Sha256Hash>(std::hint::black_box(&message), &randomness))
    });
    group.bench_function("open_valid_256b", |b| {
        b.iter(|| {
            crypto_core::open::<Sha256Hash>(
                std::hint::black_box(&commitment),
                std::hint::black_box(&message),
                &randomness,
            )
        })
    });
    group.finish();
}

criterion_group!(benches, bench_sha256_hash, bench_commit_open);
criterion_main!(benches);
