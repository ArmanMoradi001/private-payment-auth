//! Criterion benchmarks for Shamir split and reconstruct.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use crypto_core::SecretBytes;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use secret_sharing::split;

fn bench_secret() -> SecretBytes {
    SecretBytes::new((0u8..32).collect())
}

fn bench_split(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir_split");
    for (threshold, share_count) in [(2usize, 3usize), (2, 10), (10, 20)] {
        group.bench_with_input(
            BenchmarkId::new("t_n", format!("{threshold}-of-{share_count}")),
            &(threshold, share_count),
            |b, &(t, n)| {
                let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
                b.iter(|| split(&bench_secret(), t, n, &mut rng).expect("valid split"));
            },
        );
    }
    group.finish();
}

fn bench_reconstruct(c: &mut Criterion) {
    let mut group = c.benchmark_group("shamir_reconstruct");
    for (threshold, share_count) in [(2usize, 3usize), (2, 10), (10, 20)] {
        group.bench_with_input(
            BenchmarkId::new("t_n", format!("{threshold}-of-{share_count}")),
            &(threshold, share_count),
            |b, &(t, n)| {
                let mut rng = ChaCha20Rng::seed_from_u64(0xC0FFEE);
                let shares = split(&bench_secret(), t, n, &mut rng).expect("valid split");
                b.iter(|| secret_sharing::reconstruct(&shares[..t]).expect("valid reconstruct"));
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench_split, bench_reconstruct);
criterion_main!(benches);
