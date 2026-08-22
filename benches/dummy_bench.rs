//! Minimal Criterion benchmark scaffolding. No cryptographic benchmarks yet.

use criterion::{criterion_group, criterion_main, Criterion};

fn bench_noop(c: &mut Criterion) {
    c.bench_function("noop", |b| b.iter(|| std::hint::black_box(2 + 2)));
}

criterion_group!(benches, bench_noop);
criterion_main!(benches);
