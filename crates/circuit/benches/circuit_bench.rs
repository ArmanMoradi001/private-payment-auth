//! Criterion benchmarks: construction, validation, serialization,
//! identity hashing, and evaluation at several circuit sizes.

use ark_ed25519::Fr;
use circuit::{evaluate_mpc, evaluate_reference, CircuitBuilder};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mpc::{MpcSimulator, ShareContext};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Builds a Fibonacci-style chain of exactly `size` nodes: one secret
/// input, one public input, then alternating mul/add gates over the
/// two most recent nodes.
fn build_chain(size: usize) -> circuit::Circuit<Fr> {
    assert!(size >= 3);
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    let y = b.public_input();
    let (mut prev2, mut prev1) = (x, y);

    while b.next_node_id().as_usize() < size {
        let next = if b.next_node_id().get().is_multiple_of(2) {
            b.add(prev2, prev1).expect("valid")
        } else {
            b.mul(prev2, prev1).expect("valid")
        };
        prev2 = prev1;
        prev1 = next;
    }

    b.output(prev1).expect("valid");
    b.build().expect("valid")
}

fn simulator(party_count: usize, seed: u64) -> MpcSimulator<Fr, ChaCha20Rng> {
    let ctx = ShareContext::new(party_count, seed, 1).expect("valid");
    let provider =
        mpc::LocalTrustedTripleProvider::new(ctx, ChaCha20Rng::seed_from_u64(seed)).expect("valid");
    MpcSimulator::new(
        ctx,
        Box::new(provider),
        ChaCha20Rng::seed_from_u64(seed + 1),
    )
    .expect("valid")
}

fn bench_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("construction");
    for size in [10usize, 100, 1000] {
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter(|| build_chain(size));
        });
    }
    group.finish();
}

fn bench_validation(c: &mut Criterion) {
    let mut group = c.benchmark_group("validation");
    for size in [10usize, 100, 1000] {
        let circuit = build_chain(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &circuit, |b, circ| {
            b.iter(|| circ.validate());
        });
    }
    group.finish();
}

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization");
    for size in [10usize, 100, 1000] {
        let circuit = build_chain(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &circuit, |b, circ| {
            b.iter(|| circuit::serialize(circ));
        });
    }
    group.finish();
}

fn bench_identity_hashing(c: &mut Criterion) {
    let mut group = c.benchmark_group("identity");
    for size in [10usize, 100, 1000] {
        let circuit = build_chain(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &circuit, |b, circ| {
            b.iter(|| circ.compute_id());
        });
    }
    group.finish();
}

fn bench_evaluation(c: &mut Criterion) {
    let mut group = c.benchmark_group("evaluation");
    for size in [10usize, 100, 1000] {
        let circuit = build_chain(size);
        let secrets = vec![Fr::from(7u64); circuit.num_secret_inputs()];
        let publics = vec![Fr::from(11u64); circuit.num_public_inputs()];
        // A fresh simulator per iteration keeps triple accounting
        // identical across iterations; its fixed setup cost is
        // amortized by Criterion over many samples.
        let mut sim = simulator(3, 99);

        group.bench_with_input(
            BenchmarkId::new("reference", size),
            &(secrets.clone(), publics.clone()),
            |b, (s, p)| b.iter(|| evaluate_reference(std::hint::black_box(&circuit), s, p)),
        );

        group.bench_with_input(BenchmarkId::new("mpc", size), &(), |b, ()| {
            b.iter(|| {
                evaluate_mpc(
                    std::hint::black_box(&circuit),
                    &secrets,
                    &publics,
                    std::hint::black_box(&mut sim),
                    None,
                )
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_construction,
    bench_validation,
    bench_serialization,
    bench_identity_hashing,
    bench_evaluation
);
criterion_main!(benches);
