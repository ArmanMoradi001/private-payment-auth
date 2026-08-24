//! Criterion benchmarks for the MPCitH layer: view generation,
//! commitment, a single repetition, full prove/verify, and proof
//! serialization across circuit sizes and repetition counts.

use ark_ed25519::Fr;
use circuit::CircuitBuilder;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mpc::PublicValue;
use mpcith::{MpcithProver, MpcithVerifier, PartyId, RandomChallengeSource, Statement};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

/// Chain circuit with `size` nodes: one secret input, one public input,
/// then alternating mul/add gates.
fn build_chain(size: usize) -> circuit::Circuit<Fr> {
    assert!(size >= 3);
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    let p = b.public_input();
    let (mut prev2, mut prev1) = (x, p);

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

fn fixture(size: usize) -> (circuit::Circuit<Fr>, Statement, Vec<Fr>) {
    let circuit = build_chain(size);
    // Expected output is computed by the reference evaluator.
    let secrets = vec![Fr::from(7u64)];
    let publics = vec![Fr::from(11u64); circuit.num_public_inputs()];
    let outputs = circuit::evaluate_reference(&circuit, &secrets, &publics).expect("valid");
    let statement = Statement {
        circuit_id: circuit.compute_id(),
        public_inputs: publics.into_iter().map(PublicValue::new).collect(),
        expected_outputs: outputs.into_iter().map(PublicValue::new).collect(),
    };
    (circuit, statement, secrets)
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpcith/prove");
    for size in [10usize, 100, 1000] {
        for reps in [1u32, 10, 50] {
            if size == 1000 && reps == 50 {
                continue; // keeps total bench time bounded
            }
            let (circuit, statement, witness) = fixture(size);
            group.bench_with_input(
                BenchmarkId::new(format!("nodes_{size}"), reps),
                &reps,
                |b, &reps| {
                    b.iter(|| {
                        let mut prover = MpcithProver::new(
                            &circuit,
                            &statement,
                            witness.clone(),
                            Box::new(RandomChallengeSource::new(ChaCha20Rng::seed_from_u64(
                                reps as u64,
                            ))),
                            ChaCha20Rng::seed_from_u64(1234),
                        )
                        .expect("valid");
                        prover.prove(reps).expect("valid")
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpcith/verify");
    for size in [10usize, 100, 1000] {
        for reps in [1u32, 10, 50] {
            if size == 1000 && reps == 50 {
                continue;
            }
            let (circuit, statement, witness) = fixture(size);
            let mut prover = MpcithProver::new(
                &circuit,
                &statement,
                witness,
                Box::new(RandomChallengeSource::new(ChaCha20Rng::seed_from_u64(9))),
                ChaCha20Rng::seed_from_u64(1234),
            )
            .expect("valid");
            let proof = prover.prove(reps).expect("valid");

            group.bench_with_input(
                BenchmarkId::new(format!("nodes_{size}"), reps),
                &proof,
                |b, proof| {
                    b.iter(|| {
                        MpcithVerifier::new()
                            .verify(&statement, std::hint::black_box(proof), &circuit)
                            .expect("no error")
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_single_repetition(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpcith/single_repetition");
    for size in [10usize, 100, 1000] {
        let (circuit, statement, witness) = fixture(size);
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            b.iter(|| {
                let mut prover = MpcithProver::new(
                    &circuit,
                    &statement,
                    witness.clone(),
                    Box::new(mpcith::DeterministicChallengeSource::repeating(
                        PartyId::new(0).unwrap(),
                        1,
                    )),
                    ChaCha20Rng::seed_from_u64(5),
                )
                .expect("valid");
                prover.prove(1).expect("valid")
            });
        });
    }
    group.finish();
}

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("mpcith/serialization");
    for size in [10usize, 100, 1000] {
        let (circuit, statement, witness) = fixture(size);
        let mut prover = MpcithProver::new(
            &circuit,
            &statement,
            witness,
            Box::new(RandomChallengeSource::new(ChaCha20Rng::seed_from_u64(4))),
            ChaCha20Rng::seed_from_u64(77),
        )
        .expect("valid");
        let proof = prover.prove(10).expect("valid");

        group.bench_with_input(BenchmarkId::from_parameter(size), &proof, |b, proof| {
            b.iter(|| mpcith::serialize_proof(std::hint::black_box(proof)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_prove,
    bench_verify,
    bench_single_repetition,
    bench_serialization
);
criterion_main!(benches);
