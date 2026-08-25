//! Criterion benchmarks: FS derivation, proving, verification, and
//! serialization across circuit sizes and repetition counts.

use ark_ed25519::Fr;
use circuit::CircuitBuilder;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use mpc::PublicValue;
use proof::{ChallengeGenerator as _, FiatShamirChallengeGenerator, Prover, Statement, Verifier};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

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

fn bench_fs_derivation(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof/fs_derivation");
    let gen = FiatShamirChallengeGenerator;
    for size in [10usize, 100, 1000] {
        // Commitment count is fixed (3 per repetition), so FS cost is
        // constant; we still parameterize by the statement's circuit.
        let (_, statement, _) = fixture(size);
        let commitments: Vec<mpcith::ViewCommitment> = (0..3)
            .map(|i| mpcith::ViewCommitment::from_digest(crypto_core::Digest::new([i as u8; 32])))
            .collect();
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &_size| {
            b.iter(|| {
                gen.derive(
                    std::hint::black_box(&statement),
                    &commitments,
                    mpcith::RepetitionId::new(0),
                )
                .expect("ok")
            });
        });
    }
    group.finish();
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof/prove");
    for size in [10usize, 100, 1000] {
        for reps in [1u32, 10, 50, 100] {
            if size == 1000 && reps > 10 {
                continue; // bounded total bench time
            }
            let (circuit, statement, witness) = fixture(size);
            group.bench_with_input(
                BenchmarkId::new(format!("nodes_{size}"), reps),
                &reps,
                |b, &reps| {
                    b.iter(|| {
                        let mut prover = Prover::new(
                            &circuit,
                            &statement,
                            witness.clone(),
                            ChaCha20Rng::seed_from_u64(1),
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
    let mut group = c.benchmark_group("proof/verify");
    for size in [10usize, 100, 1000] {
        for reps in [1u32, 10, 50, 100] {
            if size == 1000 && reps > 10 {
                continue;
            }
            let (circuit, statement, witness) = fixture(size);
            let mut prover =
                Prover::new(&circuit, &statement, witness, ChaCha20Rng::seed_from_u64(2)).unwrap();
            let proof = prover.prove(reps).expect("valid");

            group.bench_with_input(
                BenchmarkId::new(format!("nodes_{size}"), reps),
                &proof,
                |b, proof| {
                    b.iter(|| {
                        Verifier::new()
                            .verify(&circuit, &statement, std::hint::black_box(proof))
                            .expect("no error")
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_serialization(c: &mut Criterion) {
    let mut group = c.benchmark_group("proof/serialization");
    for size in [10usize, 100, 1000] {
        let (circuit, statement, witness) = fixture(size);
        let mut prover =
            Prover::new(&circuit, &statement, witness, ChaCha20Rng::seed_from_u64(3)).unwrap();
        let proof = prover.prove(10).expect("valid");

        group.bench_with_input(BenchmarkId::from_parameter(size), &proof, |b, proof| {
            b.iter(|| proof::serialize_proof(std::hint::black_box(proof)));
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_fs_derivation,
    bench_prove,
    bench_verify,
    bench_serialization
);
criterion_main!(benches);
