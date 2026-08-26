//! Criterion benchmark comparing the SHA-256 and SHAKE256 backends for full
//! proof generation and verification. This quantifies the concrete cost of
//! the post-quantum-ready backend path against the default SHA-256 path.

use ark_ed25519::Fr;
use circuit::CircuitBuilder;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use crypto_core::backend::{CryptoBackend, Sha256Backend, Shake256Backend};
use mpc::PublicValue;
use proof::{ProtocolConfig, Prover, Statement, Verifier};
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

fn prove_with<B: CryptoBackend>(
    circuit: &circuit::Circuit<Fr>,
    statement: &Statement,
    witness: Vec<Fr>,
    reps: u32,
) -> proof::NonInteractiveProof {
    let mut prover = Prover::new(
        circuit,
        statement,
        witness,
        ChaCha20Rng::seed_from_u64(1),
        ProtocolConfig::<B>::default(),
    )
    .expect("valid");
    prover.prove(reps).expect("valid")
}

fn bench_prove(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend/prove");
    for size in [10usize, 100, 1000] {
        for reps in [1u32, 10, 50] {
            if size == 1000 && reps > 10 {
                continue;
            }
            let (circuit, statement, witness) = fixture(size);
            group.bench_with_input(
                BenchmarkId::new(format!("sha256_nodes_{size}"), reps),
                &(circuit.clone(), statement.clone(), witness.clone(), reps),
                |b, (circuit, statement, witness, reps)| {
                    b.iter(|| {
                        prove_with::<Sha256Backend>(circuit, statement, witness.clone(), *reps)
                    });
                },
            );
            let (circuit, statement, witness) = fixture(size);
            group.bench_with_input(
                BenchmarkId::new(format!("shake256_nodes_{size}"), reps),
                &(circuit.clone(), statement.clone(), witness.clone(), reps),
                |b, (circuit, statement, witness, reps)| {
                    b.iter(|| {
                        prove_with::<Shake256Backend>(circuit, statement, witness.clone(), *reps)
                    });
                },
            );
        }
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("backend/verify");
    for size in [10usize, 100, 1000] {
        for reps in [1u32, 10, 50] {
            if size == 1000 && reps > 10 {
                continue;
            }
            let (circuit, statement, witness) = fixture(size);
            let sha_proof =
                prove_with::<Sha256Backend>(&circuit, &statement, witness.clone(), reps);
            group.bench_with_input(
                BenchmarkId::new(format!("sha256_nodes_{size}"), reps),
                &(circuit.clone(), statement.clone(), sha_proof),
                |b, (circuit, statement, proof)| {
                    b.iter(|| {
                        Verifier::<Sha256Backend>::new()
                            .verify(circuit, statement, std::hint::black_box(proof))
                            .expect("no error")
                    });
                },
            );
            let (circuit, statement, witness) = fixture(size);
            let shake_proof =
                prove_with::<Shake256Backend>(&circuit, &statement, witness.clone(), reps);
            group.bench_with_input(
                BenchmarkId::new(format!("shake256_nodes_{size}"), reps),
                &(circuit.clone(), statement.clone(), shake_proof),
                |b, (circuit, statement, proof)| {
                    b.iter(|| {
                        Verifier::<Shake256Backend>::new()
                            .verify(circuit, statement, std::hint::black_box(proof))
                            .expect("no error")
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(benches, bench_prove, bench_verify);
criterion_main!(benches);
