//! Property-based tests: for randomly generated arithmetic circuits,
//! the reference evaluation and the MPC evaluation must always agree.

use ark_ed25519::Fr;
use circuit::{evaluate_mpc, evaluate_reference, reveal_output, Circuit, CircuitBuilder};
use mpc::{MpcSimulator, ShareContext};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

/// Builds a random DAG with mixed leaves (secret/public inputs and
/// constants) followed by `num_gates` binary gates. Gate operands are
/// chosen from strictly earlier nodes, so the topological order holds.
fn build_random_circuit(num_leaves: usize, num_gates: usize, seed: u64) -> Circuit<Fr> {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);

    let mut b = CircuitBuilder::<Fr>::new();
    let mut leaves = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        let id = match i % 3 {
            0 => b.secret_input(),
            1 => b.public_input(),
            _ => b.constant(Fr::from(rng.next_u64())),
        };
        leaves.push(id);
    }

    let mut all_nodes = leaves;
    for _ in 0..num_gates {
        let a = all_nodes[(rng.next_u64() as usize) % all_nodes.len()];
        let other = all_nodes[(rng.next_u64() as usize) % all_nodes.len()];
        let id = if rng.next_u64() & 1 == 0 {
            b.add(a, other).expect("valid")
        } else {
            b.mul(a, other).expect("valid")
        };
        all_nodes.push(id);
    }

    b.output(*all_nodes.last().expect("non-empty"))
        .expect("valid");
    b.build().expect("valid")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn reference_matches_mpc_on_random_circuits(
        num_leaves in 1usize..8,
        num_gates in 1usize..24,
        seed in any::<u64>(),
        party_count in 2usize..6,
    ) {
        let circuit = build_random_circuit(num_leaves, num_gates, seed);

        // Input values come from a separate deterministic stream.
        let mut rng = ChaCha20Rng::seed_from_u64(seed ^ 0xffff_ffff);
        let secret_values: Vec<Fr> = (0..circuit.num_secret_inputs())
            .map(|_| Fr::from(rng.next_u64()))
            .collect();
        let public_values: Vec<Fr> = (0..circuit.num_public_inputs())
            .map(|_| Fr::from(rng.next_u64()))
            .collect();

        let expected = evaluate_reference(&circuit, &secret_values, &public_values)?;

        let ctx = ShareContext::new(party_count, seed, 1)?;
        let provider = mpc::LocalTrustedTripleProvider::new(
            ctx,
            ChaCha20Rng::seed_from_u64(seed),
        )?;
        let mut sim = MpcSimulator::new(
            ctx,
            Box::new(provider),
            ChaCha20Rng::seed_from_u64(seed.wrapping_add(1)),
        )?;

        let outputs = evaluate_mpc(&circuit, &secret_values, &public_values, &mut sim, None)?;
        prop_assert_eq!(expected.len(), outputs.len());

        for (i, output) in outputs.iter().enumerate() {
            let opened =
                reveal_output(&sim, *circuit.outputs().get(i).unwrap(), output, None)?;
            prop_assert_eq!(opened, expected[i]);
        }
    }

    #[test]
    fn random_circuits_round_trip_serialization(
        num_leaves in 1usize..8,
        num_gates in 1usize..16,
        seed in any::<u64>(),
    ) {
        let circuit = build_random_circuit(num_leaves, num_gates, seed);
        let bytes = circuit::serialize(&circuit);
        let decoded: Circuit<Fr> = circuit::deserialize(&bytes)?;
        prop_assert_eq!(&decoded, &circuit);
        prop_assert_eq!(decoded.compute_id(), circuit.compute_id());
    }
}
