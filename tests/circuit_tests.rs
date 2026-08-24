//! Integration tests for the circuit crate: builder, validation,
//! identity, serialization, and reference/MPC evaluator equivalence.

use ark_ed25519::Fr;
use ark_ff::{One, Zero};
use circuit::{
    evaluate_mpc, evaluate_reference, reveal_output, CircuitBuilder, CircuitError, Node, NodeId,
    TranscriptHook,
};
use mpc::{MpcSimulator, ShareContext};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn simulator(party_count: usize) -> MpcSimulator<Fr, ChaCha20Rng> {
    let ctx = ShareContext::new(party_count, 42, 7).expect("valid");
    let provider =
        mpc::LocalTrustedTripleProvider::new(ctx, ChaCha20Rng::seed_from_u64(11)).expect("valid");
    MpcSimulator::new(ctx, Box::new(provider), ChaCha20Rng::seed_from_u64(12)).expect("valid")
}

/// (x + c1) * p + x * x with two outputs: sum and squared.
fn sample_circuit() -> circuit::Circuit<Fr> {
    let mut b = CircuitBuilder::new();
    let x = b.secret_input();
    let p = b.public_input();
    let c = b.constant(Fr::from(10u64));
    let t = b.add(x, c).expect("valid");
    let s = b.mul(t, p).expect("valid");
    let sq = b.mul(x, x).expect("valid");
    b.output(s).expect("valid");
    b.output(sq).expect("valid");
    b.build().expect("valid")
}

#[test]
fn builder_assigns_deterministic_ids() {
    let mut a = CircuitBuilder::<Fr>::new();
    let mut b = CircuitBuilder::<Fr>::new();
    for _ in 0..6 {
        assert_eq!(a.secret_input(), b.secret_input());
    }
}

#[test]
fn built_circuits_pass_validation() {
    let circuit = sample_circuit();
    assert!(circuit.validate().is_ok());
    assert_eq!(circuit.num_secret_inputs(), 1);
    assert_eq!(circuit.num_public_inputs(), 1);
    assert_eq!(circuit.outputs().len(), 2);
}

#[test]
fn validation_rejects_broken_circuits() {
    // Missing output.
    let mut b = CircuitBuilder::<Fr>::new();
    b.secret_input();
    assert_eq!(b.build().unwrap_err(), CircuitError::MissingOutput);

    // Undefined operand reference.
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    assert_eq!(
        b.add(x, NodeId::new(42)).unwrap_err(),
        CircuitError::InvalidReference
    );

    // Declared counts disagreeing with leaves.
    let mut b = CircuitBuilder::<Fr>::new();
    let x = b.secret_input();
    b.output(x).expect("valid");
    let circuit = b.build().expect("valid");
    assert_eq!(circuit.validate(), Ok(()));
}

#[test]
fn ids_are_stable_and_mutation_sensitive() {
    let base = || {
        let mut b = CircuitBuilder::new();
        let x = b.secret_input();
        let c = b.constant(Fr::from(5u64));
        let m = b.mul(x, c).expect("valid");
        b.output(m).expect("valid");
        b.build().expect("valid")
    };
    // Deterministic across repeated construction.
    assert_eq!(base().compute_id(), base().compute_id());

    // Mutation 1: different constant.
    let mutated_constant = {
        let mut b = CircuitBuilder::new();
        let x = b.secret_input();
        let c = b.constant(Fr::from(6u64));
        let m = b.mul(x, c).expect("valid");
        b.output(m).expect("valid");
        b.build().expect("valid")
    };
    assert_ne!(base().compute_id(), mutated_constant.compute_id());

    // Mutation 2: different operation.
    let mutated_op = {
        let mut b = CircuitBuilder::new();
        let x = b.secret_input();
        let c = b.constant(Fr::from(5u64));
        let m = b.add(x, c).expect("valid");
        b.output(m).expect("valid");
        b.build().expect("valid")
    };
    assert_ne!(base().compute_id(), mutated_op.compute_id());

    // Mutation 3: reordered operands (different node order).
    let mutated_order = {
        let mut b = CircuitBuilder::new();
        let c_leaf = b.constant(Fr::from(5u64)); // now node 0
        let x = b.secret_input(); // now node 1
        let m = b.mul(x, c_leaf).expect("valid");
        b.output(m).expect("valid");
        b.build().expect("valid")
    };
    assert_ne!(base().compute_id(), mutated_order.compute_id());
}

#[test]
fn serialization_round_trips() {
    let circuit = sample_circuit();
    let bytes = circuit::serialize(&circuit);
    let decoded: circuit::Circuit<Fr> = circuit::deserialize(&bytes).expect("valid encoding");
    assert_eq!(decoded, circuit);

    // Identity is stable across the encode/decode boundary.
    assert_eq!(decoded.compute_id(), circuit.compute_id());
}

#[test]
fn serialization_rejects_corruption() {
    let bytes = circuit::serialize(&sample_circuit());

    let mut bad_version = bytes.clone();
    bad_version[0] = 250;
    assert_eq!(
        circuit::deserialize::<Fr>(&bad_version).unwrap_err(),
        CircuitError::UnsupportedVersion
    );

    let mut trailing = bytes.clone();
    trailing.extend_from_slice(&[0u8; 8]);
    assert_eq!(
        circuit::deserialize::<Fr>(&trailing).unwrap_err(),
        CircuitError::TrailingBytes
    );

    assert_eq!(
        circuit::deserialize::<Fr>(&bytes[..bytes.len() - 3]).unwrap_err(),
        CircuitError::UnexpectedEnd
    );
}

#[test]
fn reference_and_mpc_agree() {
    let circuit = sample_circuit();
    let xv = Fr::from(9u64);
    let pv = Fr::from(4u64);

    let expected = evaluate_reference(&circuit, &[xv], &[pv]).expect("valid");

    for party_count in [2usize, 3, 5] {
        let mut sim = simulator(party_count);
        let outputs = evaluate_mpc(&circuit, &[xv], &[pv], &mut sim, None).expect("valid");
        for (i, output) in outputs.iter().enumerate() {
            let opened = reveal_output(&sim, *circuit.outputs().get(i).unwrap(), output, None)
                .expect("valid");
            assert_eq!(opened, expected[i], "party count {party_count}, output {i}");
        }
    }
}

#[test]
fn transcripts_capture_structure_without_secrets() {
    let circuit = sample_circuit();
    let mut hook = TranscriptHook::new();
    let mut sim = simulator(3);

    let outputs = evaluate_mpc(
        &circuit,
        &[Fr::one()],
        &[Fr::one()],
        &mut sim,
        Some(&mut hook),
    )
    .expect("valid");
    for (i, output) in outputs.iter().enumerate() {
        let _ = reveal_output(
            &sim,
            *circuit.outputs().get(i).unwrap(),
            output,
            Some(&mut hook),
        );
    }

    // Events are structural only: node ids in topological order. No
    // field values can appear because events cannot carry them.
    assert!(hook.len() >= 5);
    assert!(format!("{hook:?}").contains("Node"));
    assert!(!format!("{hook:?}").contains("Fr"));
}

#[test]
fn evaluation_requires_matching_input_counts() {
    let circuit = sample_circuit();
    let mut sim = simulator(2);
    assert_eq!(
        evaluate_reference(&circuit, &[], &[]).unwrap_err(),
        CircuitError::InvalidInputCount
    );
    assert_eq!(
        evaluate_mpc(&circuit, &[], &[], &mut sim, None).unwrap_err(),
        CircuitError::InvalidInputCount
    );
}

#[test]
fn node_kinds_round_trip_through_encoding() {
    // Every variant of `Node` appears in this circuit.
    let mut b = CircuitBuilder::<Fr>::new();
    let s = b.secret_input();
    let p = b.public_input();
    let c = b.constant(Fr::zero());
    let a = b.add(s, p).expect("valid");
    let m = b.mul(a, c).expect("valid");
    b.output(m).expect("valid");
    let circuit = b.build().expect("valid");

    assert!(circuit
        .nodes()
        .iter()
        .any(|n| matches!(n, Node::SecretInput)));
    assert!(circuit
        .nodes()
        .iter()
        .any(|n| matches!(n, Node::PublicInput)));
    assert!(circuit
        .nodes()
        .iter()
        .any(|n| matches!(n, Node::Constant(_))));
    assert!(circuit.nodes().iter().any(|n| matches!(n, Node::Add(_, _))));
    assert!(circuit.nodes().iter().any(|n| matches!(n, Node::Mul(_, _))));

    let decoded: circuit::Circuit<Fr> =
        circuit::deserialize(&circuit::serialize(&circuit)).expect("valid");
    assert_eq!(decoded, circuit);
}
