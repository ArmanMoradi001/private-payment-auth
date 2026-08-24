//! MPC evaluation of circuits on top of the local simulator.
//!
//! [`evaluate_mpc`] walks the circuit in node order and mirrors every
//! gate with the corresponding shared-value operation from the `mpc`
//! crate:
//!
//! - leaves are additively shared via [`MpcSimulator::input`],
//! - `Add` is a local share-wise addition,
//! - `Mul` consumes one Beaver triple.
//!
//! Nothing is revealed automatically: outputs are returned as
//! [`SharedValue`]s and the caller decides when (and whether) to open
//! them via [`MpcSimulator::reveal`] or the transcript-aware
//! [`reveal_output`] helper.

use ark_ff::PrimeField;
use mpc::{MpcSimulator, SharedValue};
use rand_core::CryptoRngCore;

use crate::circuit::Circuit;
use crate::error::CircuitError;
use crate::node::Node;
use crate::transcript::{TranscriptEvent, TranscriptHook};
use crate::types::NodeId;

/// Evaluates a circuit over additively shared values.
///
/// Inputs are consumed positionally like in
/// [`crate::eval_reference::evaluate_reference`]; public inputs are
/// shared too so that all downstream gates operate uniformly on
/// shared values. When `hook` is `Some`, structural events are
/// recorded in deterministic topological order; passing `None`
/// imposes no overhead. No secret value is ever revealed by this
/// function.
///
/// # Errors
///
/// - [`CircuitError::InvalidInputCount`] if input slice lengths do not
///   match the declared counts.
/// - [`CircuitError::MpcFault`] if the underlying sharing, arithmetic,
///   or triple provider fails.
pub fn evaluate_mpc<F: PrimeField, R: CryptoRngCore>(
    circuit: &Circuit<F>,
    secret_inputs: &[F],
    public_inputs: &[F],
    sim: &mut MpcSimulator<F, R>,
    mut hook: Option<&mut TranscriptHook>,
) -> Result<Vec<SharedValue<F>>, CircuitError> {
    if secret_inputs.len() != circuit.num_secret_inputs()
        || public_inputs.len() != circuit.num_public_inputs()
    {
        return Err(CircuitError::InvalidInputCount);
    }

    let mut values: Vec<SharedValue<F>> = Vec::with_capacity(circuit.nodes().len());
    let mut next_secret = 0usize;
    let mut next_public = 0usize;
    let record = |hook: &mut Option<&mut TranscriptHook>, event: TranscriptEvent| {
        if let Some(h) = hook.as_deref_mut() {
            h.record(event);
        }
    };

    for (index, node) in circuit.nodes().iter().enumerate() {
        let node_id = NodeId::new(index as u32);
        match node {
            Node::SecretInput => {
                let v = secret_inputs[next_secret];
                next_secret += 1;
                values.push(sim.input(v).map_err(|_| CircuitError::MpcFault)?);
                record(&mut hook, TranscriptEvent::Input(node_id));
            }
            Node::PublicInput => {
                let v = public_inputs[next_public];
                next_public += 1;
                values.push(sim.input(v).map_err(|_| CircuitError::MpcFault)?);
                record(&mut hook, TranscriptEvent::Input(node_id));
            }
            Node::Constant(value) => {
                values.push(
                    sim.input(*value.value())
                        .map_err(|_| CircuitError::MpcFault)?,
                );
                record(&mut hook, TranscriptEvent::Input(node_id));
            }
            Node::Add(a, b) => {
                let sum = values[a.as_usize()]
                    .add_secret(&values[b.as_usize()])
                    .map_err(|_| CircuitError::MpcFault)?;
                values.push(sum);
                record(&mut hook, TranscriptEvent::Operation(node_id));
            }
            Node::Mul(a, b) => {
                // Clone operand handles so the mutable simulator borrow
                // does not conflict with `values`.
                let x = values[a.as_usize()].clone();
                let y = values[b.as_usize()].clone();
                let product = sim.mul(&x, &y).map_err(|_| CircuitError::MpcFault)?;
                values.push(product);
                record(&mut hook, TranscriptEvent::Operation(node_id));
            }
        }
    }

    let outputs = circuit
        .outputs()
        .iter()
        .map(|id| values[id.as_usize()].clone())
        .collect();
    for id in circuit.outputs() {
        record(&mut hook, TranscriptEvent::Output(*id));
    }
    Ok(outputs)
}

/// Explicitly reveals one shared output through the simulator,
/// recording a [`TranscriptEvent::Open`] for `node_id` when hooked.
///
/// Revealing is always an explicit caller decision; this helper exists
/// so reveals land in the same transcript as the evaluation that
/// produced them.
pub fn reveal_output<F: PrimeField, R: CryptoRngCore>(
    sim: &MpcSimulator<F, R>,
    node_id: NodeId,
    shared: &SharedValue<F>,
    hook: Option<&mut TranscriptHook>,
) -> Result<F, mpc::MpcError> {
    let value = sim.reveal(shared)?;
    if let Some(hook) = hook {
        hook.record(TranscriptEvent::Open(node_id));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::CircuitBuilder;
    use ark_ed25519::Fr;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn simulator(party_count: usize) -> MpcSimulator<Fr, ChaCha20Rng> {
        let ctx = mpc::ShareContext::new(party_count, 1, 4).expect("valid");
        let provider = mpc::LocalTrustedTripleProvider::new(ctx, ChaCha20Rng::seed_from_u64(1))
            .expect("valid");
        MpcSimulator::new(ctx, Box::new(provider), ChaCha20Rng::seed_from_u64(2)).expect("valid")
    }

    #[test]
    fn matches_reference_evaluation() {
        // (x + 2) * p + x, three parties.
        let mut b = CircuitBuilder::new();
        let x = b.secret_input();
        let c = b.constant(Fr::from(2u64));
        let t = b.add(x, c).expect("valid");
        let p = b.public_input();
        let m = b.mul(t, p).expect("valid");
        let s = b.add(m, x).expect("valid");
        b.output(s).expect("valid");
        let circuit = b.build().expect("valid");

        let xv = Fr::from(7u64);
        let pv = Fr::from(5u64);

        let reference =
            crate::eval_reference::evaluate_reference(&circuit, &[xv], &[pv]).expect("valid");

        let mut sim = simulator(3);
        let outputs = evaluate_mpc(&circuit, &[xv], &[pv], &mut sim, None).expect("valid");
        assert_eq!(outputs.len(), 1);

        let opened = reveal_output(&sim, *circuit.outputs().first().unwrap(), &outputs[0], None)
            .expect("valid");
        assert_eq!(opened, reference[0]);
    }

    #[test]
    fn wrong_input_counts_are_rejected() {
        let mut b = CircuitBuilder::new();
        let x = b.secret_input();
        b.output(x).expect("valid");
        let circuit = b.build().expect("valid");
        let mut sim = simulator(2);
        assert_eq!(
            evaluate_mpc(&circuit, &[], &[], &mut sim, None).unwrap_err(),
            CircuitError::InvalidInputCount
        );
    }

    #[test]
    fn transcripts_record_topological_events() {
        let mut b = CircuitBuilder::new();
        let x = b.secret_input();
        let p = b.public_input();
        let s = b.add(x, p).expect("valid");
        b.output(s).expect("valid");
        let circuit = b.build().expect("valid");

        let mut hook = TranscriptHook::new();
        let mut sim = simulator(2);
        let outputs = evaluate_mpc(
            &circuit,
            &[Fr::from(3u64)],
            &[Fr::from(4u64)],
            &mut sim,
            Some(&mut hook),
        )
        .expect("valid");
        let _ = reveal_output(
            &sim,
            *circuit.outputs().first().unwrap(),
            &outputs[0],
            Some(&mut hook),
        )
        .expect("valid");

        assert_eq!(
            hook.events(),
            &[
                TranscriptEvent::Input(NodeId::new(0)),
                TranscriptEvent::Input(NodeId::new(1)),
                TranscriptEvent::Operation(NodeId::new(2)),
                TranscriptEvent::Output(NodeId::new(2)),
                TranscriptEvent::Open(NodeId::new(2)),
            ]
        );
    }

    #[test]
    fn constants_are_shared_not_revealed() {
        let mut b = CircuitBuilder::new();
        let c = b.constant(Fr::from(9u64));
        b.output(c).expect("valid");
        let circuit = b.build().expect("valid");
        let mut sim = simulator(2);
        let outputs = evaluate_mpc(&circuit, &[], &[], &mut sim, None).expect("valid");
        // Output remains shared: its debug form is redacted.
        assert_eq!(format!("{:?}", outputs[0]), "SharedValue([REDACTED])");
        assert_eq!(
            reveal_output(&sim, *circuit.outputs().first().unwrap(), &outputs[0], None)
                .expect("valid"),
            Fr::from(9u64)
        );
    }
}
