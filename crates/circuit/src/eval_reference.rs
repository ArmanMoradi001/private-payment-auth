//! Plaintext reference evaluation.
//!
//! This module evaluates a [`Circuit`] directly over field elements,
//! completely independent of the `mpc` crate: no sharing, no
//! simulator, no protocol machinery. It defines the *ground truth*
//! that the MPC evaluator ([`crate::eval_mpc`]) must reproduce, and is
//! used for testing, debugging, and policy simulation.

use ark_ff::PrimeField;

use crate::circuit::Circuit;
use crate::error::CircuitError;

/// Evaluates a validated circuit over plaintext field elements.
///
/// Inputs are consumed positionally in the order the corresponding
/// leaf nodes appear in the circuit's node vector.
///
/// # Errors
///
/// - [`CircuitError::InvalidInputCount`] if `secret_inputs` or
///   `public_inputs` do not match the declared input counts.
/// - [`CircuitError::MalformedNode`] if the circuit was not validated
///   (an operand references an out-of-range node).
pub fn evaluate_reference<F: PrimeField>(
    circuit: &Circuit<F>,
    secret_inputs: &[F],
    public_inputs: &[F],
) -> Result<Vec<F>, CircuitError> {
    if secret_inputs.len() != circuit.num_secret_inputs()
        || public_inputs.len() != circuit.num_public_inputs()
    {
        return Err(CircuitError::InvalidInputCount);
    }

    let mut values: Vec<F> = Vec::with_capacity(circuit.nodes().len());
    let mut next_secret = 0usize;
    let mut next_public = 0usize;
    for node in circuit.nodes() {
        let value = match node {
            crate::node::Node::SecretInput => {
                let v = secret_inputs[next_secret];
                next_secret += 1;
                v
            }
            crate::node::Node::PublicInput => {
                let v = public_inputs[next_public];
                next_public += 1;
                v
            }
            crate::node::Node::Constant(c) => *c.value(),
            crate::node::Node::Add(a, b) => values[a.as_usize()] + values[b.as_usize()],
            crate::node::Node::Mul(a, b) => values[a.as_usize()] * values[b.as_usize()],
        };
        values.push(value);
    }

    Ok(circuit
        .outputs()
        .iter()
        .map(|id| values[id.as_usize()])
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::CircuitBuilder;
    use ark_ed25519::Fr;
    use ark_ff::{One, Zero};

    #[test]
    fn evaluates_linear_expression() {
        // (x + 2) * p + x
        let mut b = CircuitBuilder::new();
        let x = b.secret_input();
        let c = b.constant(Fr::from(2u64));
        let t = b.add(x, c).expect("valid");
        let p = b.public_input();
        let m = b.mul(t, p).expect("valid");
        let s = b.add(m, x).expect("valid");
        b.output(s).expect("valid");
        let circuit = b.build().expect("valid");

        let x = Fr::from(7u64);
        let p = Fr::from(5u64);
        let expected = (x + Fr::from(2u64)) * p + x;
        assert_eq!(
            evaluate_reference(&circuit, &[x], &[p]).expect("valid"),
            vec![expected]
        );
    }

    #[test]
    fn multiple_outputs_preserve_order() {
        let mut b = CircuitBuilder::new();
        let a = b.secret_input();
        let d = b.secret_input();
        let s = b.add(a, d).expect("valid");
        let m = b.mul(a, d).expect("valid");
        b.output(s).expect("valid");
        b.output(m).expect("valid");
        let circuit = b.build().expect("valid");

        assert_eq!(
            evaluate_reference(&circuit, &[Fr::from(3u64), Fr::from(4u64)], &[]).expect("valid"),
            vec![Fr::from(7u64), Fr::from(12u64)]
        );
    }

    #[test]
    fn wrong_input_counts_are_rejected() {
        let mut b = CircuitBuilder::<Fr>::new();
        let x = b.secret_input();
        b.output(x).expect("valid");
        let circuit = b.build().expect("valid");

        assert_eq!(
            evaluate_reference(&circuit, &[], &[]),
            Err(CircuitError::InvalidInputCount)
        );
    }

    #[test]
    fn constants_and_zero_inputs_behave() {
        let mut b = CircuitBuilder::<Fr>::new();
        let z = b.constant(Fr::zero());
        let o = b.constant(Fr::one());
        let s = b.add(z, o).expect("valid");
        b.output(s).expect("valid");
        let circuit = b.build().expect("valid");

        assert_eq!(
            evaluate_reference(&circuit, &[], &[]).expect("valid"),
            vec![Fr::one()]
        );
    }
}
