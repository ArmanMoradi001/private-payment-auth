//! Ergonomic construction of validated circuits.
//!
//! The builder assigns [`NodeId`]s deterministically in insertion order
//! (`0, 1, 2, ...`), which makes the resulting node vector a stable
//! topological order and the circuit's canonical encoding — and hence
//! its [`crate::CircuitId`] — reproducible from the same sequence of
//! calls.

use ark_ff::PrimeField;

use crate::circuit::Circuit;
use crate::error::CircuitError;
use crate::node::Node;
use crate::types::NodeId;
use mpc::PublicValue;

/// Incremental constructor for [`Circuit`].
#[derive(Clone, Debug)]
pub struct CircuitBuilder<F> {
    nodes: Vec<Node<F>>,
    num_secret_inputs: usize,
    num_public_inputs: usize,
    outputs: Vec<NodeId>,
}

impl<F> Default for CircuitBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F> CircuitBuilder<F> {
    /// Creates an empty circuit builder.
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            num_secret_inputs: 0,
            num_public_inputs: 0,
            outputs: Vec::new(),
        }
    }

    /// Returns the id that will be assigned to the next node.
    pub fn next_node_id(&self) -> NodeId {
        NodeId::new(u32::try_from(self.nodes.len()).expect("circuit exceeds u32 node count"))
    }

    /// Checks that `id` refers to an already-defined node.
    fn check_defined(&self, id: NodeId) -> Result<(), CircuitError> {
        if id.as_usize() >= self.nodes.len() {
            return Err(CircuitError::InvalidReference);
        }
        Ok(())
    }

    fn push(&mut self, node: Node<F>) -> NodeId {
        let id = self.next_node_id();
        self.nodes.push(node);
        id
    }
}

impl<F: PrimeField> CircuitBuilder<F> {
    /// Declares a secret input leaf.
    pub fn secret_input(&mut self) -> NodeId {
        self.num_secret_inputs += 1;
        self.push(Node::SecretInput)
    }

    /// Declares a public input leaf.
    pub fn public_input(&mut self) -> NodeId {
        self.num_public_inputs += 1;
        self.push(Node::PublicInput)
    }

    /// Declares a public field constant.
    pub fn constant(&mut self, value: F) -> NodeId {
        self.push(Node::Constant(PublicValue::new(value)))
    }

    /// Adds a gate computing `a + b`.
    ///
    /// # Errors
    ///
    /// Returns [`CircuitError::InvalidReference`] if either operand is
    /// not an already-defined node.
    pub fn add(&mut self, a: NodeId, b: NodeId) -> Result<NodeId, CircuitError> {
        self.check_defined(a)?;
        self.check_defined(b)?;
        Ok(self.push(Node::Add(a, b)))
    }

    /// Adds a gate computing `a * b`.
    ///
    /// # Errors
    ///
    /// Returns [`CircuitError::InvalidReference`] if either operand is
    /// not an already-defined node.
    pub fn mul(&mut self, a: NodeId, b: NodeId) -> Result<NodeId, CircuitError> {
        self.check_defined(a)?;
        self.check_defined(b)?;
        Ok(self.push(Node::Mul(a, b)))
    }

    /// Marks `id` as an output of the circuit.
    ///
    /// # Errors
    ///
    /// Returns [`CircuitError::InvalidReference`] if `id` is not an
    /// already-defined node.
    pub fn output(&mut self, id: NodeId) -> Result<(), CircuitError> {
        self.check_defined(id)?;
        self.outputs.push(id);
        Ok(())
    }

    /// Finalizes and validates the circuit.
    ///
    /// # Errors
    ///
    /// Propagates any [`CircuitError`] from structural validation
    /// (e.g. [`CircuitError::MissingOutput`] when no output was marked).
    pub fn build(self) -> Result<Circuit<F>, CircuitError> {
        let circuit = Circuit::new(
            self.nodes,
            self.num_secret_inputs,
            self.num_public_inputs,
            self.outputs,
        );
        circuit.validate()?;
        Ok(circuit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::NodeId;
    use ark_ed25519::Fr;
    use ark_ff::One;

    fn expr_circuit() -> Circuit<Fr> {
        let mut b = CircuitBuilder::new();
        let x = b.secret_input();
        let c = b.constant(Fr::from(2u64));
        let prod = b.mul(x, c).expect("valid");
        let y = b.public_input();
        let sum = b.add(prod, y).expect("valid");
        b.output(sum).expect("valid");
        b.build().expect("valid")
    }

    #[test]
    fn ids_are_deterministic_and_positional() {
        let mut b = CircuitBuilder::<Fr>::new();
        assert_eq!(b.secret_input(), NodeId::new(0));
        assert_eq!(b.constant(Fr::one()), NodeId::new(1));
        assert_eq!(b.public_input(), NodeId::new(2));
        assert_eq!(
            b.add(NodeId::new(0), NodeId::new(1)).unwrap(),
            NodeId::new(3)
        );
    }

    #[test]
    fn built_circuit_validates() {
        assert!(expr_circuit().validate().is_ok());
    }

    #[test]
    fn missing_output_is_rejected() {
        let mut b = CircuitBuilder::<Fr>::new();
        b.secret_input();
        assert_eq!(b.build().unwrap_err(), CircuitError::MissingOutput);
    }

    #[test]
    fn undefined_operand_is_rejected() {
        let mut b = CircuitBuilder::<Fr>::new();
        let x = b.secret_input();
        assert_eq!(
            b.mul(x, NodeId::new(9)).unwrap_err(),
            CircuitError::InvalidReference
        );
    }
}
