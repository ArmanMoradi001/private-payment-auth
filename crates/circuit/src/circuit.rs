//! The arithmetic circuit type and its structural validation.

use ark_ff::PrimeField;

use crate::error::CircuitError;
use crate::node::Node;
use crate::types::{CircuitId, NodeId};

/// An ordered DAG of arithmetic nodes over the prime field `F`.
///
/// Invariants (enforced by [`Circuit::validate`] and by the builder):
///
/// 1. Node ids are positional: node `i` lives at index `i`.
/// 2. Binary gates may only reference strictly earlier nodes, so the
///    node vector is a topological order and evaluation is a single
///    forward pass.
/// 3. The circuit declares how many secret and public inputs it
///    consumes; input leaves must match these counts.
/// 4. At least one output is declared.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Circuit<F> {
    nodes: Vec<Node<F>>,
    num_secret_inputs: usize,
    num_public_inputs: usize,
    outputs: Vec<NodeId>,
}

impl<F: PrimeField> Circuit<F> {
    /// Builds a circuit from its parts without validating.
    ///
    /// Prefer [`crate::builder::CircuitBuilder`], which produces
    /// validated circuits. Callers must run [`Self::validate`].
    pub fn new(
        nodes: Vec<Node<F>>,
        num_secret_inputs: usize,
        num_public_inputs: usize,
        outputs: Vec<NodeId>,
    ) -> Self {
        Self {
            nodes,
            num_secret_inputs,
            num_public_inputs,
            outputs,
        }
    }

    /// Returns the nodes in construction (topological) order.
    pub fn nodes(&self) -> &[Node<F>] {
        &self.nodes
    }

    /// Returns the declared output node ids.
    pub fn outputs(&self) -> &[NodeId] {
        &self.outputs
    }

    /// Number of secret inputs this circuit consumes at evaluation time.
    pub fn num_secret_inputs(&self) -> usize {
        self.num_secret_inputs
    }

    /// Number of public inputs this circuit consumes at evaluation time.
    pub fn num_public_inputs(&self) -> usize {
        self.num_public_inputs
    }

    /// Computes the domain-separated semantic id of this circuit.
    ///
    /// See [`crate::identity`] for the construction.
    pub fn compute_id(&self) -> CircuitId {
        crate::identity::compute_id(self)
    }
    /// Checks all structural invariants of the circuit.
    ///
    /// # Errors
    ///
    /// - [`CircuitError::InvalidReference`] if a gate references a node
    ///   id that does not exist.
    /// - [`CircuitError::ForwardReference`] if a gate references itself
    ///   or any later node.
    /// - [`CircuitError::InvalidInputCount`] if the number of
    ///   [`Node::SecretInput`]/[`Node::PublicInput`] leaves disagrees
    ///   with the declared counts.
    /// - [`CircuitError::MissingOutput`] if no outputs are declared or
    ///   an output references a nonexistent node.
    pub fn validate(&self) -> Result<(), CircuitError> {
        for (index, node) in self.nodes.iter().enumerate() {
            let Some((a, b)) = node.operands() else {
                continue;
            };
            for operand in [a, b] {
                let pos = operand.as_usize();
                if pos >= self.nodes.len() {
                    return Err(CircuitError::InvalidReference);
                }
                if pos >= index {
                    return Err(CircuitError::ForwardReference);
                }
            }
        }

        let secret_leaves = self
            .nodes
            .iter()
            .filter(|n| matches!(n, Node::SecretInput))
            .count();
        let public_leaves = self
            .nodes
            .iter()
            .filter(|n| matches!(n, Node::PublicInput))
            .count();
        if secret_leaves != self.num_secret_inputs || public_leaves != self.num_public_inputs {
            return Err(CircuitError::InvalidInputCount);
        }

        if self.outputs.is_empty() {
            return Err(CircuitError::MissingOutput);
        }
        for output in &self.outputs {
            if output.as_usize() >= self.nodes.len() {
                return Err(CircuitError::InvalidReference);
            }
        }
        Ok(())
    }
}
