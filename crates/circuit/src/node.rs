//! Circuit nodes.
//!
//! A node is one step of an arithmetic computation. Binary gates
//! reference their operands directly by [`NodeId`] — there is no
//! separate wire/edge list. Because ids are assigned in construction
//! order and operands must reference strictly earlier nodes, the node
//! vector itself is a deterministic topological ordering of a DAG.

use mpc::PublicValue;

use crate::types::NodeId;

/// One step of an arithmetic circuit over the prime field `F`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Node<F> {
    /// A secret input supplied by the prover at evaluation time.
    SecretInput,
    /// A public input known to all parties.
    PublicInput,
    /// A publicly known field constant.
    Constant(PublicValue<F>),
    /// Field addition of two previously defined nodes.
    Add(NodeId, NodeId),
    /// Field multiplication of two previously defined nodes.
    Mul(NodeId, NodeId),
}

impl<F> Node<F> {
    /// Returns the operand ids for binary gates (`Add`, `Mul`), or
    /// `None` for leaf nodes.
    pub fn operands(&self) -> Option<(NodeId, NodeId)> {
        match self {
            Self::Add(a, b) | Self::Mul(a, b) => Some((*a, *b)),
            Self::SecretInput | Self::PublicInput | Self::Constant(_) => None,
        }
    }

    /// Returns `true` when the node is an input or constant leaf.
    pub fn is_leaf(&self) -> bool {
        self.operands().is_none()
    }
}
