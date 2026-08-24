//! Arithmetic circuit layer for payment authorization policies.
//!
//! This crate will define the statement being proven: a deterministic
//! arithmetic circuit (a topologically ordered DAG of `+` and `*`
//! gates over the prime field) that evaluates an authorization policy
//! over secret and public inputs.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod builder;
pub mod circuit;
pub mod encoding;
pub mod error;
pub mod node;
pub mod types;

pub use builder::CircuitBuilder;
pub use circuit::Circuit;
pub use error::CircuitError;
pub use node::Node;
pub use types::{CircuitId, NodeId};
