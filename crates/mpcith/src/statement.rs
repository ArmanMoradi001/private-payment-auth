//! The statement being proven: a circuit binding plus public inputs
//! and the expected plaintext results.

use mpc::PublicValue;

use circuit::CircuitId;

use crate::error::MpcithError;
use crate::types::FieldElement;

/// Public description of what is being proven.
///
/// A statement pins a specific circuit by its [`CircuitId`], the
/// public inputs fed into it, and the outputs an honest execution must
/// produce. Secret inputs (the witness) are deliberately absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// Semantic hash of the circuit this statement refers to.
    pub circuit_id: CircuitId,
    /// Public inputs in circuit declaration order.
    pub public_inputs: Vec<PublicValue<FieldElement>>,
    /// Expected outputs in circuit output order.
    pub expected_outputs: Vec<PublicValue<FieldElement>>,
}

impl Statement {
    /// Checks internal consistency against `circuit`.
    ///
    /// # Errors
    ///
    /// - [`MpcithError::InvalidCircuit`] if the circuit fails
    ///   validation or its id differs from [`Self::circuit_id`].
    /// - [`MpcithError::InvalidStatement`] if input/output counts do
    ///   not match the circuit's declarations.
    pub fn validate(&self, circuit: &circuit::Circuit<FieldElement>) -> Result<(), MpcithError> {
        circuit
            .validate()
            .map_err(|_| MpcithError::InvalidCircuit)?;
        if self.circuit_id != circuit.compute_id() {
            return Err(MpcithError::InvalidCircuit);
        }
        if self.public_inputs.len() != circuit.num_public_inputs()
            || self.expected_outputs.len() != circuit.outputs().len()
        {
            return Err(MpcithError::InvalidStatement);
        }
        Ok(())
    }
}
