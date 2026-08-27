//! Error types for circuit construction, validation, and encoding.

use core::fmt;

/// Errors produced by the `circuit` crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitError {
    /// A gate references a node id that does not exist in the circuit.
    InvalidReference,
    /// A gate references a node defined later in the node ordering.
    ///
    /// Circuits require a strict topological order: every operand must
    /// be defined before its consumer.
    ForwardReference,
    /// The circuit declares no output nodes.
    MissingOutput,
    /// The number of provided inputs disagrees with the circuit's
    /// declared secret/public input count.
    InvalidInputCount,
    /// A node is malformed (bad tag, bad operand shape, non-canonical
    /// constant, or otherwise violates the circuit invariants).
    MalformedNode,
    /// An MPC protocol operation failed during evaluation (sharing,
    /// arithmetic, or triple supply).
    MpcFault,
    /// Encoded bytes use an unsupported serialization version.
    UnsupportedVersion,
    /// Encoded bytes end with unparsed trailing data.
    TrailingBytes,
    /// Encoded bytes ended before a complete value was read.
    UnexpectedEnd,
    /// A length prefix exceeds the maximum size permitted for safe
    /// decoding (resource-exhaustion guard).
    ExcessiveSize,
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidReference => "invalid node reference",
            Self::ForwardReference => "reference to a later node",
            Self::MissingOutput => "circuit declares no outputs",
            Self::InvalidInputCount => "input count mismatch",
            Self::MalformedNode => "malformed node",
            Self::MpcFault => "mpc protocol fault during evaluation",
            Self::UnsupportedVersion => "unsupported encoding version",
            Self::TrailingBytes => "trailing bytes after circuit",
            Self::UnexpectedEnd => "unexpected end of encoding",
            Self::ExcessiveSize => "encoded structure exceeds maximum permitted size",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for CircuitError {}
