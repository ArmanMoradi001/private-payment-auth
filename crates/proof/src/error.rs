//! Error types for the Fiat–Shamir proof layer.

use core::fmt;

/// Errors produced by the `proof` crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofError {
    /// The statement is malformed or inconsistent.
    InvalidStatement,
    /// The circuit fails validation or does not match the statement.
    InvalidCircuit,
    /// The witness does not fit the circuit's secret inputs.
    InvalidWitness,
    /// A stored challenge differs from the independently derived one.
    ChallengeMismatch,
    /// A repetition failed MPCitH verification.
    VerificationFailed,
    /// Encoded bytes are malformed or truncated.
    MalformedEncoding,
    /// The encoding or protocol version is unsupported.
    InvalidVersion,
    /// The proof's statement was built for a different circuit.
    CircuitIdMismatch,
    /// The proven outputs disagree with the statement.
    OutputMismatch,
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidStatement => "invalid statement",
            Self::InvalidCircuit => "invalid circuit",
            Self::InvalidWitness => "invalid witness",
            Self::ChallengeMismatch => "fiat-shamir challenge mismatch",
            Self::VerificationFailed => "verification failed",
            Self::MalformedEncoding => "malformed encoding",
            Self::InvalidVersion => "invalid version",
            Self::CircuitIdMismatch => "circuit id mismatch",
            Self::OutputMismatch => "output mismatch",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for ProofError {}
