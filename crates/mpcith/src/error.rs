//! Error types for the MPCitH layer.

use core::fmt;

/// Errors produced by the `mpcith` crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcithError {
    /// The statement is malformed or inconsistent with its circuit.
    InvalidStatement,
    /// The supplied circuit does not match the statement's circuit id
    /// or fails structural validation.
    InvalidCircuit,
    /// A challenge does not name a valid party (0, 1, or 2).
    InvalidChallenge,
    /// The requested repetition count is zero or otherwise invalid.
    InvalidRepetitionCount,
    /// A required view commitment is absent.
    MissingCommitment,
    /// A commitment or its randomness is malformed (wrong length or
    /// undecodable).
    MalformedCommitment,
    /// An opened view expected by the challenge is missing.
    MissingResponse,
    /// An opened value (d, e, or an output share) fails its algebraic
    /// check.
    InvalidOpening,
    /// A recomputed commitment does not match the committed digest.
    CommitmentMismatch,
    /// An opened party's view disagrees with the recomputed execution.
    InconsistentView,
    /// A recorded local operation is not a valid circuit operation.
    InvalidOperation,
    /// The proof's output does not match the statement's expected
    /// outputs.
    OutputMismatch,
    /// Encoded bytes are malformed, truncated, or non-canonical.
    MalformedEncoding,
    /// The protocol was invoked in an invalid state (e.g. exhausted
    /// challenge source).
    InvalidProtocolState,
}

impl fmt::Display for MpcithError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidStatement => "invalid statement",
            Self::InvalidCircuit => "invalid circuit",
            Self::InvalidChallenge => "invalid challenge",
            Self::InvalidRepetitionCount => "invalid repetition count",
            Self::MissingCommitment => "missing commitment",
            Self::MalformedCommitment => "malformed commitment",
            Self::MissingResponse => "missing response",
            Self::InvalidOpening => "invalid opening",
            Self::CommitmentMismatch => "commitment mismatch",
            Self::InconsistentView => "inconsistent party view",
            Self::InvalidOperation => "invalid operation",
            Self::OutputMismatch => "output mismatch",
            Self::MalformedEncoding => "malformed encoding",
            Self::InvalidProtocolState => "invalid protocol state",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for MpcithError {}
