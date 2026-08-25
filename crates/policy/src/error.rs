//! Error types for the `policy` crate.

use core::fmt;

/// Errors produced when validating or compiling policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// A threshold value of zero was supplied.
    InvalidThreshold,
    /// A threshold was given an empty credential list.
    ZeroCredentials,
    /// The threshold `k` exceeds the number of credentials.
    ThresholdExceedsCount,
    /// The policy tree is structurally malformed (e.g. an empty
    /// combinator).
    MalformedPolicy,
    /// Compiling the policy into a circuit failed.
    CircuitCompilationFailed,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidThreshold => "policy threshold must be at least one",
            Self::ZeroCredentials => "threshold policy has no credentials",
            Self::ThresholdExceedsCount => "threshold exceeds credential count",
            Self::MalformedPolicy => "malformed policy structure",
            Self::CircuitCompilationFailed => "policy compilation to circuit failed",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for PolicyError {}
