//! Error types for MPC protocol operations.

use core::fmt;

/// Errors produced by the `mpc` crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MpcError {
    /// The number of protocol parties is invalid (must be greater than one).
    InvalidPartyCount,
    /// A party identifier is outside the valid range.
    InvalidPartyId,
    /// The same party appears more than once where distinctness was required.
    DuplicateParty,
    /// An expected party is missing from a participant set.
    MissingParty,
    /// Values do not belong to the same sharing context or execution.
    ContextMismatch,
    /// A share is malformed or inconsistent with its metadata.
    InvalidShare,
    /// Not enough shares were provided to reconstruct or operate on a value.
    InsufficientShares,
    /// The triple provider cannot supply any more Beaver triples.
    TripleExhaustion,
    /// A previously consumed Beaver triple was offered for reuse.
    TripleReuse,
    /// The random number generator failed to produce a usable value.
    RngFailure,
    /// The requested operation is not valid in the current state.
    InvalidOperation,
    /// A shared value was revealed in violation of the reveal policy.
    RevealMisuse,
}

impl fmt::Display for MpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidPartyCount => "invalid party count",
            Self::InvalidPartyId => "invalid party id",
            Self::DuplicateParty => "duplicate party",
            Self::MissingParty => "missing party",
            Self::ContextMismatch => "sharing context mismatch",
            Self::InvalidShare => "invalid share",
            Self::InsufficientShares => "insufficient shares",
            Self::TripleExhaustion => "beaver triple exhaustion",
            Self::TripleReuse => "beaver triple reuse detected",
            Self::RngFailure => "rng failure",
            Self::InvalidOperation => "invalid operation",
            Self::RevealMisuse => "reveal policy misuse",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for MpcError {}
