//! Error types for `crypto-core`.

use core::fmt;

/// Errors produced by cryptographic operations in this crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CryptoCoreError {
    /// A byte input or output had an unexpected length.
    InvalidLength,
    /// A serialized encoding could not be decoded.
    MalformedEncoding,
    /// A commitment failed to open or verify against a value.
    InvalidCommitment,
    /// The random number generator failed or was misconfigured.
    RngFailure,
    /// A general-purpose rejection of caller-supplied input.
    InvalidInput,
}

impl fmt::Display for CryptoCoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength => write!(f, "invalid length"),
            Self::MalformedEncoding => write!(f, "malformed encoding"),
            Self::InvalidCommitment => write!(f, "invalid commitment"),
            Self::RngFailure => write!(f, "rng failure"),
            Self::InvalidInput => write!(f, "invalid input"),
        }
    }
}

impl core::error::Error for CryptoCoreError {}
