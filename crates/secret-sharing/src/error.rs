//! Error types for secret sharing operations.

use core::fmt;

/// Errors produced by the secret-sharing crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSharingError {
    /// The requested threshold is not in the range `2 <= threshold`.
    InvalidThreshold,
    /// The requested share count is zero or otherwise invalid.
    InvalidShareCount,
    /// The threshold exceeds the number of shares.
    ThresholdGreaterThanCount,
    /// An input buffer was empty where non-empty input was required.
    EmptyInput,
    /// Not enough shares were provided to reach the reconstruction threshold.
    InsufficientShares,
    /// Two or more shares carry the same index.
    DuplicateShareIndex,
    /// A share index is outside the valid range (zero or above the share count).
    InvalidShareIndex,
    /// Shares do not agree on version, threshold, or share count metadata.
    IncompatibleMetadata,
    /// Encoded bytes are not a valid canonical encoding.
    MalformedEncoding,
    /// A byte sequence could not be interpreted as a field element.
    InvalidFieldElement,
    /// The random number generator failed to produce a usable value.
    RngFailure,
    /// Reconstruction failed to produce a consistent result.
    ReconstructionFailure,
    /// The secret (or encoded value) is too large for the chosen prime field.
    SecretTooLargeForField,
}

impl fmt::Display for SecretSharingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidThreshold => "invalid threshold",
            Self::InvalidShareCount => "invalid share count",
            Self::ThresholdGreaterThanCount => "threshold is greater than share count",
            Self::EmptyInput => "empty input",
            Self::InsufficientShares => "insufficient shares for reconstruction",
            Self::DuplicateShareIndex => "duplicate share index",
            Self::InvalidShareIndex => "share index out of range",
            Self::IncompatibleMetadata => "incompatible share metadata",
            Self::MalformedEncoding => "malformed encoding",
            Self::InvalidFieldElement => "invalid field element",
            Self::RngFailure => "rng failure",
            Self::ReconstructionFailure => "reconstruction failure",
            Self::SecretTooLargeForField => "secret too large for the field modulus",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SecretSharingError {}
