//! Error types for the `policy` crate.
//!
//! Every error is a flat, structured enum carrying no secret or witness
//! material: credential secrets, amounts, and witness values are never
//! embedded in an error (see `docs/security/policy-security.md`).

use core::fmt;

/// Errors produced when validating, normalizing, encoding, compiling,
/// or evaluating policies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyError {
    /// A threshold value of zero was supplied (`k` must be `>= 1`).
    InvalidThreshold,
    /// The threshold `k` exceeds the number of members.
    ThresholdExceedsCount,
    /// Two members of the same `Threshold` share a credential id.
    DuplicateCredential,
    /// A credential id was zero (credentials must be non-zero).
    InvalidCredentialId,
    /// A combinator (`And`/`Or`) was given an empty member list.
    EmptyPolicy,
    /// The policy tree is deeper than [`MAX_POLICY_DEPTH`](crate::validation::MAX_POLICY_DEPTH).
    MaxDepthExceeded,
    /// The policy tree has more nodes than [`MAX_POLICY_NODES`](crate::validation::MAX_POLICY_NODES).
    MaxNodesExceeded,
    /// A threshold arity exceeds [`MAX_THRESHOLD_ARITY`](crate::validation::MAX_THRESHOLD_ARITY).
    MaxArityExceeded,
    /// The policy references more credentials than
    /// [`MAX_CREDENTIAL_COUNT`](crate::validation::MAX_CREDENTIAL_COUNT).
    MaxCredentialsExceeded,
    /// A combinator has more children than
    /// [`MAX_COMBINATOR_CHILDREN`](crate::validation::MAX_COMBINATOR_CHILDREN).
    MaxCombinatorChildrenExceeded,
    /// The canonical encoding is larger than [`MAX_ENCODED_SIZE`](crate::validation::MAX_ENCODED_SIZE).
    EncodedSizeExceeded,
    /// The encoding version is unknown.
    UnknownVersion,
    /// The encoding is truncated or otherwise malformed.
    MalformedEncoding,
    /// The encoding contains non-empty trailing bytes.
    TrailingBytes,
    /// The witness does not match the policy (missing credential or amount).
    WitnessMismatch,
    /// Policy compilation to a circuit failed.
    CompilationFailure,
    /// The compiled circuit failed structural validation.
    CircuitValidationFailure,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidThreshold => "threshold must be at least one",
            Self::ThresholdExceedsCount => "threshold exceeds member count",
            Self::DuplicateCredential => "duplicate credential in threshold members",
            Self::InvalidCredentialId => "credential id must be non-zero",
            Self::EmptyPolicy => "combinator must have at least one member",
            Self::MaxDepthExceeded => "policy exceeds maximum depth",
            Self::MaxNodesExceeded => "policy exceeds maximum node count",
            Self::MaxArityExceeded => "threshold exceeds maximum arity",
            Self::MaxCredentialsExceeded => "policy references too many credentials",
            Self::MaxCombinatorChildrenExceeded => "combinator exceeds maximum children",
            Self::EncodedSizeExceeded => "policy encoding exceeds maximum size",
            Self::UnknownVersion => "unknown policy encoding version",
            Self::MalformedEncoding => "malformed policy encoding",
            Self::TrailingBytes => "trailing bytes after policy encoding",
            Self::WitnessMismatch => "witness does not match policy",
            Self::CompilationFailure => "policy compilation to circuit failed",
            Self::CircuitValidationFailure => "compiled circuit failed validation",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for PolicyError {}
