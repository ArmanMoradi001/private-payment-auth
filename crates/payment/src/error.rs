//! Error types for the `payment` crate.

use core::fmt;

/// Errors produced by payment validation, authorization, and
/// verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentError {
    /// The policy is structurally invalid or failed to compile.
    InvalidPolicy,
    /// The statement names a different policy than the one supplied.
    PolicyIdMismatch,
    /// The witness count does not cover the policy's credentials.
    WitnessCountMismatch,
    /// A credential secret is empty or exceeds the size limit.
    MalformedCredentialSecret,
    /// A credential secret does not hash to its committed value.
    CredentialCommitmentMismatch,
    /// Fewer valid credentials than the threshold requires.
    ThresholdNotMet,
    /// The payment amount exceeds the policy's spending cap.
    AmountExceedsLimit,
    /// The witness amount disagrees with the statement's amount.
    AmountMismatch,
    /// A claimed binary digit does not match the value it decomposes.
    InvalidBitWitness,
    /// The combined policy tree evaluates to “not authorized”.
    PolicyNotSatisfied,
    /// Generating the non-interactive proof failed.
    ProofGenerationFailed,
    /// The proof is malformed or fails cryptographic verification.
    ProofRejected,
    /// The proof does not attest the supplied statement/policy pair.
    StatementMismatch,
}

impl fmt::Display for PaymentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidPolicy => "invalid policy",
            Self::PolicyIdMismatch => "policy id mismatch",
            Self::WitnessCountMismatch => "witness does not cover policy credentials",
            Self::MalformedCredentialSecret => "malformed credential secret",
            Self::CredentialCommitmentMismatch => "credential does not match its commitment",
            Self::ThresholdNotMet => "credential threshold not met",
            Self::AmountExceedsLimit => "amount exceeds spending limit",
            Self::AmountMismatch => "witness amount differs from statement",
            Self::InvalidBitWitness => "range-check digit witness is inconsistent",
            Self::PolicyNotSatisfied => "policy not satisfied",
            Self::ProofGenerationFailed => "proof generation failed",
            Self::ProofRejected => "proof rejected",
            Self::StatementMismatch => "proof statement mismatch",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for PaymentError {}
