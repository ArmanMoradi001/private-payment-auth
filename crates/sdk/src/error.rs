//! Public error model for the SDK.
//!
//! [`SdkError`] is the single error type returned by every SDK entry
//! point. Variants are high-level, actionable, and intentionally vague
//! about internal cryptographic state: messages never include witness
//! values, secret material, share contents, raw proof bytes, or other
//! data that could help an attacker recover secrets. The goal is to
//! let application developers diagnose and recover without ever
//! learning something that should remain private.

use core::fmt;

/// Errors produced by the SDK.
///
/// Each variant carries enough context for a developer to react (retry
/// with different inputs, fall back to a different policy, surface a
/// user-facing error), but never enough to reconstruct any secret or
/// leak intermediate cryptographic state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdkError {
    /// The supplied payment object is structurally invalid or fails
    /// validation (bad version, inconsistent fields, missing nonce).
    InvalidPayment,
    /// The supplied policy is structurally invalid, fails normalization,
    /// or exceeds the supported limits.
    InvalidPolicy,
    /// The witness does not match the policy/circuit binding (wrong
    /// secret count, wrong credential, wrong amounts).
    InvalidWitness,
    /// An authorization artifact (or any sub-component) is malformed:
    /// truncated bytes, bad version tag, unknown encoding, trailing
    /// garbage.
    ArtifactMalformed,
    /// The artifact's version stamp is one this SDK does not support.
    VersionUnsupported,
    /// The artifact's cryptographic backend id is one this SDK does
    /// not support.
    BackendUnsupported,
    /// The verifier's configured backend does not match the backend
    /// the authorization was generated under. This is a hard
    /// configuration error (the caller must align their config with
    /// the artifact's bound backend); never silently re-encoded.
    BackendMismatch,
    /// The artifact's payment binding does not match the payment the
    /// caller expects.
    PaymentMismatch,
    /// The artifact's policy binding does not match the policy the
    /// caller expects.
    PolicyMismatch,
    /// The artifact's circuit binding does not match the policy the
    /// caller expects (the circuit id differs from the one the policy
    /// compiles to).
    CircuitMismatch,
    /// The contained proof fails verification (bad challenge, bad
    /// opening, bad output).
    ProofInvalid,
    /// Authorization generation failed for a non-secret reason
    /// (transcript overflow, randomness source failure, resource limit).
    AuthorizationGenerationFailed,
    /// Self-verification of a freshly generated authorization failed:
    /// the SDK was unable to convince itself the artifact it just
    /// produced is sound. The artifact is rejected.
    SelfVerificationFailed,
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::InvalidPayment => "payment object is invalid: check version, fields, and nonce",
            Self::InvalidPolicy => {
                "policy is invalid: check structure, normalization, and size limits"
            }
            Self::InvalidWitness => "witness does not match the policy/circuit binding",
            Self::ArtifactMalformed => {
                "authorization artifact is malformed: truncated bytes or bad encoding"
            }
            Self::VersionUnsupported => "authorization version is not supported by this SDK",
            Self::BackendUnsupported => {
                "authorization was produced under an unsupported cryptographic backend"
            }
            Self::BackendMismatch => {
                "verifier backend does not match the authorization's bound backend"
            }
            Self::PaymentMismatch => {
                "authorization payment binding does not match the expected payment"
            }
            Self::PolicyMismatch => {
                "authorization policy binding does not match the expected policy"
            }
            Self::CircuitMismatch => {
                "authorization circuit binding does not match the expected policy"
            }
            Self::ProofInvalid => "authorization proof is invalid",
            Self::AuthorizationGenerationFailed => "authorization generation failed",
            Self::SelfVerificationFailed => {
                "self-verification of the generated authorization failed"
            }
        };
        f.write_str(msg)
    }
}

impl std::error::Error for SdkError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_are_informative_and_secret_free() {
        // Every variant must format without panicking and without
        // including any data the caller did not supply themselves.
        let variants = [
            SdkError::InvalidPayment,
            SdkError::InvalidPolicy,
            SdkError::InvalidWitness,
            SdkError::ArtifactMalformed,
            SdkError::VersionUnsupported,
            SdkError::BackendUnsupported,
            SdkError::BackendMismatch,
            SdkError::PaymentMismatch,
            SdkError::PolicyMismatch,
            SdkError::CircuitMismatch,
            SdkError::ProofInvalid,
            SdkError::AuthorizationGenerationFailed,
            SdkError::SelfVerificationFailed,
        ];
        for v in variants {
            let s = format!("{}", v);
            assert!(!s.is_empty(), "Display must produce a non-empty message");
            assert!(!s.contains("0x"), "no raw hex in error messages: {s}");
        }
    }

    #[test]
    fn errors_are_copy_eq_and_debug() {
        let a = SdkError::ProofInvalid;
        let b = a;
        assert_eq!(a, b);
        assert_eq!(format!("{:?}", a), "ProofInvalid");
    }

    #[test]
    fn errors_implement_std_error_trait() {
        fn assert_error<E: std::error::Error>(_: E) {}
        assert_error(SdkError::InvalidPayment);
    }
}
