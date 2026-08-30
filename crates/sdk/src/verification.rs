//! Verification result types for the SDK.
//!
//! These types are the public, application-facing surface of
//! authorization verification. Variants are deliberately
//! **high-level**: they categorize the *kind* of mismatch (which
//! binding field disagreed, which dependency failed) but never leak
//! cryptographic internals such as share values, raw proof bytes,
//! MPCitH challenge outputs, or statement encoding details.

use core::fmt;

/// Outcome of [`crate::Sdk::verify`].
///
/// Returned in the `Ok` arm; never used for error propagation. Use the
/// [`VerificationFailure`] variants to react programmatically to
/// specific failure modes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationResult {
    /// Every binding and every cryptographic check passed.
    Valid,
    /// At least one binding check or the cryptographic proof failed.
    Invalid(VerificationFailure),
}

/// High-level reason an [`Authorization`](crate::Authorization)
/// verification failed.
///
/// Variants never embed cryptographic state, secret material, or raw
/// bytes — they are safe to surface in user-facing error messages and
/// logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerificationFailure {
    /// The authorization's payment binding does not match the
    /// caller's expected payment.
    PaymentMismatch,
    /// The authorization's policy binding does not match the
    /// caller's expected policy.
    PolicyMismatch,
    /// The authorization's circuit binding does not match the circuit
    /// derived from the caller's expected policy.
    CircuitMismatch,
    /// The authorization's cryptographic backend id does not match
    /// the SDK's configured backend.
    BackendMismatch,
    /// The authorization's encoding/protocol version is unsupported by
    /// this SDK build.
    VersionMismatch,
    /// The contained proof passed all binding checks but failed the
    /// cryptographic verification step.
    ProofInvalid,
}

impl fmt::Display for VerificationFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            Self::PaymentMismatch => "payment binding does not match expected payment",
            Self::PolicyMismatch => "policy binding does not match expected policy",
            Self::CircuitMismatch => "circuit binding does not match expected policy",
            Self::BackendMismatch => {
                "authorization was produced under an unsupported cryptographic backend"
            }
            Self::VersionMismatch => "authorization version is not supported by this SDK",
            Self::ProofInvalid => "authorization proof is invalid",
        };
        f.write_str(msg)
    }
}

impl VerificationResult {
    /// Returns `true` iff this result represents a fully valid
    /// authorization.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_is_recognized_as_valid() {
        assert!(VerificationResult::Valid.is_valid());
        assert!(!VerificationResult::Invalid(VerificationFailure::PaymentMismatch).is_valid());
        assert!(!VerificationResult::Invalid(VerificationFailure::ProofInvalid).is_valid());
    }

    #[test]
    fn failure_display_is_informative_and_secret_free() {
        for f in [
            VerificationFailure::PaymentMismatch,
            VerificationFailure::PolicyMismatch,
            VerificationFailure::CircuitMismatch,
            VerificationFailure::BackendMismatch,
            VerificationFailure::VersionMismatch,
            VerificationFailure::ProofInvalid,
        ] {
            let s = format!("{}", f);
            assert!(!s.is_empty());
            assert!(!s.contains("0x"));
        }
    }
}
