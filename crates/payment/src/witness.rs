//! The prover's private witness.
//!
//! [`PrivateWitness`] carries the credential secrets that back a
//! payment authorization. It never enters any statement or proof
//! artifact; it only feeds the proving pipeline and is dropped
//! (zeroized) afterwards.

use policy::Policy;

use crate::error::PaymentError;

/// Upper bound on a single credential secret's length.
pub const MAX_CREDENTIAL_SECRET_LEN: usize = 4096;

/// Secret inputs for an authorization attempt.
#[derive(Clone)]
pub struct PrivateWitness {
    /// Credential secrets in the policy's canonical (depth-first)
    /// order; one per [`policy::CredentialPolicy`].
    pub credential_secrets: Vec<crypto_core::SecretBytes>,
}

impl core::fmt::Debug for PrivateWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "PrivateWitness({} secrets)",
            self.credential_secrets.len()
        )
    }
}

impl PrivateWitness {
    /// Checks the witness against `policy`'s shape.
    ///
    /// # Errors
    ///
    /// - [`PaymentError::InvalidPolicy`] if `policy` itself is invalid.
    /// - [`PaymentError::WitnessCountMismatch`] if the secret count
    ///   differs from the number of credentials declared by the policy.
    /// - [`PaymentError::MalformedCredentialSecret`] for empty secrets
    ///   or secrets beyond [`MAX_CREDENTIAL_SECRET_LEN`].
    pub fn validate(&self, policy: &Policy) -> Result<(), PaymentError> {
        let required = required_credentials(policy)?;
        if self.credential_secrets.len() != required {
            return Err(PaymentError::WitnessCountMismatch);
        }
        for secret in &self.credential_secrets {
            if secret.is_empty() || secret.len() > MAX_CREDENTIAL_SECRET_LEN {
                return Err(PaymentError::MalformedCredentialSecret);
            }
        }
        Ok(())
    }
}

/// Counts the credentials a witness must supply, in canonical order.
///
/// # Errors
///
/// Returns [`crate::error::PaymentError::InvalidPolicy`] when the tree
/// is structurally invalid or contains no threshold leaf.
pub fn required_credentials(policy: &Policy) -> Result<usize, PaymentError> {
    use policy::Policy;
    match policy {
        Policy::Threshold { credentials, .. } => Ok(credentials.len()),
        Policy::AmountAtMost { .. } => Ok(0),
        Policy::And { policies } | Policy::Or { policies } => {
            let mut total = 0;
            for sub in policies {
                total += required_credentials(sub)?;
            }
            Ok(total)
        }
    }
}
