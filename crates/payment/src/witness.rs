//! The prover's private witness.
//!
//! [`PrivateWitness`] carries everything a payment authorization
//! proves knowledge of: the credential secrets backing the policy's
//! commitments, the payment amount, and the binary digit witnesses for
//! the sound range check (`policy::range_check`). It never enters any
//! statement or proof artifact; it feeds the proving pipeline and is
//! dropped (zeroized) afterwards.

use crypto_core::SecretBytes;
use policy::range_check::AMOUNT_BIT_LEN;
use policy::Policy;
use zeroize::Zeroize;

use crate::amount::Amount;
use crate::error::PaymentError;

/// Upper bound on a single credential secret's length.
pub const MAX_CREDENTIAL_SECRET_LEN: usize = 4096;

/// Secret inputs for an authorization attempt.
#[derive(Clone)]
pub struct PrivateWitness {
    /// Credential secrets in the policy's canonical (depth-first)
    /// order; one per [`policy::CredentialPolicy`].
    pub credential_secrets: Vec<SecretBytes>,
    /// The payment amount being authorized.
    pub amount: Amount,
    /// Little-endian binary digits of `amount.value`, as consumed by
    /// the range-check gadget (`SecretSlot::AmountBit`).
    pub amount_bits: [bool; AMOUNT_BIT_LEN],
    /// Little-endian binary digits of `limit − amount.value` for the
    /// policy's amount cap(s), as consumed by
    /// `SecretSlot::DifferenceBit`.
    pub difference_bits: [bool; AMOUNT_BIT_LEN],
}

impl PrivateWitness {
    /// Builds a witness with honest digit decompositions relative to
    /// `limit` (the policy's amount cap).
    ///
    /// For policies whose amount leaves declare several distinct
    /// limits, only one difference decomposition can be supplied; use
    /// distinct caps in separate policies or identical limits.
    #[must_use]
    pub fn new(credentials: Vec<SecretBytes>, amount: Amount, limit: u64) -> Self {
        Self {
            credential_secrets: credentials,
            amount,
            amount_bits: crate::decompose(amount.value),
            difference_bits: crate::decompose(limit.wrapping_sub(amount.value)),
        }
    }

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

impl core::fmt::Debug for PrivateWitness {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PrivateWitness")
            .field("credentials", &self.credential_secrets.len())
            .field("amount", &self.amount)
            .finish_non_exhaustive()
    }
}

impl Zeroize for PrivateWitness {
    fn zeroize(&mut self) {
        for secret in &mut self.credential_secrets {
            secret.zeroize();
        }
        self.amount.value = 0;
        for bit in &mut self.amount_bits {
            *bit = false;
        }
        for bit in &mut self.difference_bits {
            *bit = false;
        }
    }
}

impl Drop for PrivateWitness {
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Counts the credentials a witness must supply, in canonical order.
///
/// # Errors
///
/// Returns [`crate::error::PaymentError::InvalidPolicy`] when the tree
/// is structurally invalid.
pub fn required_credentials(policy: &Policy) -> Result<usize, PaymentError> {
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
