//! The prover's private witness.
//!
//! [`PrivateWitness`] carries everything a payment authorization proves
//! knowledge of: the credential secrets backing the policy's
//! commitments, the payment amount, and the binary digit witnesses for
//! the sound range check. It never enters any statement or proof
//! artifact; it feeds the proving pipeline and is dropped (zeroized)
//! afterwards.
//!
//! Credential secrets are stored in the policy's canonical
//! (depth-first) order of [`Policy::Credential`] leaves, matching the order the
//! compiler consumes them.

use crypto_core::SecretBytes;
use policy::{credential_commitment, AmountLimit, CredentialId, Policy};
use zeroize::Zeroize;

use crate::amount::Amount;
use crate::error::PaymentError;

/// Upper bound on a single credential secret's length.
pub const MAX_CREDENTIAL_SECRET_LEN: usize = 4096;

/// Secret inputs for an authorization attempt.
#[derive(Clone)]
pub struct PrivateWitness {
    /// Credential secrets in the policy's canonical (depth-first)
    /// order; one per [`Policy::Credential`] leaf.
    pub credential_secrets: Vec<SecretBytes>,
    /// The payment amount being authorized.
    pub amount: Amount,
    /// Little-endian binary digits of `amount.value`, as consumed by
    /// the range-check gadget (`SecretSlot::AmountBit`).
    pub amount_bits: [bool; policy::AMOUNT_BIT_LEN],
    /// Little-endian binary digits of `limit − amount.value` for the
    /// policy's amount cap(s), as consumed by `SecretSlot::DifferenceBit`.
    pub difference_bits: [bool; policy::AMOUNT_BIT_LEN],
}

impl PrivateWitness {
    /// Builds a witness with honest digit decompositions relative to
    /// `limit` (the policy's first amount cap).
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
        let required = policy_credential_ids(policy).len();
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

    /// Builds the typed [`policy::PolicyWitness`] consumed by the
    /// reference evaluator and circuit compiler.
    ///
    /// # Errors
    ///
    /// Returns [`PaymentError::WitnessCountMismatch`] if the secret
    /// count disagrees with the policy.
    pub fn to_policy_witness(
        &self,
        policy: &Policy,
    ) -> Result<policy::PolicyWitness, PaymentError> {
        self.validate(policy)?;
        let ids = policy_credential_ids(policy);
        let mut witness =
            policy::PolicyWitness::new().with_amount(AmountLimit::new(self.amount.value));
        for (id, secret) in ids.into_iter().zip(self.credential_secrets.iter()) {
            witness = witness.with_credential(id, secret.clone());
        }
        Ok(witness)
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

/// Returns the credential ids in the policy's canonical (depth-first)
/// order — the order in which [`PrivateWitness::credential_secrets`]
/// must be supplied.
#[must_use]
pub fn policy_credential_ids(policy: &Policy) -> Vec<CredentialId> {
    let mut ids = Vec::new();
    collect(policy, &mut ids);
    ids
}

fn collect(policy: &Policy, ids: &mut Vec<CredentialId>) {
    match policy {
        Policy::Credential(id) => ids.push(*id),
        Policy::AmountAtMost(_) => {}
        Policy::Threshold { members, .. } | Policy::And(members) | Policy::Or(members) => {
            for member in members {
                collect(member, ids);
            }
        }
    }
}

/// Recomputes a credential commitment; exposed for tests and tooling.
#[must_use]
pub fn recompute_commitment(secret: &crypto_core::SecretBytes) -> crypto_core::Digest {
    credential_commitment(secret)
}
