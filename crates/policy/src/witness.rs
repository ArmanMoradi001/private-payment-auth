//! The typed witness model for policy evaluation.
//!
//! A [`PolicyWitness`] binds the secret material a prover supplies to a
//! (normalized) policy. It uses typed, deterministically-ordered
//! collections — never `HashMap` keyed by free-form strings — so that
//! witness construction and consumption are reproducible.

use crypto_core::SecretBytes;

use crate::ast::{AmountLimit, CredentialId, Policy};
use crate::error::PolicyError;

/// A prover's secret inputs for a (normalized) policy.
#[derive(Clone, Debug)]
pub struct PolicyWitness {
    /// Credential secrets, each bound to the credential id it satisfies.
    ///
    /// Ordered by insertion; lookups are by [`CredentialId`], so the
    /// order is irrelevant to semantics but kept deterministic for
    /// reproducibility.
    pub credential_secrets: Vec<(CredentialId, SecretBytes)>,
    /// The payment amount, when the policy contains an `AmountAtMost`
    /// leaf. `None` means the amount is absent (the witness will fail
    /// any amount check).
    pub amount: Option<AmountLimit>,
}

impl PolicyWitness {
    /// Builds an empty witness.
    pub fn new() -> Self {
        Self {
            credential_secrets: Vec::new(),
            amount: None,
        }
    }

    /// Adds a credential secret binding.
    pub fn with_credential(mut self, id: CredentialId, secret: SecretBytes) -> Self {
        self.credential_secrets.push((id, secret));
        self
    }

    /// Sets the payment amount.
    pub fn with_amount(mut self, amount: AmountLimit) -> Self {
        self.amount = Some(amount);
        self
    }

    /// Checks that this witness matches `policy`'s shape: every
    /// credential leaf has a secret and any amount cap is backed by an
    /// amount.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError::WitnessMismatch`] if a credential id is
    /// missing or the policy needs an amount that is absent.
    pub fn validate_against(&self, policy: &Policy) -> Result<(), PolicyError> {
        let mut required_credentials = Vec::new();
        let mut needs_amount = false;
        collect_requirements(policy, &mut required_credentials, &mut needs_amount);

        for id in &required_credentials {
            if !self
                .credential_secrets
                .iter()
                .any(|(present, _)| present == id)
            {
                return Err(PolicyError::WitnessMismatch);
            }
        }
        if needs_amount && self.amount.is_none() {
            return Err(PolicyError::WitnessMismatch);
        }
        Ok(())
    }

    /// Looks up the secret bound to `id`, if present.
    pub fn secret_for(&self, id: &CredentialId) -> Option<&SecretBytes> {
        self.credential_secrets
            .iter()
            .find(|(present, _)| present == id)
            .map(|(_, secret)| secret)
    }
}

impl Default for PolicyWitness {
    fn default() -> Self {
        Self::new()
    }
}

/// Outcome of evaluating a single policy node (no secret material).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeOutcome {
    /// An amount-cap leaf.
    Amount {
        /// The limit that was checked.
        limit: AmountLimit,
        /// Whether the amount was within the limit.
        satisfied: bool,
    },
    /// A credential leaf.
    Credential {
        /// The credential id that was checked.
        id: CredentialId,
        /// Whether the supplied secret matched the commitment.
        satisfied: bool,
    },
    /// A threshold combinator.
    Threshold {
        /// The arity.
        k: crate::ast::ThresholdK,
        /// Whether at least `k` members were satisfied.
        satisfied: bool,
        /// Outcomes of the members, in policy order.
        members: Vec<NodeOutcome>,
    },
    /// An `And` combinator.
    And {
        /// Whether every member was satisfied.
        satisfied: bool,
        /// Outcomes of the members, in policy order.
        members: Vec<NodeOutcome>,
    },
    /// An `Or` combinator.
    Or {
        /// Whether at least one member was satisfied.
        satisfied: bool,
        /// Outcomes of the members, in policy order.
        members: Vec<NodeOutcome>,
    },
}

/// The result of evaluating a whole policy.
///
/// `authorized` is the root outcome; `root` carries the per-node detail
/// for testing and debugging. No secret or witness value is exposed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthorizationResult {
    /// Whether the whole policy authorized.
    pub authorized: bool,
    /// The outcome tree rooted at the policy.
    pub root: NodeOutcome,
}

fn collect_requirements(
    policy: &Policy,
    credentials: &mut Vec<CredentialId>,
    needs_amount: &mut bool,
) {
    match policy {
        Policy::AmountAtMost(_) => *needs_amount = true,
        Policy::Credential(id) => credentials.push(*id),
        Policy::Threshold { members, .. } | Policy::And(members) | Policy::Or(members) => {
            for member in members {
                collect_requirements(member, credentials, needs_amount);
            }
        }
    }
}
