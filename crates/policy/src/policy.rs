//! The payment authorization policy model.
//!
//! A [`Policy`] is a declarative description of when a payment is
//! allowed: a threshold over credential commitments, a spending cap,
//! or boolean combinations of both. Policies are pure data — they are
//! compiled to arithmetic circuits by [`crate::compiler`] and reduced
//! to a stable [`PolicyId`] by domain-separated hashing.
//!
//! Canonical encoding: every variant is prefixed with a one-byte tag
//! and all variable-length collections are 4-byte big-endian length
//! framed, so the encoding is injective (distinct policies never share
//! an encoding) and therefore safe as a hash preimage.

use core::fmt;

use crypto_core::{CanonicalEncode, Digest, HashFunction, SecretBytes, Sha256Hash};

/// Domain separator binding policy ids to this application and policy
/// model version.
pub const POLICY_ID_DOMAIN: &[u8] = b"private-payment-auth/policy/v1";

/// Domain separator for credential commitments:
/// `SHA-256("private-payment-auth/credential/v1" ‖ secret_bytes)`.
pub const CREDENTIAL_COMMITMENT_DOMAIN: &[u8] = b"private-payment-auth/credential/v1";

/// Maximum nesting depth of a [`Policy`] tree accepted by validation.
///
/// Guards the recursive validator and compiler against stack exhaustion
/// from a hostile deeply-nested policy.
pub const MAX_POLICY_DEPTH: usize = 100;

/// Maximum number of credentials a [`Policy`] may reference in total.
///
/// Bounds compilation and witness sizing; a policy referencing an
/// unbounded number of credentials would otherwise drive unbounded work.
pub const MAX_CREDENTIAL_COUNT: usize = 1000;

/// One-byte variant tags for the canonical policy encoding.
mod tag {
    pub(super) const THRESHOLD: u8 = 1;
    pub(super) const AMOUNT_AT_MOST: u8 = 2;
    pub(super) const AND: u8 = 3;
    pub(super) const OR: u8 = 4;
}

/// Stable identity of a policy: `SHA-256(POLICY_ID_DOMAIN ‖ canonical_encoding)`.
///
/// Two policies with equal ids are equal by construction because the
/// canonical encoding is injective.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PolicyId(Digest);

impl PolicyId {
    /// Wraps a digest as a policy id.
    pub fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// Borrows the underlying digest.
    pub fn as_digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Debug for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PolicyId({})", self.0)
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl CanonicalEncode for PolicyId {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

/// The requirement one credential must satisfy.
///
/// A credential is valid when `SHA-256(credential_secret)` equals
/// `expected_commitment` (see [`credential_commitment`]). Only the
/// commitment is public; the secret stays with the payer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialPolicy {
    /// The expected `SHA-256` digest of the credential secret.
    pub expected_commitment: Digest,
}

impl CanonicalEncode for CredentialPolicy {
    fn encode(&self, out: &mut Vec<u8>) {
        self.expected_commitment.encode(out);
    }
}

/// Computes the credential commitment for `secret`.
pub fn credential_commitment(secret: &SecretBytes) -> Digest {
    Sha256Hash::hash_domain(CREDENTIAL_COMMITMENT_DOMAIN, secret.as_bytes()).into()
}

/// A declarative payment authorization policy.
///
/// All leaves evaluate to a boolean; combinators combine booleans. See
/// the crate-level documentation for evaluation semantics.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Policy {
    /// Satisfied when at least `k` of `credentials` are valid.
    Threshold {
        /// Minimum number of valid credentials (`k >= 1`).
        k: usize,
        /// The candidate credentials, in canonical order.
        credentials: Vec<CredentialPolicy>,
    },
    /// Satisfied when the payment amount is at most `limit`.
    ///
    /// Phase-7 caveat: the compiled constraint uses raw field
    /// arithmetic and is *not* production-safe for final financial
    /// amounts; see `docs/decisions/0008-private-authorization.md`.
    AmountAtMost {
        /// Maximum allowed amount, inclusive.
        limit: u64,
    },
    /// Satisfied when every sub-policy is satisfied.
    And {
        /// Sub-policies, in canonical order (at least one).
        policies: Vec<Policy>,
    },
    /// Satisfied when at least one sub-policy is satisfied.
    Or {
        /// Sub-policies, in canonical order (at least one).
        policies: Vec<Policy>,
    },
}

impl Policy {
    /// Returns the canonical encoding of this policy.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        CanonicalEncode::encode(self, &mut out);
        out
    }

    /// Computes the domain-separated semantic id of this policy.
    pub fn policy_id(&self) -> PolicyId {
        PolicyId::from_digest(Sha256Hash::hash_domain(POLICY_ID_DOMAIN, &self.encode()).into())
    }

    /// Checks structural validity independent of any circuit mapping.
    ///
    /// # Errors
    ///
    /// - [`crate::PolicyError::InvalidThreshold`] for `k == 0`.
    /// - [`crate::PolicyError::ZeroCredentials`] for an empty
    ///   credential list.
    /// - [`crate::PolicyError::ThresholdExceedsCount`] when
    ///   `k > credentials.len()`.
    /// - [`crate::PolicyError::ExcessiveCredentials`] when the total
    ///   credential count exceeds [`MAX_CREDENTIAL_COUNT`].
    /// - [`crate::PolicyError::ExcessivePolicyDepth`] when nesting
    ///   exceeds [`MAX_POLICY_DEPTH`].
    /// - [`crate::PolicyError::MalformedPolicy`] for empty `And`/`Or`
    ///   combinations or an invalid nested sub-policy.
    pub fn validate(&self) -> Result<(), crate::error::PolicyError> {
        let mut creds = 0usize;
        self.validate_impl(0, &mut creds)
    }

    fn validate_impl(
        &self,
        depth: usize,
        creds: &mut usize,
    ) -> Result<(), crate::error::PolicyError> {
        if depth > MAX_POLICY_DEPTH {
            return Err(crate::error::PolicyError::ExcessivePolicyDepth);
        }
        match self {
            Self::Threshold { k, credentials } => {
                if *k == 0 {
                    return Err(crate::error::PolicyError::InvalidThreshold);
                }
                if credentials.is_empty() {
                    return Err(crate::error::PolicyError::ZeroCredentials);
                }
                if *k > credentials.len() {
                    return Err(crate::error::PolicyError::ThresholdExceedsCount);
                }
                *creds += credentials.len();
                if *creds > MAX_CREDENTIAL_COUNT {
                    return Err(crate::error::PolicyError::ExcessiveCredentials);
                }
                Ok(())
            }
            Self::AmountAtMost { .. } => Ok(()),
            Self::And { policies } | Self::Or { policies } => {
                if policies.is_empty() {
                    return Err(crate::error::PolicyError::MalformedPolicy);
                }
                for policy in policies {
                    policy.validate_impl(depth + 1, creds)?;
                }
                Ok(())
            }
        }
    }
}

impl CanonicalEncode for Policy {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Threshold { k, credentials } => {
                out.push(tag::THRESHOLD);
                out.extend_from_slice(
                    &u32::try_from(*k)
                        .expect("threshold exceeds u32 range")
                        .to_be_bytes(),
                );
                out.extend_from_slice(&(credentials.len() as u32).to_be_bytes());
                for credential in credentials {
                    CanonicalEncode::encode(credential, out);
                }
            }
            Self::AmountAtMost { limit } => {
                out.push(tag::AMOUNT_AT_MOST);
                out.extend_from_slice(&limit.to_be_bytes());
            }
            Self::And { policies } => {
                out.push(tag::AND);
                out.extend_from_slice(&(policies.len() as u32).to_be_bytes());
                for policy in policies {
                    CanonicalEncode::encode(policy, out);
                }
            }
            Self::Or { policies } => {
                out.push(tag::OR);
                out.extend_from_slice(&(policies.len() as u32).to_be_bytes());
                for policy in policies {
                    CanonicalEncode::encode(policy, out);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn threshold(k: usize, n: usize) -> Policy {
        Policy::Threshold {
            k,
            credentials: (0usize..n)
                .map(|i| CredentialPolicy {
                    expected_commitment: Digest::new([i as u8; 32]),
                })
                .collect(),
        }
    }

    #[test]
    fn encoding_is_deterministic() {
        let policy = Policy::And {
            policies: vec![threshold(2, 3), Policy::AmountAtMost { limit: 500 }],
        };
        assert_eq!(policy.encode(), policy.encode());
    }

    #[test]
    fn distinct_policies_have_distinct_encodings() {
        let base = threshold(2, 3);
        let variants = [
            threshold(1, 3),
            threshold(2, 4),
            Policy::AmountAtMost { limit: 5 },
            Policy::Or {
                policies: vec![base.clone()],
            },
            Policy::And {
                policies: vec![base.clone()],
            },
        ];
        for variant in &variants {
            assert_ne!(base.encode(), variant.encode());
        }
        // Tag boundaries are unambiguous: a threshold followed by an
        // amount never decodes like two thresholds would.
        let combined = Policy::And {
            policies: vec![threshold(1, 1), Policy::AmountAtMost { limit: 1 }],
        };
        let swapped = Policy::And {
            policies: vec![Policy::AmountAtMost { limit: 1 }, threshold(1, 1)],
        };
        assert_ne!(combined.encode(), swapped.encode());
    }

    #[test]
    fn policy_ids_are_stable_and_discriminating() {
        let policy = Policy::And {
            policies: vec![threshold(2, 3), Policy::AmountAtMost { limit: 100 }],
        };
        assert_eq!(policy.policy_id(), policy.policy_id());

        let mutated = Policy::And {
            policies: vec![threshold(2, 3), Policy::AmountAtMost { limit: 101 }],
        };
        assert_ne!(policy.policy_id(), mutated.policy_id());
    }

    #[test]
    fn validation_enforces_threshold_shape() {
        assert_eq!(
            Policy::Threshold {
                k: 0,
                credentials: vec![]
            }
            .validate(),
            Err(crate::error::PolicyError::InvalidThreshold)
        );
        assert_eq!(
            Policy::Threshold {
                k: 1,
                credentials: vec![]
            }
            .validate(),
            Err(crate::error::PolicyError::ZeroCredentials)
        );
        assert_eq!(
            threshold(3, 2).validate(),
            Err(crate::error::PolicyError::ThresholdExceedsCount)
        );
        assert_eq!(threshold(2, 3).validate(), Ok(()));

        assert_eq!(
            Policy::And { policies: vec![] }.validate(),
            Err(crate::error::PolicyError::MalformedPolicy)
        );
        assert_eq!(
            Policy::Or {
                policies: vec![Policy::And { policies: vec![] }]
            }
            .validate(),
            Err(crate::error::PolicyError::MalformedPolicy)
        );
        assert_eq!(Policy::AmountAtMost { limit: 10 }.validate(), Ok(()));
    }

    #[test]
    fn credential_commitments_are_domain_separated() {
        let secret = SecretBytes::new(vec![1, 2, 3]);
        assert_eq!(
            credential_commitment(&secret),
            credential_commitment(&secret)
        );
        let other = SecretBytes::new(vec![1, 2, 4]);
        assert_ne!(
            credential_commitment(&secret),
            credential_commitment(&other)
        );
        assert_ne!(
            credential_commitment(&secret).as_bytes(),
            &Sha256Hash::hash(secret.as_bytes())
        );
    }
}
