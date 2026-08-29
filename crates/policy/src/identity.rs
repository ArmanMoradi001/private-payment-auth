//! Semantic identity of [`Policy`] trees.
//!
//! A [`PolicyId`] is `SHA-256(DOMAIN_POLICY ‖ canonical_encoding)` where
//! the canonical encoding is that of the *normalized* policy. Because
//! normalization is canonical and the encoding is injective, two
//! policies share an id exactly when they are semantically equivalent.

use crypto_core::{CryptoBackend, Digest};

use crate::ast::Policy;
use crate::encoding::encode;
use crate::error::PolicyError;
use crate::normalize::normalize;
use crate::validation::MAX_ENCODED_SIZE;

/// Domain separator binding policy ids to this application and policy
/// model version.
pub const DOMAIN_POLICY: &[u8] = b"private-payment-auth/policy/v2";

/// Stable identity of a policy.
///
/// Two policies with equal ids are semantically equivalent by
/// construction (their normalized canonical encodings are identical).
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

    /// Returns the raw digest bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl core::fmt::Debug for PolicyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PolicyId({})", self.0)
    }
}

impl core::fmt::Display for PolicyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Computes the domain-separated semantic id of `policy`.
///
/// The policy is normalized first, so `policy_id(raw) ==
/// policy_id(normalize(raw))` for every valid policy.
///
/// # Errors
///
/// Returns [`PolicyError::EncodedSizeExceeded`] if the canonical
/// encoding exceeds [`MAX_ENCODED_SIZE`], or [`PolicyError::MalformedEncoding`]
/// if a size prefix cannot be encoded (which is unreachable for an
/// in-memory policy).
pub fn policy_id(policy: &Policy) -> Result<PolicyId, PolicyError> {
    let normalized = normalize(policy)?;
    let bytes = encode(&normalized);
    if bytes.len() > MAX_ENCODED_SIZE {
        return Err(PolicyError::EncodedSizeExceeded);
    }
    let generic = crypto_core::Sha256Backend::hash_domain(DOMAIN_POLICY, &bytes);
    Ok(PolicyId::from_digest(Digest::new(generic.to_array_32())))
}
