//! The typed policy AST.
//!
//! A [`Policy`] is a declarative description of when a payment is
//! authorized. Every variant is strongly typed so that the validation,
//! normalization, encoding, and circuit-compilation passes operate on
//! a single, unambiguous recursive structure — there is no external
//! text DSL or JSON policy format (see `docs/decisions/0011-policy-ast-
//! and-normalization.md`).
//!
//! Leaves evaluate to a boolean:
//!
//! * [`Policy::AmountAtMost`] — the payment amount is at most a limit.
//! * [`Policy::Credential`] — a credential secret hashes to a committed
//!   value.
//!
//! Combinators combine booleans:
//!
//! * [`Policy::Threshold`] — at least `k` members are satisfied.
//! * [`Policy::And`] — every member is satisfied.
//! * [`Policy::Or`] — at least one member is satisfied.

use core::fmt;

use crypto_core::{CryptoBackend, Digest};

use crate::error::PolicyError;

/// Canonical, fixed width of a [`CredentialId`].
pub const CREDENTIAL_ID_LEN: usize = 32;

/// Domain separator for credential commitments:
/// `SHA-256(DOMAIN_CREDENTIAL ‖ secret_bytes)`.
///
/// Shared by the reference evaluator and the circuit compiler so the
/// two never drift (see `docs/security/policy-security.md`).
pub const CREDENTIAL_COMMITMENT_DOMAIN: &[u8] = b"private-payment-auth/credential/v2";

/// A fixed-size, canonical credential identifier.
///
/// In this model a `CredentialId` *is* the expected commitment digest:
/// a payment authorizes when `SHA-256(secret) == CredentialId`. The 32
/// byte array is the natural canonical encoding, so credentials sort
/// and hash unambiguously.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CredentialId([u8; CREDENTIAL_ID_LEN]);

impl CredentialId {
    /// The all-zero credential id (rejected by validation).
    pub const ZERO: Self = Self([0u8; CREDENTIAL_ID_LEN]);

    /// Wraps raw bytes as a credential id.
    pub fn new(bytes: [u8; CREDENTIAL_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw bytes.
    pub fn as_bytes(&self) -> &[u8; CREDENTIAL_ID_LEN] {
        &self.0
    }

    /// Consumes the id, returning the raw bytes.
    pub fn to_array(self) -> [u8; CREDENTIAL_ID_LEN] {
        self.0
    }

    /// Builds a credential id from an expected commitment digest.
    pub fn from_commitment(digest: Digest) -> Self {
        Self(*digest.as_bytes())
    }

    /// Returns `true` if every byte is zero.
    pub fn is_zero(&self) -> bool {
        self.0 == [0u8; CREDENTIAL_ID_LEN]
    }
}

impl fmt::Debug for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialId({})", hex(&self.0))
    }
}

impl fmt::Display for CredentialId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

/// A spending limit: the payment amount must be `<= limit`.
///
/// Wraps the Phase 8 amount representation (an exact `u64` count of the
/// base unit). There is deliberately no conversion from an arbitrary
/// field element: amounts originate as `u64` and are proven in-range by
/// the dual bit-decomposition range check.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AmountLimit(u64);

impl AmountLimit {
    /// Wraps a raw limit value.
    pub fn new(limit: u64) -> Self {
        Self(limit)
    }

    /// Returns the limit value.
    pub fn value(&self) -> u64 {
        self.0
    }
}

impl fmt::Debug for AmountLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AmountLimit({})", self.0)
    }
}

impl fmt::Display for AmountLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A threshold arity `k`: at least `k` members must be satisfied.
///
/// Construction is unvalidated; [`crate::validation::validate`] enforces
/// `1 <= k <= members.len()`. `k` is a `u16` so the count is bounded
/// well below the membership limits and encodes in two bytes.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ThresholdK(u16);

impl ThresholdK {
    /// Wraps a raw arity.
    pub fn new(k: u16) -> Self {
        Self(k)
    }

    /// Returns the arity value.
    pub fn get(&self) -> u16 {
        self.0
    }
}

impl fmt::Debug for ThresholdK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ThresholdK({})", self.0)
    }
}

impl fmt::Display for ThresholdK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A declarative payment authorization policy.
///
/// All leaves evaluate to a boolean; combinators combine booleans. The
/// AST is recursive and strongly typed — see the crate-level
/// documentation for evaluation semantics and `normalize` for the
/// canonicalization rules.
#[derive(Clone, PartialEq, Eq)]
pub enum Policy {
    /// Satisfied when the payment amount is at most `limit`.
    AmountAtMost(AmountLimit),
    /// Satisfied when `SHA-256(secret) == id` for the matching witness
    /// secret (the credential commitment).
    Credential(CredentialId),
    /// Satisfied when at least `k` members are satisfied.
    Threshold {
        /// Minimum number of satisfied members (`1 <= k <= len`).
        k: ThresholdK,
        /// The member policies, in canonical order.
        members: Vec<Policy>,
    },
    /// Satisfied when every member is satisfied.
    And(Vec<Policy>),
    /// Satisfied when at least one member is satisfied.
    Or(Vec<Policy>),
}

impl Policy {
    /// Returns the canonical encoding of this policy.
    ///
    /// The encoding is deterministic, injective, versioned, and bounded.
    pub fn encode(&self) -> Vec<u8> {
        crate::encoding::encode(self)
    }

    /// Decodes a policy from its canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] for unknown versions, truncation, unknown
    /// tags, trailing bytes, or structurally invalid shapes.
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        crate::encoding::decode(bytes)
    }

    /// Computes the domain-separated semantic id of this policy.
    ///
    /// The policy is normalized first, so `policy_id(p) ==
    /// policy_id(normalize(p))`.
    pub fn policy_id(&self) -> crate::identity::PolicyId {
        crate::identity::policy_id(self).expect("normalization and encoding cannot fail")
    }

    /// Checks structural validity independent of any circuit mapping.
    ///
    /// # Errors
    ///
    /// Returns the first [`PolicyError`] encountered; see
    /// [`crate::validation::validate`].
    pub fn validate(&self) -> Result<(), PolicyError> {
        crate::validation::validate(self)
    }

    /// Returns the canonical (normalized) form of this policy.
    ///
    /// # Errors
    ///
    /// Returns [`PolicyError`] if normalization fails (it cannot for a
    /// structurally valid policy, but the surface is `Result`).
    pub fn normalize(&self) -> Result<Self, PolicyError> {
        crate::normalize::normalize(self)
    }
}

impl fmt::Debug for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AmountAtMost(limit) => write!(f, "AmountAtMost({limit})"),
            Self::Credential(id) => write!(f, "Credential({id})"),
            Self::Threshold { k, members } => write!(f, "Threshold(k={k}, {members:?})"),
            Self::And(members) => write!(f, "And({members:?})"),
            Self::Or(members) => write!(f, "Or({members:?})"),
        }
    }
}

/// Computes the credential commitment for `secret`.
///
/// This is the single source of truth for credential commitment
/// semantics, shared by the reference evaluator and the circuit
/// compiler.
pub fn credential_commitment(secret: &crypto_core::SecretBytes) -> Digest {
    let generic =
        crypto_core::Sha256Backend::hash_domain(CREDENTIAL_COMMITMENT_DOMAIN, secret.as_bytes());
    Digest::new(generic.to_array_32())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
