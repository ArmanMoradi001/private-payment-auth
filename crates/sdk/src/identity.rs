//! Semantic identity of [`Authorization`] artifacts.
//!
//! An [`AuthorizationId`] is the domain-separated SHA-256 hash of the
//! canonical encoding of an authorization. Two authorizations share an
//! id exactly when every binding field — version, protocol version,
//! backend, payment, policy, circuit, and the contained proof bytes —
//! is identical.

use core::fmt;

use crypto_core::CanonicalEncode;
use crypto_core::Digest;
use crypto_core::HashFunction;
use crypto_core::Sha256Hash;

use crate::types::{Authorization, AUTHORIZATION_ID_DOMAIN};

/// Stable identity of an [`Authorization`].
///
/// Constructed via [`authorization_id`] from an [`Authorization`]; two
/// authorizations share an [`AuthorizationId`] exactly when they bind
/// the same payment, policy, circuit, and proof under the same
/// protocol/backend.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct AuthorizationId(Digest);

impl AuthorizationId {
    /// Wraps a digest as an authorization id.
    pub fn from_digest(digest: Digest) -> Self {
        Self(digest)
    }

    /// Borrows the underlying digest.
    pub fn as_digest(&self) -> &Digest {
        &self.0
    }

    /// Returns the raw 32-byte id.
    pub fn as_bytes(&self) -> &[u8; 32] {
        self.0.as_bytes()
    }
}

impl fmt::Debug for AuthorizationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AuthorizationId({})", self.0)
    }
}

impl fmt::Display for AuthorizationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Computes the domain-separated semantic id of `auth`.
///
/// The hash input is the canonical encoding of:
///
/// ```text
/// version(u8)
///   ‖ protocol_version(u8)
///   ‖ backend_id(16B)
///   ‖ payment_id(32B)
///   ‖ policy_id(32B)
///   ‖ circuit_id(32B)
///   ‖ proof_bytes(canonical proof encoding)
/// ```
///
/// Domain separator: [`AUTHORIZATION_ID_DOMAIN`].
pub fn authorization_id(auth: &Authorization) -> AuthorizationId {
    let mut buf: Vec<u8> = Vec::new();
    buf.push(auth.version());
    buf.push(auth.protocol_version());
    auth.backend_id().encode(&mut buf);
    buf.extend_from_slice(auth.payment_id());
    auth.policy_id().encode(&mut buf);
    auth.circuit_id().encode(&mut buf);

    let proof_bytes = proof::encoding::serialize_proof(auth.proof());
    (&proof_bytes[..]).encode(&mut buf);

    let digest = Sha256Hash::hash_domain(AUTHORIZATION_ID_DOMAIN, &buf);
    AuthorizationId::from_digest(digest.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use circuit::CircuitId;
    use crypto_core::BackendId;
    use crypto_core::Digest;
    use mpc::PublicValue;
    use mpcith::FieldElement;
    use proof::Statement;

    fn dummy_statement() -> Statement {
        Statement {
            circuit_id: CircuitId::from_digest(Digest::new([0x11; 32])),
            public_inputs: Vec::<PublicValue<FieldElement>>::new(),
            expected_outputs: Vec::<PublicValue<FieldElement>>::new(),
        }
    }

    fn dummy_proof() -> proof::NonInteractiveProof {
        proof::NonInteractiveProof::new(
            1,
            1,
            BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0"),
            dummy_statement(),
            Vec::new(),
        )
    }

    #[test]
    fn ids_are_deterministic_and_discriminating() {
        let auth = Authorization::new(
            1,
            1,
            BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0"),
            [1u8; 32],
            Digest::new([2u8; 32]),
            Digest::new([3u8; 32]),
            dummy_proof(),
        );
        assert_eq!(authorization_id(&auth), authorization_id(&auth));

        // Mutate one binding field: payment_id.
        let other = Authorization::new(
            1,
            1,
            BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0"),
            [9u8; 32],
            Digest::new([2u8; 32]),
            Digest::new([3u8; 32]),
            dummy_proof(),
        );
        assert_ne!(authorization_id(&auth), authorization_id(&other));
    }

    #[test]
    fn id_changes_with_protocol_version() {
        let proof = dummy_proof();
        let backend = BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0");
        let a = Authorization::new(
            1,
            1,
            backend,
            [1u8; 32],
            Digest::new([2u8; 32]),
            Digest::new([3u8; 32]),
            proof.clone(),
        );
        let b = Authorization::new(
            1,
            2,
            backend,
            [1u8; 32],
            Digest::new([2u8; 32]),
            Digest::new([3u8; 32]),
            proof,
        );
        assert_ne!(authorization_id(&a), authorization_id(&b));
    }

    #[test]
    fn debug_display_format() {
        let auth = Authorization::new(
            1,
            1,
            BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0"),
            [0u8; 32],
            Digest::new([0u8; 32]),
            Digest::new([0u8; 32]),
            dummy_proof(),
        );
        let id = authorization_id(&auth);
        let printed = format!("{}", id);
        assert_eq!(printed.len(), 64);
        assert!(format!("{:?}", id).starts_with("AuthorizationId("));
    }
}
