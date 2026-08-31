//! Canonical serialization for [`Authorization`] artifacts.
//!
//! This module is the on-the-wire counterpart to
//! [`crate::identity::authorization_id`]. The byte layout mirrors the
//! id-hash input one-for-one so any change to the encoding is visible
//! in the id and vice versa.
//!
//! ## Layout
//!
//! ```text
//! version(u8) ‖ protocol_version(u8) ‖ backend_id(16B) ‖ payment_id(32B)
//!   ‖ policy_id(32B) ‖ circuit_id(32B) ‖ proof_bytes
//! ```
//!
//! `proof_bytes` is the output of [`proof::encoding::serialize_proof`],
//! which is itself self-delimiting (it rejects trailing bytes).
//!
//! ## Versioning
//!
//! [`AUTHORIZATION_VERSION`] is the on-the-wire artifact version. It is
//! bumped whenever the layout above changes incompatibly. Decoders
//! reject unknown versions; they never silently upgrade or downgrade.
//!
//! ## Compatibility policy
//!
//! Decoding enforces all three compatibility rules in order, and on
//! failure reports the most specific [`SdkError`] available:
//!
//! 1. The artifact `version` byte must equal
//!    [`AUTHORIZATION_VERSION`]. Otherwise
//!    [`SdkError::VersionUnsupported`].
//! 2. The `protocol_version` byte must be in
//!    [`SUPPORTED_PROTOCOL_VERSIONS`]. Otherwise
//!    [`SdkError::VersionUnsupported`].
//! 3. The `backend_id` must be in [`SUPPORTED_BACKEND_IDS`]
//!    (re-exported from [`proof::encoding`]). Otherwise
//!    [`SdkError::BackendUnsupported`].
//! 4. The contained proof is then re-validated by
//!    [`proof::encoding::deserialize_proof`], which enforces its own
//!    version, protocol id, and backend-id rules; failures are
//!    translated to the same [`SdkError`] shape.
//!
//! There is no silent upgrade/downgrade path and no guessing of
//! compatibility. The caller must align their SDK build with the
//! artifact's bound versions.
//!
//! ## No secrets
//!
//! [`Authorization`] contains no secret material by design: every
//! secret input was absorbed into MPCitH view commitments inside the
//! proof, and the proof redacts its hidden material in `Debug`. The
//! canonical encoding therefore contains nothing a third party needs
//! to keep confidential.

use crypto_core::BackendId;
use proof::encoding::serialize_proof;
use proof::encoding::SUPPORTED_BACKEND_IDS;
use proof::NonInteractiveProof;
use proof::ProofError;

use crate::error::SdkError;
use crate::types::Authorization;
use crate::types::AUTHORIZATION_VERSION;

/// Protocol versions this SDK build accepts during decoding.
///
/// The set is intentionally explicit: anything outside it is rejected
/// with [`SdkError::VersionUnsupported`] rather than silently
/// downgraded to a known version.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u8] = &[1, 2];

/// Width of the fixed-size header in bytes:
///
/// `version(u8) ‖ protocol_version(u8) ‖ backend_id(16B) ‖ payment_id(32B) ‖ policy_id(32B) ‖ circuit_id(32B)`.
const HEADER_LEN: usize = 1 + 1 + 16 + 32 + 32 + 32;

/// Encodes `auth` into its canonical byte representation.
///
/// The output is deterministic: serializing the same `Authorization`
/// twice always produces byte-for-byte identical output. The encoding
/// contains no secret material.
///
/// Layout: see the [module-level documentation](self).
pub fn serialize(auth: &Authorization) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + 64);
    out.push(auth.version());
    out.push(auth.protocol_version());
    out.extend_from_slice(auth.backend_id().as_bytes());
    out.extend_from_slice(auth.payment_id());
    out.extend_from_slice(auth.policy_id().as_bytes());
    out.extend_from_slice(auth.circuit_id().as_bytes());
    let proof_bytes = serialize_proof(auth.proof());
    out.extend_from_slice(&proof_bytes);
    out
}

/// Decodes `bytes` into an [`Authorization`], enforcing the
/// compatibility rules described in the module documentation.
///
/// # Errors
///
/// - [`SdkError::VersionUnsupported`] if the artifact version or
///   protocol version byte is outside the supported set.
/// - [`SdkError::BackendUnsupported`] if the artifact's `backend_id`
///   is not in [`SUPPORTED_BACKEND_IDS`] (or the contained proof's
///   `backend_id` is unknown).
/// - [`SdkError::ArtifactMalformed`] for any structural problem:
///   truncated bytes, trailing bytes, or any decode failure from the
///   contained proof.
pub fn deserialize(bytes: &[u8]) -> Result<Authorization, SdkError> {
    if bytes.len() < HEADER_LEN {
        return Err(SdkError::ArtifactMalformed);
    }

    let version = bytes[0];
    if version != AUTHORIZATION_VERSION {
        return Err(SdkError::VersionUnsupported);
    }

    let protocol_version = bytes[1];
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&protocol_version) {
        return Err(SdkError::VersionUnsupported);
    }

    let mut backend_id_bytes = [0u8; 16];
    backend_id_bytes.copy_from_slice(&bytes[2..18]);
    let backend_id = BackendId::new(backend_id_bytes);
    if !SUPPORTED_BACKEND_IDS.contains(&backend_id) {
        return Err(SdkError::BackendUnsupported);
    }

    let mut payment_id = [0u8; 32];
    payment_id.copy_from_slice(&bytes[18..50]);
    let policy_id = read_digest(&bytes[50..82])?;
    let circuit_id = read_digest(&bytes[82..114])?;

    let proof_bytes = &bytes[HEADER_LEN..];
    let proof = decode_proof(proof_bytes)?;

    Ok(Authorization::new(
        version,
        protocol_version,
        backend_id,
        payment_id,
        policy_id,
        circuit_id,
        proof,
    ))
}

fn read_digest(slice: &[u8]) -> Result<crypto_core::Digest, SdkError> {
    if slice.len() != 32 {
        return Err(SdkError::ArtifactMalformed);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(slice);
    Ok(crypto_core::Digest::new(out))
}

fn decode_proof(bytes: &[u8]) -> Result<NonInteractiveProof, SdkError> {
    match proof::encoding::deserialize_proof(bytes) {
        Ok(proof) => Ok(proof),
        Err(ProofError::InvalidVersion) => Err(SdkError::VersionUnsupported),
        Err(ProofError::UnsupportedBackend) => Err(SdkError::BackendUnsupported),
        Err(_) => Err(SdkError::ArtifactMalformed),
    }
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

    fn dummy_proof(backend: BackendId) -> proof::NonInteractiveProof {
        proof::NonInteractiveProof::new(
            proof::encoding::ENCODING_VERSION,
            proof::encoding::PROTOCOL_ID,
            backend,
            dummy_statement(),
            Vec::new(),
        )
    }

    fn sample_auth() -> Authorization {
        Authorization::new(
            AUTHORIZATION_VERSION,
            1,
            BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0"),
            [1u8; 32],
            Digest::new([2u8; 32]),
            Digest::new([3u8; 32]),
            dummy_proof(BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0")),
        )
    }

    #[test]
    fn header_layout_is_stable() {
        let bytes = serialize(&sample_auth());
        // version
        assert_eq!(bytes[0], AUTHORIZATION_VERSION);
        // protocol_version
        assert_eq!(bytes[1], 1);
        // backend_id prefix
        assert_eq!(&bytes[2..18], b"sha256-v1\0\0\0\0\0\0\0");
        // payment_id starts at offset 18
        assert_eq!(&bytes[18..50], &[1u8; 32]);
        // policy_id starts at offset 50
        assert_eq!(&bytes[50..82], &[2u8; 32]);
        // circuit_id starts at offset 82
        assert_eq!(&bytes[82..114], &[3u8; 32]);
        // proof bytes begin at the header boundary
        assert!(bytes.len() >= HEADER_LEN);
    }

    #[test]
    fn supported_protocol_versions_are_explicit() {
        assert!(SUPPORTED_PROTOCOL_VERSIONS.contains(&1));
        assert!(!SUPPORTED_PROTOCOL_VERSIONS.contains(&0));
    }

    #[test]
    fn deserialize_rejects_truncated_header() {
        let bytes = serialize(&sample_auth());
        for cut in 0..HEADER_LEN {
            assert!(
                matches!(deserialize(&bytes[..cut]), Err(SdkError::ArtifactMalformed)),
                "expected ArtifactMalformed at cut {cut}"
            );
        }
    }
}
