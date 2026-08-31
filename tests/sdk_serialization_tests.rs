//! Round-trip and compatibility tests for the canonical
//! [`Authorization`] encoding.
//!
//! These tests sit outside the `sdk` crate (in the workspace-level
//! integration test tree) so they exercise the public API the same way
//! an external consumer would: via [`sdk::serialize`] and
//! [`sdk::deserialize`].

use circuit::CircuitId;
use crypto_core::{BackendId, Digest};
use mpc::PublicValue;
use mpcith::FieldElement;
use proof::Statement;
use sdk::{deserialize, serialize, Authorization, SdkError};

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

const SHA256_BACKEND: BackendId = BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0");

fn sample_auth() -> Authorization {
    Authorization::new(
        sdk::AUTHORIZATION_VERSION,
        1,
        SHA256_BACKEND,
        [1u8; 32],
        Digest::new([2u8; 32]),
        Digest::new([3u8; 32]),
        dummy_proof(SHA256_BACKEND),
    )
}

fn alt_auth() -> Authorization {
    Authorization::new(
        sdk::AUTHORIZATION_VERSION,
        2,
        SHA256_BACKEND,
        [0xaa; 32],
        Digest::new([0xbb; 32]),
        Digest::new([0xcc; 32]),
        dummy_proof(SHA256_BACKEND),
    )
}

#[test]
fn round_trip_preserves_authorization() {
    let auth = sample_auth();
    let bytes = serialize(&auth);
    let recovered = deserialize(&bytes).expect("valid encoding must decode");
    assert_eq!(recovered.version(), auth.version());
    assert_eq!(recovered.protocol_version(), auth.protocol_version());
    assert_eq!(recovered.backend_id(), auth.backend_id());
    assert_eq!(recovered.payment_id(), auth.payment_id());
    assert_eq!(recovered.policy_id(), auth.policy_id());
    assert_eq!(recovered.circuit_id(), auth.circuit_id());
}

#[test]
fn round_trips_distinct_authorizations() {
    for auth in [sample_auth(), alt_auth()] {
        let bytes = serialize(&auth);
        let recovered = deserialize(&bytes).expect("valid encoding must decode");
        assert_eq!(recovered.payment_id(), auth.payment_id());
        assert_eq!(recovered.protocol_version(), auth.protocol_version());
    }
}

#[test]
fn serialization_is_byte_for_byte_stable() {
    let auth = sample_auth();
    let a = serialize(&auth);
    let b = serialize(&auth);
    assert_eq!(a, b, "serialize must be deterministic");
}

#[test]
fn distinct_authorizations_produce_distinct_bytes() {
    let a = serialize(&sample_auth());
    let b = serialize(&alt_auth());
    assert_ne!(a, b);
}

#[test]
fn deserialize_rejects_empty_input() {
    assert!(matches!(deserialize(&[]), Err(SdkError::ArtifactMalformed)));
}

#[test]
fn deserialize_rejects_truncated_header() {
    let bytes = serialize(&sample_auth());
    // Cut one byte off the front of each header field.
    for cut in 0..bytes.len() {
        if cut < 114 {
            assert!(
                matches!(deserialize(&bytes[..cut]), Err(SdkError::ArtifactMalformed)),
                "expected ArtifactMalformed for truncation at {cut}"
            );
        } else {
            // Cuts inside the proof bytes can be either ArtifactMalformed
            // (truncation) or VersionUnsupported (proof version mismatch)
            // — both are acceptable hard rejections.
            let outcome = deserialize(&bytes[..cut]);
            assert!(
                matches!(
                    outcome,
                    Err(SdkError::ArtifactMalformed) | Err(SdkError::VersionUnsupported)
                ),
                "unexpected outcome at cut {cut}: {outcome:?}"
            );
        }
    }
}

#[test]
fn deserialize_rejects_trailing_bytes() {
    let mut bytes = serialize(&sample_auth());
    bytes.push(0xff);
    assert!(matches!(
        deserialize(&bytes),
        Err(SdkError::ArtifactMalformed)
    ));
}

#[test]
fn deserialize_rejects_unknown_artifact_version() {
    let mut bytes = serialize(&sample_auth());
    bytes[0] = sdk::AUTHORIZATION_VERSION.wrapping_add(1);
    assert!(matches!(
        deserialize(&bytes),
        Err(SdkError::VersionUnsupported)
    ));
}

#[test]
fn deserialize_rejects_unknown_protocol_version() {
    let mut bytes = serialize(&sample_auth());
    bytes[1] = 99;
    assert!(matches!(
        deserialize(&bytes),
        Err(SdkError::VersionUnsupported)
    ));
}

#[test]
fn deserialize_rejects_unknown_backend_id() {
    let mut bytes = serialize(&sample_auth());
    // Overwrite the backend_id (bytes 2..18) with a well-formed but
    // unsupported 16-byte id.
    bytes[2..18].copy_from_slice(b"unknown-v99\0\0\0\0\0");
    assert!(matches!(
        deserialize(&bytes),
        Err(SdkError::BackendUnsupported)
    ));
}

#[test]
fn deserialize_rejects_zero_version() {
    let mut bytes = serialize(&sample_auth());
    bytes[0] = 0;
    assert!(matches!(
        deserialize(&bytes),
        Err(SdkError::VersionUnsupported)
    ));
}

#[test]
fn deserialize_rejects_max_version() {
    let mut bytes = serialize(&sample_auth());
    bytes[0] = u8::MAX;
    assert!(matches!(
        deserialize(&bytes),
        Err(SdkError::VersionUnsupported)
    ));
}

#[test]
fn supported_protocol_versions_match_decode_policy() {
    // Every supported version must round-trip cleanly.
    for &v in sdk::SUPPORTED_PROTOCOL_VERSIONS {
        let auth = Authorization::new(
            sdk::AUTHORIZATION_VERSION,
            v,
            SHA256_BACKEND,
            [1u8; 32],
            Digest::new([2u8; 32]),
            Digest::new([3u8; 32]),
            dummy_proof(SHA256_BACKEND),
        );
        let bytes = serialize(&auth);
        let recovered = deserialize(&bytes).expect("supported protocol version must decode");
        assert_eq!(recovered.protocol_version(), v);
    }

    // The set must reject at least one value.
    assert!(!sdk::SUPPORTED_PROTOCOL_VERSIONS.is_empty());
    assert!(!sdk::SUPPORTED_PROTOCOL_VERSIONS.contains(&0));
}
