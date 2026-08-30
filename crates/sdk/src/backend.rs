//! Backend dispatch for the verification-only workflow.
//!
//! The SDK is generic over the cryptographic backend (see
//! [`crypto_core::CryptoBackend`]) so a single artifact format can be
//! verified under any supported primitive. At runtime, however, the
//! `BackendId` recorded in an [`Authorization`](crate::Authorization)
//! is a plain byte tag with no compile-time type information. The
//! helpers in this module turn that tag back into a concrete backend
//! type so the verifier can dispatch to the right monomorphized code
//! path.
//!
//! Two principles govern the design:
//!
//! 1. **Explicit selection.** The SDK never silently picks a backend.
//!    On the authorization path the SDK reads
//!    [`SdkConfig::backend_id`](crate::SdkConfig::backend_id); on the
//!    verification path it reads the artifact's bound
//!    [`Authorization::backend_id`](crate::Authorization::backend_id).
//!    A mismatch between the verifier's configured backend and the
//!    artifact's bound backend is reported as
//!    [`SdkError::BackendMismatch`],
//!    never silently re-encoded.
//!
//! 2. **No secret material.** This module performs pure dispatch; it
//!    does not touch the witness, secret shares, or any private
//!    payload. It is safe to use from a verifier who only ever holds
//!    `(Payment, Policy, Authorization)`.

use crypto_core::BackendId;
use crypto_core::CryptoBackend;
use crypto_core::Sha256Backend;
use crypto_core::Shake256Backend;

use crate::error::SdkError;

/// Concrete backend variant the SDK can dispatch to today.
///
/// New variants may be appended; consumers must treat this as a
/// non-exhaustive set in case a backend is added in a future release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BackendType {
    /// SHA-256 backend (the workspace default).
    Sha256,
    /// SHAKE256 backend (a SHA-3 XOF, kept protocol-compatible via
    /// 32-byte fixed digests).
    Shake256,
}

impl BackendType {
    /// The [`BackendId`] this variant identifies with.
    pub fn id(&self) -> BackendId {
        match self {
            Self::Sha256 => Sha256Backend::ID,
            Self::Shake256 => Shake256Backend::ID,
        }
    }
}

/// Maps a [`BackendId`] to the concrete [`BackendType`] the SDK can
/// dispatch to.
///
/// Returns [`SdkError::BackendUnsupported`] when `id` does not name a
/// backend this SDK build knows how to handle. The SDK deliberately
/// refuses to silently fall back to a "closest match" — the caller
/// must align their configuration with the artifact's bound backend.
///
/// This helper carries no secrets: it is safe to call from a
/// verifier who only ever holds `(Payment, Policy, Authorization)`.
pub fn backend_from_id(id: &BackendId) -> Result<BackendType, SdkError> {
    if *id == Sha256Backend::ID {
        Ok(BackendType::Sha256)
    } else if *id == Shake256Backend::ID {
        Ok(BackendType::Shake256)
    } else {
        Err(SdkError::BackendUnsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_from_id_recognizes_supported_backends() {
        assert_eq!(
            backend_from_id(&Sha256Backend::ID).expect("sha256 must be supported"),
            BackendType::Sha256
        );
        assert_eq!(
            backend_from_id(&Shake256Backend::ID).expect("shake256 must be supported"),
            BackendType::Shake256
        );
    }

    #[test]
    fn backend_from_id_rejects_unknown_backends() {
        let unknown = BackendId::new(*b"unknown-v99\0\0\0\0\0");
        let err = backend_from_id(&unknown).expect_err("unknown backend must error");
        assert_eq!(err, SdkError::BackendUnsupported);
    }

    #[test]
    fn backend_type_id_round_trips() {
        for ty in [BackendType::Sha256, BackendType::Shake256] {
            let recovered = backend_from_id(&ty.id()).expect("round-trip must succeed");
            assert_eq!(recovered, ty);
        }
    }

    #[test]
    fn backend_type_ids_are_distinct() {
        assert_ne!(BackendType::Sha256.id(), BackendType::Shake256.id());
    }
}
