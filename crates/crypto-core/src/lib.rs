//! Core cryptographic primitives and traits.
//!
//! This crate defines the foundational types and implementations for
//! digests, secret handling, and error reporting used by every other
//! crate in the workspace.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod backend;
pub mod commitment;
pub mod digest;
pub mod encoding;
pub mod error;
pub mod hash;
pub mod random;
pub mod secret;

pub use backend::{
    BackendId, CryptoBackend, GenericDigest, Shake256Backend, Sha256Backend, BACKEND_ID_LEN,
    DOMAIN_CIRCUIT, DOMAIN_COMMIT, DOMAIN_FS, DOMAIN_HASH, DOMAIN_PAYMENT, DOMAIN_POLICY,
};
pub use commitment::{commit, open, Commitment, CommitmentRandomness, RANDOMNESS_LEN};
pub use digest::{Digest, DIGEST_LEN};
pub use encoding::CanonicalEncode;
pub use error::CryptoCoreError;
pub use hash::{HashFunction, Sha256Hash};
pub use secret::SecretBytes;
