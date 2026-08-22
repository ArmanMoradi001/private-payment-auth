//! Core cryptographic primitives and traits.
//!
//! This crate defines the foundational types and implementations for
//! digests, secret handling, and error reporting used by every other
//! crate in the workspace.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod digest;
pub mod error;
pub mod secret;

pub use digest::{Digest, DIGEST_LEN};
pub use error::CryptoCoreError;
pub use secret::SecretBytes;
