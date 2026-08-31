//! Public SDK for integrating cryptographic payment authorization.
//!
//! This crate is the single, stable entry point for external consumers.
//! It is an **orchestration layer only**: every cryptographic operation
//! is delegated to the underlying [`crypto_core`], [`circuit`],
//! [`mpcith`], [`proof`], [`policy`], and [`payment`] crates. The SDK
//! adds no new cryptographic primitives, MPC protocols, or proof
//! systems — its job is to wire existing verified components into a
//! coherent, ergonomic, and well-typed authorization workflow.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod authorize;
pub mod backend;
pub mod config;
pub mod encoding;
pub mod error;
pub mod identity;
pub mod types;
pub mod verification;

pub use authorize::Sdk;
pub use backend::{backend_from_id, BackendType};
pub use config::SdkConfig;
pub use encoding::{deserialize, serialize, SUPPORTED_PROTOCOL_VERSIONS};
pub use error::SdkError;
pub use identity::{authorization_id, AuthorizationId};
pub use types::{Authorization, AUTHORIZATION_VERSION};
pub use verification::{VerificationFailure, VerificationResult};
