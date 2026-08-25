//! Payment policy definition and compilation.
//!
//! This crate defines authorization policies (spending limits,
//! multi-party approval rules) and deterministically compiles them into
//! the arithmetic circuits proven by the `proof` crate, using
//! `crypto-core` for credential commitments and `circuit` for circuit
//! construction.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod compiler;
pub mod error;
pub mod policy;

pub use compiler::{
    compile, compile_with_layout, CompiledPolicy, PublicSlot, SecretSlot, AMOUNT_BOUND,
};
pub use error::PolicyError;
pub use policy::{
    credential_commitment, CredentialPolicy, Policy, PolicyId, CREDENTIAL_COMMITMENT_DOMAIN,
    POLICY_ID_DOMAIN,
};
