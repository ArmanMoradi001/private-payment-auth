//! Payment authorization orchestration.
//!
//! This crate composes proofs (`proof`) and authorization rules
//! (`policy`) into end-to-end payment authorization flows: statements
//! describe payments, the relation validates them in the clear, and
//! [`authorization`] produces and verifies zero-knowledge proofs that
//! the payer's private credentials satisfy the policy. It depends on
//! the abstract proof interface only — never directly on the
//! underlying MPC or MPC-in-the-Head layers.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod authorization;
pub mod error;
pub mod relation;
pub mod statement;
pub mod witness;
mod wiring;

pub use authorization::{authorize, verify_authorization, AUTHORIZATION_REPETITIONS};
pub use error::PaymentError;
pub use relation::{recompute_commitment, AuthorizationRelation};
pub use statement::{PaymentStatement, PAYMENT_ID_LEN, STATEMENT_VERSION};
pub use witness::{PrivateWitness, MAX_CREDENTIAL_SECRET_LEN};
