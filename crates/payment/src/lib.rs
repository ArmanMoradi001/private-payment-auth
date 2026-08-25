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

pub mod amount;
pub mod authorization;
pub mod error;
pub mod payment;
pub mod range_check;
pub mod relation;
pub mod statement;
mod wiring;
pub mod witness;

pub use amount::{Amount, AmountError, AmountUnit};
pub use authorization::{authorize, verify_authorization, AUTHORIZATION_REPETITIONS};
pub use error::PaymentError;
pub use payment::{Payment, NONCE_LEN as PAYMENT_NONCE_LEN, PAYMENT_ID_DOMAIN, PAYMENT_ID_LEN};
pub use proof::PROTOCOL_VERSION;
pub use range_check::{circuit_range_check_outputs, decompose, reference_range_check};
pub use relation::{recompute_commitment, AuthorizationRelation};
pub use statement::{
    PaymentStatement, StatementError, NONCE_LEN as STATEMENT_NONCE_LEN, STATEMENT_VERSION,
};
pub use witness::{PrivateWitness, MAX_CREDENTIAL_SECRET_LEN};
