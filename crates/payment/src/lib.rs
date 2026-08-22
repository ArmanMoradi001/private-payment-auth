//! Payment authorization orchestration.
//!
//! This crate will compose proofs (`proof`) and authorization rules
//! (`policy`) into end-to-end payment authorization flows. It depends on
//! the abstract proof interface only — never directly on the underlying
//! MPC or MPC-in-the-Head layers.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
