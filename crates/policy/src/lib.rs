//! Payment policy definition and evaluation.
//!
//! This crate will define authorization policies (spending limits,
//! multi-party approval rules, time locks) and evaluate them against
//! payment requests, using `crypto-core` for policy commitments.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
