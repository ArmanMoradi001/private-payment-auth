//! Standalone verification of authorized payments.
//!
//! This crate will independently verify payment authorization artifacts:
//! checking proofs via the `proof` interface and validating compliance
//! with `policy`, using only `crypto-core` primitives.
#![forbid(unsafe_code)]
#![warn(missing_docs)]
