//! Secret sharing schemes for distributed key and input handling.
//!
//! This crate implements Shamir-style secret sharing and related
//! reconstruction logic, built on top of `crypto-core` primitives.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod encoding;
pub mod error;
pub mod field;
pub mod shamir;
pub mod share;

pub use error::SecretSharingError;
pub use field::FIELD_ELEMENT_SIZE;
pub use shamir::{reconstruct, split};
pub use share::Share;
