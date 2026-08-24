//! Multi-party computation protocols for payment authorization.
//!
//! This crate implements the MPC protocol layer, coordinating
//! distributed computation over additively shared secrets using the
//! prime-field primitives of `ark-ff` and the foundations provided by
//! `crypto-core` and `secret-sharing`.
//!
//! Sharing in this crate is *additive*: each party holds one random
//! field element and only the sum of all shares equals the secret.
//! The Shamir sharing in `secret-sharing` is not reused here; see
//! [`types`] for the additive share types.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod arithmetic;
pub mod context;
pub mod error;
pub mod sharing;
pub mod simulator;
pub mod triples;
pub mod types;

pub use context::ShareContext;
pub use error::MpcError;
pub use sharing::{reconstruct, share_input};
pub use simulator::{MpcSimulator, TranscriptHook};
pub use triples::{BeaverTriple, LocalTrustedTripleProvider, TripleProvider};
pub use types::{PublicValue, Share, SharedValue};
