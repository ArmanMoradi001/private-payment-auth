//! Non-interactive Fiat–Shamir proofs over MPC-in-the-Head.
//!
//! This crate wraps the interactive [`mpcith`] protocol into a
//! non-interactive proof: challenges are derived from the committed
//! statement and view commitments via SHA-256 (Fiat–Shamir), so the
//! prover cannot adapt after committing. The crate *consumes* mpcith —
//! it never re-implements MPC or verification semantics.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod encoding;
pub mod error;
pub mod fiat_shamir;
pub mod proof;
pub mod prover;
pub mod statement;
pub mod verifier;

/// Protocol version stamped into every proof and FS derivation.
pub const PROTOCOL_VERSION: u8 = 1;

pub use encoding::{deserialize_proof, serialize_proof, ENCODING_VERSION, PROTOCOL_ID};
pub use error::ProofError;
pub use fiat_shamir::{ChallengeGenerator, FiatShamirChallengeGenerator, FsSession, FS_DOMAIN};
pub use proof::{NonInteractiveProof, ProofId, ProofRepetition, PROOF_ID_DOMAIN};
pub use prover::Prover;
pub use statement::Statement;
pub use verifier::{VerificationResult, Verifier};
