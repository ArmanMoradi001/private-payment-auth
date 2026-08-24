//! MPC-in-the-Head for the payment authorization circuit layer.
//!
//! This crate turns a 3-party simulated MPC execution of a [`circuit`]
//! into a proof of correct evaluation. The model is deliberately fixed:
//! exactly **three** virtual parties per repetition (this is *not* the
//! n-party `mpc` simulator). For each repetition the prover commits to
//! all three party views, receives a challenge naming one hidden
//! party, and opens the other two. A cheating view is caught whenever
//! it is opened, giving soundness error `(1/3)^repetitions` once the
//! Fiat–Shamir transform is applied.
//!
//! Status: interactive challenge source only — Fiat–Shamir is
//! intentionally deferred (see ADR 0006).
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod commitment;
pub mod encoding;
pub mod error;
pub mod prover;
pub mod types;
pub mod view;

pub use commitment::{commit_view, verify_commitment, ViewCommitment};
pub use encoding::{decode_proof, decode_view, encode_proof, encode_view, ENCODING_VERSION};
pub use error::MpcithError;
pub use prover::{MpcithProof, OpenedView, Repetition};
pub use types::{Challenge, FieldElement, PartyId, RepetitionId, PARTY_COUNT};
pub use view::{LocalOperation, PartyView, TripleShare};
