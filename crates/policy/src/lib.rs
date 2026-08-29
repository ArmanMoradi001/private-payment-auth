//! Payment policy definition, normalization, and compilation.
//!
//! This crate defines an authorization policy (spending limits,
//! multi-party approval rules) as a strongly typed, recursive AST and
//! deterministically compiles it into the arithmetic circuits proven by
//! the `proof` crate. `crypto-core` provides credential commitments and
//! `circuit` provides circuit construction.
//!
//! There is **no** text DSL, JSON policy format, or external policy
//! language (see `docs/decisions/0011-policy-ast-and-normalization.md`).
//! Policy semantics are fixed by this crate's typed AST and the
//! reference evaluator.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod ast;
pub mod compiler;
pub mod encoding;
pub mod error;
pub mod evaluator;
pub mod identity;
pub mod normalize;
pub mod range_check;
pub mod validation;
pub mod witness;

pub use ast::{
    credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK,
    CREDENTIAL_COMMITMENT_DOMAIN,
};
pub use compiler::{
    compile, compile_with_layout, CompilationMetadata, CompiledPolicy, PublicSlot, SecretSlot,
};
pub use encoding::{decode, encode, ENCODING_VERSION};
pub use error::PolicyError;
pub use evaluator::evaluate;
pub use identity::{policy_id, PolicyId, DOMAIN_POLICY};
pub use normalize::normalize;
pub use range_check::AMOUNT_BIT_LEN;
pub use validation::{
    validate, MAX_COMBINATOR_CHILDREN, MAX_CREDENTIAL_COUNT, MAX_ENCODED_SIZE, MAX_POLICY_DEPTH,
    MAX_POLICY_NODES, MAX_THRESHOLD_ARITY, MAX_THRESHOLD_MEMBERS,
};
pub use witness::{AuthorizationResult, NodeOutcome, PolicyWitness};
