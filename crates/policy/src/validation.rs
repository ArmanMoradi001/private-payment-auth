//! Structural validation of [`Policy`] trees.
//!
//! Validation is independent of circuit compilation and enforces every
//! resource bound required to keep recursion, node counts, credential
//! counts, and arity finite. All limits are explicit `const`s — there
//! is no global mutable configuration.

use crate::ast::{Policy, CREDENTIAL_ID_LEN};
use crate::error::PolicyError;

/// Maximum nesting depth of a [`Policy`] tree.
pub const MAX_POLICY_DEPTH: usize = 100;
/// Maximum number of nodes in a [`Policy`] tree (leaves and combinators).
pub const MAX_POLICY_NODES: usize = 10_000;
/// Maximum threshold arity `k`.
pub const MAX_THRESHOLD_ARITY: usize = 1000;
/// Maximum number of distinct credential leaves in a [`Policy`] tree.
pub const MAX_CREDENTIAL_COUNT: usize = 1000;
/// Maximum number of children of a single combinator (`And`/`Or`).
pub const MAX_COMBINATOR_CHILDREN: usize = 1000;
/// Maximum number of members of a single `Threshold`.
pub const MAX_THRESHOLD_MEMBERS: usize = 1000;
/// Maximum byte length of a canonical encoding.
pub const MAX_ENCODED_SIZE: usize = 1_048_576;

/// Validates `policy` against all structural and resource rules.
///
/// # Errors
///
/// Returns the first [`PolicyError`] that applies; see the crate-level
/// resource limits for the precise bounds.
pub fn validate(policy: &Policy) -> Result<(), PolicyError> {
    let mut ctx = Context {
        depth: 0,
        nodes: 0,
        credentials: 0,
    };
    validate_impl(policy, &mut ctx)
}

struct Context {
    depth: usize,
    nodes: usize,
    credentials: usize,
}

fn validate_impl(policy: &Policy, ctx: &mut Context) -> Result<(), PolicyError> {
    if ctx.depth > MAX_POLICY_DEPTH {
        return Err(PolicyError::MaxDepthExceeded);
    }
    ctx.nodes += 1;
    if ctx.nodes > MAX_POLICY_NODES {
        return Err(PolicyError::MaxNodesExceeded);
    }

    match policy {
        Policy::AmountAtMost(_) => Ok(()),
        Policy::Credential(id) => {
            if id.is_zero() {
                return Err(PolicyError::InvalidCredentialId);
            }
            ctx.credentials += 1;
            if ctx.credentials > MAX_CREDENTIAL_COUNT {
                return Err(PolicyError::MaxCredentialsExceeded);
            }
            Ok(())
        }
        Policy::Threshold { k, members } => {
            let k = k.get() as usize;
            if k == 0 {
                return Err(PolicyError::InvalidThreshold);
            }
            if k > MAX_THRESHOLD_ARITY {
                return Err(PolicyError::MaxArityExceeded);
            }
            if members.is_empty() {
                return Err(PolicyError::EmptyPolicy);
            }
            if members.len() > MAX_THRESHOLD_MEMBERS {
                return Err(PolicyError::MaxCombinatorChildrenExceeded);
            }
            if k > members.len() {
                return Err(PolicyError::ThresholdExceedsCount);
            }
            check_distinct_credentials(members)?;
            for member in members {
                ctx.depth += 1;
                validate_impl(member, ctx)?;
                ctx.depth -= 1;
            }
            Ok(())
        }
        Policy::And(members) | Policy::Or(members) => {
            if members.is_empty() {
                return Err(PolicyError::EmptyPolicy);
            }
            if members.len() > MAX_COMBINATOR_CHILDREN {
                return Err(PolicyError::MaxCombinatorChildrenExceeded);
            }
            for member in members {
                ctx.depth += 1;
                validate_impl(member, ctx)?;
                ctx.depth -= 1;
            }
            Ok(())
        }
    }
}

/// Rejects duplicate credential ids *within the immediate* `Threshold`
/// member list. Duplicates would otherwise collapse under the boolean
/// semantics and are rejected as a policy-authoring mistake.
fn check_distinct_credentials(members: &[Policy]) -> Result<(), PolicyError> {
    // Only direct Credential leaves participate; nested credentials are
    // the policy author's responsibility and are not flattened here.
    let mut seen = Vec::with_capacity(members.len());
    for member in members {
        if let Policy::Credential(id) = member {
            if seen.contains(id) {
                return Err(PolicyError::DuplicateCredential);
            }
            seen.push(*id);
        }
    }
    Ok(())
}

/// A compile-time sanity check that credential ids fit the wire size.
pub const fn credential_id_len() -> usize {
    CREDENTIAL_ID_LEN
}
