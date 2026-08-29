//! Canonical normalization of [`Policy`] trees.
//!
//! Normalization rewrites a policy into a unique canonical form that
//! preserves semantics exactly. Two policies with the same
//! normalization are semantically equivalent, which is what makes
//! [`crate::identity::policy_id`] a stable identifier of policy
//! semantics.
//!
//! Rules (all semantics-preserving):
//!
//! 1. **Flatten nested same-type combinators.** `And([A, And([B, C])])`
//!    becomes `And([A, B, C])`; `Or` likewise.
//! 2. **Remove redundant singleton combinators.** `And([A])` becomes
//!    `A`; `Or([A])` becomes `A`. (A `Threshold` retains its members.)
//! 3. **Canonical child ordering** for commutative operators. `And` and
//!    `Or` children are sorted by their canonical encoding (byte-level
//!    lexicographic order); `Threshold` members are sorted the same way
//!    because member order has no semantic meaning.
//! 4. **Threshold members are NOT de-duplicated** — duplicates can
//!    change threshold semantics (a `k`-of-`n` where a member appears
//!    twice is genuinely different).
//! 5. **`And`/`Or` children ARE de-duplicated** — `And([A, A])` equals
//!    `And([A])` semantically.
//!
//! The transform is idempotent: `normalize(normalize(p)) == normalize(p)`.

use crate::ast::Policy;
use crate::error::PolicyError;

/// Returns the canonical (normalized) form of `policy`.
///
/// # Errors
///
/// Returns [`PolicyError::MalformedEncoding`] only if encoding during
/// sorting fails, which cannot happen for an in-memory policy; the
/// `Result` is retained for a uniform API.
pub fn normalize(policy: &Policy) -> Result<Policy, PolicyError> {
    normalize_node(policy)
}

fn normalize_node(policy: &Policy) -> Result<Policy, PolicyError> {
    match policy {
        Policy::AmountAtMost(_) | Policy::Credential(_) => Ok(policy.clone()),
        Policy::Threshold { k, members } => {
            let mut normalized = Vec::with_capacity(members.len());
            for member in members {
                normalized.push(normalize_node(member)?);
            }
            // Member order is irrelevant to `k`-of-`n` semantics; sort
            // by canonical encoding for a unique form.
            normalized.sort_by_cached_key(Policy::encode);
            Ok(Policy::Threshold {
                k: *k,
                members: normalized,
            })
        }
        Policy::And(members) => Ok(normalize_combinator(Policy::make_and, 4, members)),
        Policy::Or(members) => Ok(normalize_combinator(Policy::make_or, 5, members)),
    }
}

/// Normalizes a commutative combinator: recursively normalize children,
/// flatten nested same-type combinators, de-duplicate, sort by
/// canonical encoding, and collapse singletons.
fn normalize_combinator(
    make: impl Fn(Vec<Policy>) -> Policy,
    parent_tag: u8,
    members: &[Policy],
) -> Policy {
    let mut flat: Vec<Policy> = Vec::with_capacity(members.len());
    for member in members {
        let normalized = normalize_node(member).expect("normalize cannot fail");
        flatten_into(parent_tag, &normalized, &mut flat);
    }

    // De-duplicate by canonical encoding (semantics-preserving).
    let mut unique: Vec<Policy> = Vec::with_capacity(flat.len());
    for policy in flat {
        let encoding = policy.encode();
        if !unique.iter().any(|u| u.encode() == encoding) {
            unique.push(policy);
        }
    }

    // Sort by canonical encoding for a stable order.
    unique.sort_by_cached_key(Policy::encode);

    // Collapse singleton combinators to their single member.
    if unique.len() == 1 {
        return unique.into_iter().next().expect("just checked len == 1");
    }
    make(unique)
}

/// Splices `policy` into `out` only when it is the *same* combinator
/// variant as the parent (identified by `tag`): `And` into `And`, `Or`
/// into `Or`. Cross-type nesting (`Or([And(..)])`, `And([Or(..)])`) must
/// NOT be flattened — doing so would change semantics, since
/// `Or([And(a, b)])` is not equivalent to `Or(a, b)`.
fn flatten_into(tag: u8, policy: &Policy, out: &mut Vec<Policy>) {
    match policy {
        Policy::And(inner) if tag == 4 => out.extend(inner.iter().cloned()),
        Policy::Or(inner) if tag == 5 => out.extend(inner.iter().cloned()),
        _ => out.push(policy.clone()),
    }
}

impl Policy {
    /// Builds an `And` node (kept private to this module's combinator
    /// helper to avoid leaking the constructor).
    fn make_and(members: Vec<Policy>) -> Policy {
        Policy::And(members)
    }

    /// Builds an `Or` node.
    fn make_or(members: Vec<Policy>) -> Policy {
        Policy::Or(members)
    }
}
