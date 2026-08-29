//! Reference evaluator for [`Policy`] trees.
//!
//! This is the **semantic ground truth**. It evaluates a policy against
//! a [`PolicyWitness`] in the clear, independent of any circuit. The
//! circuit compiler (see `compiler`) must agree with this evaluator for
//! every valid input.
//!
//! Credential commitment semantics are identical to those used by the
//! circuit: `SHA-256(secret) == CredentialId` under the credential
//! domain. The hash is computed through [`crate::ast::credential_commitment`]
//! — the evaluator never re-implements hashing.

use crate::ast::{credential_commitment, Policy};
use crate::error::PolicyError;
use crate::witness::{AuthorizationResult, NodeOutcome, PolicyWitness};

/// Evaluates `policy` against `witness`.
///
/// Missing credential secrets or a missing amount make the corresponding
/// leaf unsatisfiable rather than erroring, so the result always reflects
/// a concrete authorization decision.
///
/// # Errors
///
/// Returns [`PolicyError::WitnessMismatch`] only when the witness fails
/// the structural `validate_against` check; evaluation itself is total.
pub fn evaluate(
    policy: &Policy,
    witness: &PolicyWitness,
) -> Result<AuthorizationResult, PolicyError> {
    witness.validate_against(policy)?;
    let root = eval_node(policy, witness);
    let authorized = match &root {
        NodeOutcome::And { satisfied, .. }
        | NodeOutcome::Or { satisfied, .. }
        | NodeOutcome::Threshold { satisfied, .. }
        | NodeOutcome::Amount { satisfied, .. }
        | NodeOutcome::Credential { satisfied, .. } => *satisfied,
    };
    Ok(AuthorizationResult { authorized, root })
}

fn eval_node(policy: &Policy, witness: &PolicyWitness) -> NodeOutcome {
    match policy {
        Policy::AmountAtMost(limit) => {
            let satisfied = match witness.amount {
                Some(amount) => amount.value() <= limit.value(),
                None => false,
            };
            NodeOutcome::Amount {
                limit: *limit,
                satisfied,
            }
        }
        Policy::Credential(id) => {
            let satisfied = match witness.secret_for(id) {
                Some(secret) => {
                    let commitment = credential_commitment(secret);
                    commitment.as_bytes() == id.as_bytes()
                }
                None => false,
            };
            NodeOutcome::Credential { id: *id, satisfied }
        }
        Policy::Threshold { k, members } => {
            let mut outcomes = Vec::with_capacity(members.len());
            let mut satisfied_count = 0usize;
            for member in members {
                let outcome = eval_node(member, witness);
                if is_satisfied(&outcome) {
                    satisfied_count += 1;
                }
                outcomes.push(outcome);
            }
            let satisfied = satisfied_count >= k.get() as usize;
            NodeOutcome::Threshold {
                k: *k,
                satisfied,
                members: outcomes,
            }
        }
        Policy::And(members) => {
            let mut outcomes = Vec::with_capacity(members.len());
            let mut satisfied = true;
            for member in members {
                let outcome = eval_node(member, witness);
                if !is_satisfied(&outcome) {
                    satisfied = false;
                }
                outcomes.push(outcome);
            }
            NodeOutcome::And {
                satisfied,
                members: outcomes,
            }
        }
        Policy::Or(members) => {
            let mut outcomes = Vec::with_capacity(members.len());
            let mut satisfied = false;
            for member in members {
                let outcome = eval_node(member, witness);
                if is_satisfied(&outcome) {
                    satisfied = true;
                }
                outcomes.push(outcome);
            }
            NodeOutcome::Or {
                satisfied,
                members: outcomes,
            }
        }
    }
}

fn is_satisfied(outcome: &NodeOutcome) -> bool {
    match outcome {
        NodeOutcome::And { satisfied, .. }
        | NodeOutcome::Or { satisfied, .. }
        | NodeOutcome::Threshold { satisfied, .. }
        | NodeOutcome::Amount { satisfied, .. }
        | NodeOutcome::Credential { satisfied, .. } => *satisfied,
    }
}
