//! Sharing context binding shares to a protocol execution.
//!
//! Every shared value is created within a context that names the
//! execution it belongs to. Contexts are compared structurally: mixing
//! values from different contexts or party counts is an error
//! ([`crate::MpcError::ContextMismatch`]).

/// Identifies a set of parties participating in one MPC execution.
///
/// `execution_id` and `domain` exist to domain-separate future
/// transcript/proof usage (MPCitH); they are carried with every
/// sharing operation so artifacts can never be replayed across
/// executions or application domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareContext {
    /// Number of parties holding additive shares.
    pub party_count: usize,
    /// Identifier of the protocol execution this context belongs to.
    pub execution_id: u64,
    /// Application domain tag separating distinct protocol usages.
    pub domain: u8,
}

impl ShareContext {
    /// Creates a new context.
    ///
    /// # Errors
    ///
    /// Returns [`crate::MpcError::InvalidPartyCount`] when
    /// `party_count <= 1`; an MPC execution requires at least two
    /// parties for the sharing to hide anything.
    pub fn new(party_count: usize, execution_id: u64, domain: u8) -> Result<Self, crate::MpcError> {
        if party_count <= 1 {
            return Err(crate::MpcError::InvalidPartyCount);
        }
        Ok(Self {
            party_count,
            execution_id,
            domain,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_contexts_are_accepted() {
        let ctx = ShareContext::new(3, 1, 0).expect("valid");
        assert_eq!(ctx.party_count, 3);
        assert_eq!(ctx.execution_id, 1);
        assert_eq!(ctx.domain, 0);
    }

    #[test]
    fn singleton_or_empty_party_sets_are_rejected() {
        assert_eq!(
            ShareContext::new(1, 1, 0),
            Err(crate::MpcError::InvalidPartyCount)
        );
        assert_eq!(
            ShareContext::new(0, 1, 0),
            Err(crate::MpcError::InvalidPartyCount)
        );
    }
}
