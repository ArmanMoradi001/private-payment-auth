//! Core data types for additive secret sharing.
//!
//! Unlike the Shamir sharing in the `secret-sharing` crate, an MPC
//! computation distributes values *additively*: each party holds one
//! random field element and only the sum of all shares equals the
//! secret. The types here deliberately do not carry Shamir metadata
//! (thresholds or share indices).

use ark_ff::Zero;
use zeroize::Zeroize;

/// A plaintext field element that is known publicly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicValue<F>(F);

impl<F> PublicValue<F> {
    /// Wraps a raw field element as a public value.
    pub fn new(value: F) -> Self {
        Self(value)
    }

    /// Returns a reference to the underlying field element.
    pub fn value(&self) -> &F {
        &self.0
    }

    /// Consumes the value, returning the underlying field element.
    pub fn into_value(self) -> F {
        self.0
    }
}

/// One party's additive share of a secret field element.
///
/// The wrapped value must never be logged; `Debug` output is redacted.
#[derive(Clone, PartialEq, Eq)]
pub struct Share<F>(F);

impl<F> Share<F> {
    /// Wraps a raw field element as a share.
    pub fn new(value: F) -> Self {
        Self(value)
    }

    /// Returns a reference to the underlying field element.
    pub fn value(&self) -> &F {
        &self.0
    }

    /// Consumes the share, returning the underlying field element.
    pub fn into_value(self) -> F {
        self.0
    }
}

impl<F> core::fmt::Debug for Share<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Share([REDACTED])")
    }
}

/// A secret field element distributed additively across all parties.
///
/// The concatenation of every party's [`Share`] reconstructs the value;
/// any strict subset reveals nothing about it.
#[derive(Clone, PartialEq, Eq)]
pub struct SharedValue<F> {
    shares: Vec<Share<F>>,
}

impl<F> SharedValue<F> {
    /// Builds a shared value from one share per party, in party order.
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::MpcError::InvalidShare`] when the slice is
    /// empty; a distributed value requires at least one party.
    pub fn from_shares(shares: Vec<Share<F>>) -> Result<Self, crate::MpcError> {
        if shares.is_empty() {
            return Err(crate::MpcError::InvalidShare);
        }
        Ok(Self { shares })
    }

    /// Crate-internal constructor for validated share vectors.
    pub(crate) fn from_validated_shares(shares: Vec<Share<F>>) -> Self {
        debug_assert!(!shares.is_empty(), "shared values are never empty");
        Self { shares }
    }

    /// Returns the per-party shares in party order.
    pub fn shares(&self) -> &[Share<F>] {
        &self.shares
    }

    /// Consumes the shared value, returning its shares.
    pub fn into_shares(self) -> Vec<Share<F>> {
        self.shares
    }

    /// Returns the number of parties holding this value.
    pub fn len(&self) -> usize {
        self.shares.len()
    }

    /// Returns `true` when no party holds a share of this value.
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }
}

impl<F> core::fmt::Debug for SharedValue<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedValue([REDACTED])")
    }
}

impl<F: Clone + Zero> Zeroize for Share<F> {
    fn zeroize(&mut self) {
        self.0 = F::zero();
    }
}

impl<F: Clone + Zero> Zeroize for SharedValue<F> {
    fn zeroize(&mut self) {
        for share in &mut self.shares {
            share.zeroize();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed25519::Fr;
    use ark_ff::{One, Zero};

    #[test]
    fn debug_output_is_redacted() {
        let share = Share::new(Fr::from(42u64));
        assert_eq!(format!("{share:?}"), "Share([REDACTED])");

        let shared = SharedValue::from_shares(vec![Share::new(Fr::one()), Share::new(Fr::zero())])
            .expect("non-empty");
        assert_eq!(format!("{shared:?}"), "SharedValue([REDACTED])");
    }

    #[test]
    fn accessors_round_trip() {
        let value = Fr::from(7u64);
        let public = PublicValue::new(value);
        assert_eq!(*public.value(), value);
        assert_eq!(public.into_value(), value);

        let shared = SharedValue::from_shares(vec![Share::new(Fr::one()), Share::new(Fr::zero())])
            .expect("non-empty");
        assert_eq!(shared.len(), 2);
        assert!(!shared.is_empty());
        assert_eq!(shared.shares().len(), 2);
        assert_eq!(shared.into_shares().len(), 2);

        assert!(
            SharedValue::<Fr>::from_shares(Vec::new()).is_err(),
            "empty shared values are rejected"
        );
    }
}
