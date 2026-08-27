//! Beaver triple generation and supply.
//!
//! Multiplication of two shared values consumes a fresh *Beaver
//! triple*: three shared values `[a], [b], [c]` with `c = a · b`,
//! where `a` and `b` are uniformly random. The [`TripleProvider`]
//! trait abstracts over how triples are produced; in this phase a
//! [`LocalTrustedTripleProvider`] simulates an honest dealer with a
//! CSPRNG. Later phases will replace it with distributed triple
//! generation without changing the arithmetic layer.

use ark_ff::PrimeField;
use rand_core::CryptoRngCore;
use std::collections::BTreeSet;
use zeroize::Zeroize;

use crate::context::ShareContext;
use crate::error::MpcError;
use crate::sharing::share_input;
use crate::types::SharedValue;

/// A shared multiplication triple `[a], [b], [c]` with `c = a · b`.
#[derive(Clone, PartialEq, Eq)]
pub struct BeaverTriple<F> {
    /// First random multiplicand, shared across all parties.
    pub a: SharedValue<F>,
    /// Second random multiplicand, shared across all parties.
    pub b: SharedValue<F>,
    /// Shared product of the masked values: `c = a · b`.
    pub c: SharedValue<F>,
}

impl<F> core::fmt::Debug for BeaverTriple<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("BeaverTriple([REDACTED])")
    }
}

impl<F: Clone + ark_ff::Zero> Zeroize for BeaverTriple<F> {
    fn zeroize(&mut self) {
        self.a.zeroize();
        self.b.zeroize();
        self.c.zeroize();
    }
}

/// Supplies fresh Beaver triples to the arithmetic layer.
pub trait TripleProvider<F> {
    /// Returns the next unconsumed triple.
    ///
    /// Implementations must never hand out the same triple twice; a
    /// reused triple breaks the privacy of every multiplication that
    /// used it.
    fn next_triple(&mut self) -> Result<BeaverTriple<F>, MpcError>;
}

/// Simulates a trusted dealer generating triples locally with a CSPRNG.
///
/// Suitable for simulation and testing only. Each issued triple is
/// tracked by a monotonically increasing identifier; identifiers are
/// recorded so a faulty provider state can never silently re-issue a
/// consumed triple ([`MpcError::TripleReuse`]).
pub struct LocalTrustedTripleProvider<R> {
    ctx: ShareContext,
    rng: R,
    next_id: u64,
    issued_ids: BTreeSet<u64>,
}

impl<R: CryptoRngCore> LocalTrustedTripleProvider<R> {
    /// Creates a provider distributing shares across `ctx.party_count`
    /// parties and drawing randomness from `rng`.
    ///
    /// # Errors
    ///
    /// Propagates [`MpcError`] from [`ShareContext::new`].
    pub fn new(ctx: ShareContext, rng: R) -> Result<Self, MpcError> {
        if ctx.party_count <= 1 {
            return Err(MpcError::InvalidPartyCount);
        }
        Ok(Self {
            ctx,
            rng,
            next_id: 0,
            issued_ids: BTreeSet::new(),
        })
    }

    /// Number of triples handed out so far.
    pub fn triples_issued(&self) -> u64 {
        self.next_id
    }

    /// Returns the context this provider shares into.
    pub fn context(&self) -> &ShareContext {
        &self.ctx
    }

    fn issue_id(&mut self) -> Result<u64, MpcError> {
        let id = self
            .next_id
            .checked_add(1)
            .ok_or(MpcError::TripleExhaustion)?;
        if !self.issued_ids.insert(id - 1) {
            return Err(MpcError::TripleReuse);
        }
        self.next_id = id;
        Ok(id - 1)
    }
}

impl<F: PrimeField, R: CryptoRngCore> TripleProvider<F> for LocalTrustedTripleProvider<R> {
    fn next_triple(&mut self) -> Result<BeaverTriple<F>, MpcError> {
        let _id = self.issue_id()?;

        let a_value = F::rand(&mut self.rng);
        let b_value = F::rand(&mut self.rng);
        let c_value = a_value * b_value;

        Ok(BeaverTriple {
            a: shared_from(&self.ctx, &a_value, &mut self.rng)?,
            b: shared_from(&self.ctx, &b_value, &mut self.rng)?,
            c: shared_from(&self.ctx, &c_value, &mut self.rng)?,
        })
    }
}

/// Additively shares a single value across the context's parties.
fn shared_from<F: PrimeField, R: CryptoRngCore>(
    ctx: &ShareContext,
    value: &F,
    rng: &mut R,
) -> Result<SharedValue<F>, MpcError> {
    let shares = share_input(ctx, value, rng)?;
    SharedValue::from_shares(shares).map_err(|_| MpcError::InvalidShare)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed25519::Fr;
    use ark_ff::Zero;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn triples_satisfy_c_equals_a_times_b() {
        let ctx = ShareContext::new(3, 1, 0).expect("valid");
        let mut provider =
            LocalTrustedTripleProvider::new(ctx, ChaCha20Rng::seed_from_u64(11)).expect("valid");

        for _ in 0..8 {
            let t = provider.next_triple().expect("valid");
            assert_eq!(t.a.len(), 3);
            let a = t.a.shares().iter().fold(Fr::zero(), |s, x| s + x.value());
            let b = t.b.shares().iter().fold(Fr::zero(), |s, x| s + x.value());
            let c = t.c.shares().iter().fold(Fr::zero(), |s, x| s + x.value());
            assert_eq!(c, a * b);
        }
        assert_eq!(provider.triples_issued(), 8);
    }

    #[test]
    fn debug_output_is_redacted() {
        let ctx = ShareContext::new(2, 1, 0).expect("valid");
        let mut provider =
            LocalTrustedTripleProvider::new(ctx, ChaCha20Rng::seed_from_u64(2)).expect("valid");
        let t: BeaverTriple<Fr> = provider.next_triple().expect("valid");
        assert_eq!(format!("{t:?}"), "BeaverTriple([REDACTED])");
    }

    #[test]
    fn singleton_context_is_rejected() {
        let ctx = ShareContext {
            party_count: 1,
            execution_id: 0,
            domain: 0,
        };
        assert!(matches!(
            LocalTrustedTripleProvider::<ChaCha20Rng>::new(ctx, ChaCha20Rng::seed_from_u64(1)),
            Err(MpcError::InvalidPartyCount)
        ));
    }

    #[test]
    fn consecutive_triples_are_independent() {
        // Guards the phase-3 rule: mpc shares are plain field elements
        // (additive), not secret-sharing Shamir shares; and successive
        // triples must be fresh randomness, never reused.
        let ctx = ShareContext::new(2, 4, 9).expect("valid");
        let mut provider =
            LocalTrustedTripleProvider::new(ctx, ChaCha20Rng::seed_from_u64(6)).expect("valid");

        let t1: BeaverTriple<Fr> = provider.next_triple().expect("valid");
        let t2: BeaverTriple<Fr> = provider.next_triple().expect("valid");
        assert_ne!(t1.a.shares()[0].value(), t2.a.shares()[0].value());
        assert_ne!(t1.c.shares(), t2.c.shares());
    }
}
