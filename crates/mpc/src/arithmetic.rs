//! Arithmetic on additively shared values.
//!
//! Additions and public-scalar operations are purely local: each party
//! transforms its own share independently. Multiplication of two shared
//! values requires interaction, simulated here through a fresh Beaver
//! triple from a [`crate::TripleProvider`]:
//!
//! ```text
//! [d] = [x] - [a],  [e] = [y] - [b]        (local)
//! d = Σ[d], e = Σ[e]                       (reconstruction / opening)
//! [z] = [c] + d·[b] + e·[a] + d·e          (local; d·e to party 0's share)
//! ```
//!
//! Since `d = x - a` and `e = y - b`, the sum over parties equals
//! `(a + d)(b + e) = x · y` while the opened masks `d`, `e` are
//! statistically independent of `x` and `y`.

use ark_ff::PrimeField;

use crate::error::MpcError;
use crate::triples::TripleProvider;
use crate::types::{PublicValue, Share, SharedValue};

impl<F: PrimeField> SharedValue<F> {
    /// Adds a public value by adjusting the first party's share.
    ///
    /// Only one share changes, so the sum of all shares increases by
    /// exactly the public value.
    pub fn add_public(&self, public: &PublicValue<F>) -> SharedValue<F> {
        let mut shares = self.shares().to_vec();
        let delta = *public.value();
        if let Some(first) = shares.first_mut() {
            *first = Share::new(*first.value() + delta);
        }
        // `self` came from `SharedValue::from_shares`, so it is non-empty.
        SharedValue::from_validated_shares(shares)
    }

    /// Adds another shared value of the same context, party-wise.
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::ContextMismatch`] when the two values are
    /// held by different numbers of parties.
    pub fn add_secret(&self, other: &SharedValue<F>) -> Result<SharedValue<F>, MpcError> {
        if self.len() != other.len() {
            return Err(MpcError::ContextMismatch);
        }
        let shares = self
            .shares()
            .iter()
            .zip(other.shares())
            .map(|(x, y)| Share::new(*x.value() + y.value()))
            .collect();
        Ok(SharedValue::from_validated_shares(shares))
    }

    /// Multiplies every share by a public scalar.
    ///
    /// Because the scalar distributes over addition, reconstructing the
    /// result yields `public · secret`.
    #[must_use]
    pub fn mul_public(&self, public: &PublicValue<F>) -> SharedValue<F> {
        let scale = *public.value();
        let shares = self
            .shares()
            .iter()
            .map(|s| Share::new(*s.value() * scale))
            .collect();
        SharedValue::from_validated_shares(shares)
    }

    /// Multiplies this value by another shared value using a fresh
    /// Beaver triple.
    ///
    /// The masked differences `d = x - a` and `e = y - b` are
    /// reconstructed (simulated locally), then each party combines its
    /// shares of `[c]`, `[a]`, `[b]` with the public `d`, `e`. The
    /// constant term `d·e` is added to the first party's share.
    ///
    /// # Errors
    ///
    /// - [`MpcError::ContextMismatch`] if operands or triple shares
    ///   disagree on the number of parties.
    /// - Any error propagated from [`TripleProvider::next_triple`]
    ///   (e.g. [`MpcError::TripleExhaustion`]).
    #[allow(clippy::similar_names)]
    pub fn mul_secret(
        &self,
        other: &SharedValue<F>,
        provider: &mut dyn TripleProvider<F>,
    ) -> Result<SharedValue<F>, MpcError> {
        if self.len() != other.len() {
            return Err(MpcError::ContextMismatch);
        }

        let triple = provider.next_triple()?;
        let (a, b, c) = (triple.a, triple.b, triple.c);
        if a.len() != self.len() || b.len() != self.len() || c.len() != self.len() {
            return Err(MpcError::ContextMismatch);
        }

        // Open the masked values d = x - a and e = y - b.
        let d_shares: Vec<Share<F>> = self
            .shares()
            .iter()
            .zip(a.shares())
            .map(|(x, ai)| Share::new(*x.value() - ai.value()))
            .collect();
        let e_shares: Vec<Share<F>> = other
            .shares()
            .iter()
            .zip(b.shares())
            .map(|(y, bi)| Share::new(*y.value() - bi.value()))
            .collect();
        let d = sum(&d_shares);
        let e = sum(&e_shares);

        // [z] = [c] + d·[b] + e·[a]; the public d·e lands with party 0.
        let shares = c
            .shares()
            .iter()
            .enumerate()
            .zip(b.shares().iter().zip(a.shares()))
            .map(|((i, ci), (bi, ai))| {
                let mut z = *ci.value() + d * bi.value() + e * ai.value();
                if i == 0 {
                    z += d * e;
                }
                Share::new(z)
            })
            .collect();

        Ok(SharedValue::from_validated_shares(shares))
    }
}

/// Sums raw field elements across shares.
fn sum<F: PrimeField>(shares: &[Share<F>]) -> F {
    shares.iter().fold(F::zero(), |acc, s| acc + s.value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::ShareContext;
    use crate::sharing::{reconstruct, share_input};
    use crate::triples::LocalTrustedTripleProvider;
    use ark_ed25519::Fr;
    use ark_ff::{One, Zero};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn setup(party_count: usize) -> (ShareContext, LocalTrustedTripleProvider<ChaCha20Rng>) {
        let ctx = ShareContext::new(party_count, 1, 0).expect("valid");
        let provider =
            LocalTrustedTripleProvider::new(ctx, ChaCha20Rng::seed_from_u64(2024)).expect("valid");
        (ctx, provider)
    }

    fn shared<R: rand_core::RngCore + rand_core::CryptoRng>(
        ctx: &ShareContext,
        v: Fr,
        rng: &mut R,
    ) -> SharedValue<Fr> {
        SharedValue::from_shares(share_input(ctx, &v, rng).expect("valid")).expect("non-empty")
    }

    #[test]
    fn add_public_and_mul_public_reconstruct_correctly() {
        let (ctx, _provider) = setup(3);
        let mut rng = ChaCha20Rng::seed_from_u64(1);

        let x = shared(&ctx, Fr::from(10u64), &mut rng);
        let five = PublicValue::new(Fr::from(5u64));

        assert_eq!(
            reconstruct(&ctx, x.add_public(&five).shares()).expect("valid"),
            Fr::from(15u64)
        );
        assert_eq!(
            reconstruct(&ctx, x.mul_public(&five).shares()).expect("valid"),
            Fr::from(50u64)
        );
    }

    #[test]
    fn add_secret_is_local_and_exact() {
        let (ctx, _provider) = setup(4);
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        let x = shared(&ctx, Fr::from(30u64), &mut rng);
        let y = shared(&ctx, Fr::from(12u64), &mut rng);

        let sum = x.add_secret(&y).expect("same context");
        assert_eq!(
            reconstruct(&ctx, sum.shares()).expect("valid"),
            Fr::from(42u64)
        );
    }

    #[test]
    fn mul_secret_matches_plaintext_product() {
        for seed in 0..5u64 {
            let (ctx, mut provider) = setup(3);
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let x = shared(&ctx, Fr::from(17u64 + seed), &mut rng);
            let y = shared(&ctx, Fr::from(23u64 + 2 * seed), &mut rng);

            let z = x.mul_secret(&y, &mut provider).expect("valid");
            let expected = Fr::from(17u64 + seed) * Fr::from(23u64 + 2 * seed);
            assert_eq!(reconstruct(&ctx, z.shares()).expect("valid"), expected);
        }
    }

    #[test]
    fn mul_with_one_and_zero_is_identity_and_absorbing() {
        let (ctx, mut provider) = setup(5);
        let mut rng = ChaCha20Rng::seed_from_u64(8);
        let x = shared(&ctx, Fr::from(9u64), &mut rng);
        let one = shared(&ctx, Fr::one(), &mut rng);
        let zero = shared(&ctx, Fr::zero(), &mut rng);

        let times_one = x.mul_secret(&one, &mut provider).expect("valid");
        assert_eq!(
            reconstruct(&ctx, times_one.shares()).expect("valid"),
            Fr::from(9u64)
        );

        let times_zero = x.mul_secret(&zero, &mut provider).expect("valid");
        assert_eq!(
            reconstruct(&ctx, times_zero.shares()).expect("valid"),
            Fr::zero()
        );
    }

    #[test]
    fn mixed_party_counts_are_rejected() {
        let (ctx_a, mut provider) = setup(3);
        let ctx_b = ShareContext::new(2, 1, 0).expect("valid");
        let mut rng = ChaCha20Rng::seed_from_u64(4);

        let three_party = shared(&ctx_a, Fr::from(3u64), &mut rng);
        let two_party = shared(&ctx_b, Fr::from(4u64), &mut rng);

        assert_eq!(
            three_party.add_secret(&two_party).map(|_| ()).unwrap_err(),
            MpcError::ContextMismatch
        );
        assert_eq!(
            three_party
                .mul_secret(&two_party, &mut provider)
                .map(|_| ())
                .unwrap_err(),
            MpcError::ContextMismatch
        );
    }
}
