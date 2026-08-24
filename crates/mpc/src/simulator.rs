//! Local MPC simulator and the high-level execution API.
//!
//! [`MpcSimulator`] drives a complete simulated MPC execution in a
//! single process: inputs are additively shared across the configured
//! parties, arithmetic runs through the shared-value API with triples
//! from an injectable [`crate::TripleProvider`], and values are
//! revealed by reconstruction. This is the reference execution model
//! that the future distributed protocol must reproduce.
//!
//! [`TranscriptHook`] is a placeholder seam for MPCitH integration:
//! once the proof layer lands, every operation and reveal recorded
//! here becomes part of the Fiat–Shamir transcript.

use ark_ff::PrimeField;
use rand_core::CryptoRngCore;

use crate::context::ShareContext;
use crate::error::MpcError;
use crate::sharing::{reconstruct, share_input};
use crate::triples::TripleProvider;
use crate::types::{PublicValue, SharedValue};

/// High-level driver for a locally simulated MPC execution.
pub struct MpcSimulator<F, R> {
    ctx: ShareContext,
    provider: Box<dyn TripleProvider<F>>,
    rng: R,
}

impl<F: PrimeField, R: CryptoRngCore> MpcSimulator<F, R> {
    /// Creates a simulator for `ctx` sourcing multiplication masks from
    /// `provider` and sharing randomness from `rng`.
    ///
    /// # Errors
    ///
    /// Returns [`MpcError::InvalidPartyCount`] when `ctx.party_count`
    /// is not greater than one.
    pub fn new(
        ctx: ShareContext,
        provider: Box<dyn TripleProvider<F>>,
        rng: R,
    ) -> Result<Self, MpcError> {
        if ctx.party_count <= 1 {
            return Err(MpcError::InvalidPartyCount);
        }
        Ok(Self { ctx, provider, rng })
    }

    /// The context (party count, execution id, domain) of this run.
    pub fn context(&self) -> &ShareContext {
        &self.ctx
    }

    /// Secretly shares `secret` across all parties.
    ///
    /// # Errors
    /// Propagates errors from [`share_input`].
    pub fn input(&mut self, secret: F) -> Result<SharedValue<F>, MpcError> {
        let shares = share_input(&self.ctx, &secret, &mut self.rng)?;
        SharedValue::from_shares(shares).map_err(|_| MpcError::InvalidShare)
    }

    /// Reconstructs and publishes the plaintext behind `shared`.
    ///
    /// # Errors
    ///
    /// - Propagates errors from [`reconstruct`].
    /// - Returns [`MpcError::RevealMisuse`] when `shared` was not
    ///   produced for this simulator's context shape.
    pub fn reveal(&self, shared: &SharedValue<F>) -> Result<F, MpcError> {
        if shared.len() != self.ctx.party_count {
            return Err(MpcError::RevealMisuse);
        }
        reconstruct(&self.ctx, shared.shares())
    }

    /// Adds two shared values without interaction.
    ///
    /// # Errors
    /// Propagates errors from [`SharedValue::add_secret`].
    pub fn add(&self, x: &SharedValue<F>, y: &SharedValue<F>) -> Result<SharedValue<F>, MpcError> {
        let sum = x.add_secret(y)?;
        Ok(sum)
    }

    /// Multiplies two shared values, consuming one Beaver triple.
    ///
    /// # Errors
    /// Propagates errors from [`SharedValue::mul_secret`].
    pub fn mul(
        &mut self,
        x: &SharedValue<F>,
        y: &SharedValue<F>,
    ) -> Result<SharedValue<F>, MpcError> {
        // The provider trait object borrows mutably for this call only;
        // the triple is consumed immediately.
        let provider = self.provider.as_mut();
        x.mul_secret(y, provider)
    }

    /// Convenience wrapper exposing [`PublicValue`] construction.
    pub fn public(&self, value: F) -> PublicValue<F> {
        PublicValue::new(value)
    }
}

/// Placeholder transcript recorder for future MPCitH integration.
///
/// Methods are intentionally empty in Phase 3: they define *where*
/// transcript events will be emitted so the simulator's call sites do
/// not need to change once the proof layer exists. The hook must never
/// record share values — only operation kinds and public openings.
#[derive(Debug, Default, Clone)]
pub struct TranscriptHook {
    recorded_events: usize,
}

impl TranscriptHook {
    /// Creates an empty transcript hook.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a protocol operation (to be wired into the transcript).
    pub fn record_operation(&mut self) {
        // Phase 3 stub: no transcript is produced yet.
        self.recorded_events += 1;
    }

    /// Records a reveal event (to be wired into the transcript).
    pub fn record_reveal(&mut self) {
        // Phase 3 stub: no transcript is produced yet.
        self.recorded_events += 1;
    }

    /// Number of events observed so far.
    pub fn recorded_count(&self) -> usize {
        self.recorded_events
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::triples::LocalTrustedTripleProvider;
    use ark_ed25519::Fr;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn end_to_end_simulation_matches_plaintext() {
        let ctx = ShareContext::new(4, 777, 3).expect("valid");
        let provider =
            LocalTrustedTripleProvider::new(ctx, ChaCha20Rng::seed_from_u64(55)).expect("valid");
        let mut sim =
            MpcSimulator::<Fr, _>::new(ctx, Box::new(provider), ChaCha20Rng::seed_from_u64(66))
                .expect("valid");

        let x = sim.input(Fr::from(100u64)).expect("valid");
        let y = sim.input(Fr::from(20u64)).expect("valid");
        let five = sim.public(Fr::from(5u64));

        let sum = sim.add(&x, &y).expect("same context");
        let scaled = x.mul_public(&five);
        let product = sim.mul(&x, &y).expect("valid");

        assert_eq!(sim.reveal(&sum).expect("valid"), Fr::from(120u64));
        assert_eq!(sim.reveal(&scaled).expect("valid"), Fr::from(500u64));
        assert_eq!(sim.reveal(&product).expect("valid"), Fr::from(2000u64));
    }

    #[test]
    fn reveal_rejects_foreign_context_shapes() {
        let ctx = ShareContext::new(3, 1, 0).expect("valid");
        let other = ShareContext::new(2, 1, 0).expect("valid");
        let provider =
            LocalTrustedTripleProvider::new(ctx, ChaCha20Rng::seed_from_u64(9)).expect("valid");
        let sim =
            MpcSimulator::<Fr, _>::new(ctx, Box::new(provider), ChaCha20Rng::seed_from_u64(10))
                .expect("valid");

        let mut rng = ChaCha20Rng::seed_from_u64(11);
        let shares = share_input(&other, &Fr::from(4u64), &mut rng).expect("valid");
        let foreign = SharedValue::from_shares(shares).expect("non-empty");

        assert!(matches!(sim.reveal(&foreign), Err(MpcError::RevealMisuse)));
    }

    #[test]
    fn singleton_context_is_rejected() {
        let bad = ShareContext {
            party_count: 1,
            execution_id: 0,
            domain: 0,
        };
        let good = ShareContext::new(2, 0, 0).expect("valid");
        let provider: Box<dyn TripleProvider<Fr>> =
            Box::new(LocalTrustedTripleProvider::new(good, ChaCha20Rng::seed_from_u64(1)).unwrap());
        assert!(matches!(
            MpcSimulator::<Fr, _>::new(bad, provider, ChaCha20Rng::seed_from_u64(2)),
            Err(MpcError::InvalidPartyCount)
        ));
    }

    #[test]
    fn transcript_hook_counts_events() {
        let mut hook = TranscriptHook::new();
        hook.record_operation();
        hook.record_operation();
        hook.record_reveal();
        assert_eq!(hook.recorded_count(), 3);
        assert_eq!(format!("{hook:?}"), "TranscriptHook { recorded_events: 3 }");
    }
}
