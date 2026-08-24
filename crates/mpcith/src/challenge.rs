//! Challenge sources.
//!
//! Challenges name which of the three party views stays hidden. The
//! prover receives challenges through the injectable
//! [`ChallengeSource`] trait: production uses a random source; tests
//! use a deterministic one to force specific hidden parties.
//! Fiat–Shamir will later replace this seam with transcript-derived
//! challenges (see ADR 0006).

use rand_core::{CryptoRngCore, RngCore};
use std::collections::VecDeque;

use crate::error::MpcithError;
use crate::types::{Challenge, PartyId, PARTY_COUNT};

/// Supplies per-repetition challenges to the prover.
pub trait ChallengeSource {
    /// Returns the next challenge.
    fn next_challenge(&mut self) -> Result<Challenge, MpcithError>;
}

/// Draws uniformly random hidden parties from a CSPRNG.
///
/// The modulo reduction over `u64` introduces bias far below any
/// practical security bound (≈ 2^-63 relative); it avoids pulling in a
/// sampling dependency.
pub struct RandomChallengeSource<R> {
    rng: R,
}

impl<R: CryptoRngCore> RandomChallengeSource<R> {
    /// Wraps an RNG as a challenge source.
    pub fn new(rng: R) -> Self {
        Self { rng }
    }
}

impl<R: CryptoRngCore> ChallengeSource for RandomChallengeSource<R> {
    fn next_challenge(&mut self) -> Result<Challenge, MpcithError> {
        let value = (RngCore::next_u64(&mut self.rng) % u64::from(PARTY_COUNT)) as u8;
        let hidden_party = PartyId::new(value).map_err(|_| MpcithError::InvalidProtocolState)?;
        Ok(Challenge { hidden_party })
    }
}

/// Returns pre-configured challenges in order; used by tests and
/// security analysis to exercise every hidden-party choice.
#[derive(Clone, Debug, Default)]
pub struct DeterministicChallengeSource {
    queue: VecDeque<PartyId>,
}

impl DeterministicChallengeSource {
    /// Builds a source yielding the given hidden parties in order.
    pub fn new(hidden_parties: impl IntoIterator<Item = PartyId>) -> Self {
        Self {
            queue: hidden_parties.into_iter().collect(),
        }
    }

    /// Builds a source yielding `hidden` for every challenge forever
    /// (until exhausted callers stop asking).
    pub fn repeating(hidden: PartyId, count: usize) -> Self {
        Self::new(std::iter::repeat_n(hidden, count))
    }
}

impl ChallengeSource for DeterministicChallengeSource {
    fn next_challenge(&mut self) -> Result<Challenge, MpcithError> {
        let hidden_party = self
            .queue
            .pop_front()
            .ok_or(MpcithError::InvalidProtocolState)?;
        Ok(Challenge { hidden_party })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn random_source_only_emits_valid_parties() {
        let mut src = RandomChallengeSource::new(ChaCha20Rng::seed_from_u64(5));
        for _ in 0..64 {
            let c = src.next_challenge().expect("valid");
            assert!(c.hidden_party.get() < PARTY_COUNT);
        }
    }

    #[test]
    fn deterministic_source_yields_configured_sequence() {
        let parties = [0u8, 2, 1];
        let mut src = DeterministicChallengeSource::new(
            parties.iter().map(|&p| PartyId::new(p).expect("valid")),
        );
        for expected in parties {
            let c = src.next_challenge().expect("valid");
            assert_eq!(c.hidden_party.get(), expected);
        }
        assert_eq!(src.next_challenge(), Err(MpcithError::InvalidProtocolState));
    }

    #[test]
    fn repeating_source_is_constant() {
        let mut src = DeterministicChallengeSource::repeating(PartyId::new(2).unwrap(), 3);
        for _ in 0..3 {
            assert_eq!(src.next_challenge().expect("valid").hidden_party.get(), 2);
        }
        assert!(src.next_challenge().is_err());
    }
}
