//! Additive sharing and reconstruction of secret inputs.
//!
//! A secret field element is distributed by drawing `party_count - 1`
//! uniformly random elements and setting the last share to
//! `secret - sum(random shares)`. Reconstruction is the sum over all
//! shares. Because every share is uniform, any strict subset reveals
//! nothing about the secret (information-theoretic privacy).

use ark_ff::PrimeField;
use rand_core::CryptoRngCore;

use crate::context::ShareContext;
use crate::error::MpcError;
use crate::types::Share;

/// Splits `secret` into one additive [`Share`] per party.
///
/// The first `party_count - 1` shares are fresh uniformly random field
/// elements; the last share is chosen so that the sum of all shares
/// equals the secret.
///
/// # Errors
///
/// - [`MpcError::InvalidPartyCount`] if `ctx.party_count <= 1`.
/// - [`MpcError::RngFailure`] if randomness generation fails.
pub fn share_input<F: PrimeField, R: CryptoRngCore>(
    ctx: &ShareContext,
    secret: &F,
    rng: &mut R,
) -> Result<Vec<Share<F>>, MpcError> {
    if ctx.party_count <= 1 {
        return Err(MpcError::InvalidPartyCount);
    }

    let mut random_sum = F::zero();
    let mut shares = Vec::with_capacity(ctx.party_count);
    for _ in 1..ctx.party_count {
        let r = F::rand(&mut *rng);
        random_sum += r;
        shares.push(Share::new(r));
    }
    shares.push(Share::new(*secret - random_sum));
    Ok(shares)
}

/// Reconstructs the secret as the sum over all party shares.
///
/// # Errors
///
/// - [`MpcError::InsufficientShares`] if fewer than `ctx.party_count`
///   shares are provided.
/// - [`MpcError::InvalidOperation`] if more than `ctx.party_count`
///   shares are provided; additive reconstruction consumes exactly one
///   share per party and extras indicate a protocol fault.
pub fn reconstruct<F: PrimeField>(ctx: &ShareContext, shares: &[Share<F>]) -> Result<F, MpcError> {
    if shares.len() < ctx.party_count {
        return Err(MpcError::InsufficientShares);
    }
    if shares.len() > ctx.party_count {
        return Err(MpcError::InvalidOperation);
    }

    let mut secret = F::zero();
    for share in shares {
        secret += *share.value();
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ed25519::Fr;
    use ark_ff::{One, Zero};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn ctx() -> ShareContext {
        ShareContext::new(4, 7, 0).expect("valid")
    }

    #[test]
    fn share_and_reconstruct_round_trip() {
        let mut rng = ChaCha20Rng::seed_from_u64(42);
        let context = ctx();
        let secret = Fr::from(123456789u64);

        let shares = share_input::<Fr, _>(&context, &secret, &mut rng).expect("valid");
        assert_eq!(shares.len(), 4);

        let recovered = reconstruct(&context, &shares).expect("valid");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn zero_secret_shares_are_uniform() {
        // Even the all-zero secret yields individually random shares;
        // only their sum is zero.
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let context = ctx();
        let shares = share_input::<Fr, _>(&context, &Fr::zero(), &mut rng).expect("valid");
        assert!(shares.iter().any(|s| *s.value() != Fr::zero()));
        assert_eq!(reconstruct(&context, &shares).expect("valid"), Fr::zero());
    }

    #[test]
    fn strict_subsets_reveal_nothing_but_are_rejected_on_reconstruct() {
        let mut rng = ChaCha20Rng::seed_from_u64(99);
        let context = ctx();
        let secret = Fr::one();
        let shares = share_input::<Fr, _>(&context, &secret, &mut rng).expect("valid");

        assert_eq!(
            reconstruct(&context, &shares[..3]),
            Err(MpcError::InsufficientShares)
        );
        // Individual shares are not the secret.
        for share in &shares {
            assert_ne!(*share.value(), secret);
        }
    }

    #[test]
    fn wrong_share_count_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let context = ctx();
        let mut shares = share_input::<Fr, _>(&context, &Fr::zero(), &mut rng).expect("valid");
        shares.push(Share::new(Fr::zero()));
        assert_eq!(
            reconstruct(&context, &shares),
            Err(MpcError::InvalidOperation)
        );
    }

    #[test]
    fn invalid_context_is_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let bad = ShareContext {
            party_count: 1,
            execution_id: 0,
            domain: 0,
        };
        let err = share_input::<Fr, _>(&bad, &Fr::zero(), &mut rng).unwrap_err();
        assert_eq!(err, MpcError::InvalidPartyCount);
    }
}
