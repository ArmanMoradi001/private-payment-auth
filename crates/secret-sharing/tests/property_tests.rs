//! Property-based tests for Shamir split/reconstruct.

use crypto_core::SecretBytes;
use proptest::prelude::*;
use rand_chacha::rand_core::SeedableRng;

fn secret_strategy() -> impl Strategy<Value = SecretBytes> {
    // Non-empty secrets; leading zeros are stripped by `split`, so generate
    // secrets with a non-zero first byte to keep round-trips exact.
    (
        any::<u8>(),
        1usize..=32,
        prop::collection::vec(any::<u8>(), 0..32),
    )
        .prop_map(|(first, len, rest)| {
            let mut bytes = Vec::with_capacity(len);
            bytes.push((first % 15) + 1);
            for b in rest.into_iter().take(len - 1) {
                bytes.push(b);
            }
            SecretBytes::new(bytes)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn reconstruct_split_round_trip(
        secret in secret_strategy(),
        threshold in 2usize..8,
        extra in 0usize..6,
        seed in any::<u64>(),
    ) {
        let share_count = threshold + extra;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let shares = secret_sharing::split(&secret, threshold, share_count, &mut rng).expect("valid split");
        let recovered = secret_sharing::reconstruct(&shares).expect("valid reconstruct");
        assert_eq!(recovered.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn any_subset_of_size_threshold_reconstructs(
        secret in secret_strategy(),
        threshold in 2usize..7,
        extra in 0usize..5,
        drop_seed in any::<u8>(),
    ) {
        let share_count = threshold + extra;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(u64::from(drop_seed) + 1);
        let shares = secret_sharing::split(&secret, threshold, share_count, &mut rng).expect("valid split");

        // Deterministically pick an arbitrary subset of size `threshold`.
        let mut indices: Vec<usize> = (0..share_count).collect();
        let mut state = u32::from(drop_seed);
        for i in (1..indices.len()).rev() {
            state = state.wrapping_mul(1664525).wrapping_add(1013904223);
            let j = (state as usize) % (i + 1);
            indices.swap(i, j);
        }
        let subset: Vec<_> = indices[..threshold].iter().map(|&i| shares[i].clone()).collect();
        let recovered = secret_sharing::reconstruct(&subset).expect("valid reconstruct");
        assert_eq!(recovered.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn subsets_smaller_than_threshold_fail(
        secret in secret_strategy(),
        threshold in 3usize..7,
        extra in 0usize..4,
    ) {
        let share_count = threshold + extra;
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(123);
        let shares = secret_sharing::split(&secret, threshold, share_count, &mut rng).expect("valid split");
        for size in 1..threshold.min(shares.len()) {
            let subset: Vec<_> = shares[..size].to_vec();
            assert!(
                secret_sharing::reconstruct(&subset).is_err(),
                "{size} of {threshold} shares must not reconstruct"
            );
        }
    }
}
