//! Cryptographic randomness helpers.

use rand_core::CryptoRngCore;

use crate::error::CryptoCoreError;
use crate::secret::SecretBytes;

/// Fills a [`SecretBytes`] of `len` fresh random bytes from `rng`.
///
/// RNG failures are mapped to [`CryptoCoreError::RngFailure`]; the
/// partially filled buffer is still zeroized on drop.
pub fn generate_random_bytes<R: CryptoRngCore>(
    rng: &mut R,
    len: usize,
) -> Result<SecretBytes, CryptoCoreError> {
    let mut bytes = SecretBytes::new(vec![0u8; len]);
    rng.try_fill_bytes(bytes.as_bytes_mut())
        .map_err(|_| CryptoCoreError::RngFailure)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{CryptoRng, OsRng, RngCore};

    struct FailingRng;
    impl RngCore for FailingRng {
        fn next_u32(&mut self) -> u32 {
            unreachable!()
        }
        fn next_u64(&mut self) -> u64 {
            unreachable!()
        }
        fn fill_bytes(&mut self, _dest: &mut [u8]) {
            unreachable!()
        }
        fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand_core::Error> {
            Err(rand_core::Error::new(std::io::Error::other("rng failed")))
        }
    }
    impl CryptoRng for FailingRng {}

    #[test]
    fn generates_requested_length() {
        let s = generate_random_bytes(&mut OsRng, 32).expect("os rng");
        assert_eq!(s.len(), 32);
        assert_ne!(s.as_bytes(), &[0u8; 32]);
    }

    #[test]
    fn failing_rng_maps_to_error() {
        let err = generate_random_bytes(&mut FailingRng, 8).unwrap_err();
        assert_eq!(err, CryptoCoreError::RngFailure);
    }
}
