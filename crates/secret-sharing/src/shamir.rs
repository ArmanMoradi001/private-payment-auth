//! Shamir secret sharing over the crate's prime field.
//!
//! A secret is treated as an integer in the prime field. Splitting draws a
//! random polynomial of degree `threshold - 1` whose constant term is the
//! secret and evaluates it at the non-zero points `x = 1..=share_count`.
//! Any `threshold` distinct shares reconstruct the secret via Lagrange
//! interpolation at `x = 0`.

use crate::error::SecretSharingError;
use crate::field::{element_from_be_bytes, element_to_be_bytes, random_element, FieldElement};
use crate::share::Share;
use ark_ff::{Field, One, Zero};
use crypto_core::SecretBytes;

/// Maximum supported share count.
///
/// Bounds both split-time generation and reconstruction input size. A
/// caller attempting to reconstruct from an unbounded number of shares
/// would otherwise drive quadratic duplicate-checking cost.
pub const MAX_SHARE_COUNT: usize = 1000;

/// Splits a secret into `share_count` shares requiring `threshold` shares to
/// reconstruct.
///
/// The secret is canonicalized by stripping leading zero bytes before it is
/// mapped into the field; reconstruction returns this canonical form. The
/// secret must be at most [`crate::field::FIELD_ELEMENT_SIZE`] bytes long and
/// represent an integer strictly below the field modulus.
///
/// # Errors
///
/// - [`SecretSharingError::EmptyInput`] if the secret is empty.
/// - [`SecretSharingError::InvalidThreshold`] if `threshold <= 1`.
/// - [`SecretSharingError::InvalidShareCount`] if `share_count == 0` or
///   exceeds [`MAX_SHARE_COUNT`].
/// - [`SecretSharingError::ThresholdGreaterThanCount`] if
///   `threshold > share_count`.
/// - [`SecretSharingError::SecretTooLargeForField`] if the secret does not
///   fit in the prime field.
pub fn split<R: rand_core::CryptoRngCore>(
    secret: &SecretBytes,
    threshold: usize,
    share_count: usize,
    rng: &mut R,
) -> Result<Vec<Share>, SecretSharingError> {
    if threshold <= 1 {
        return Err(SecretSharingError::InvalidThreshold);
    }
    if share_count == 0 || share_count > MAX_SHARE_COUNT {
        return Err(SecretSharingError::InvalidShareCount);
    }
    if threshold > share_count {
        return Err(SecretSharingError::ThresholdGreaterThanCount);
    }

    let secret_bytes = canonical_secret_bytes(secret)?;
    let secret_element = element_from_be_bytes(&secret_bytes)
        .map_err(|_| SecretSharingError::SecretTooLargeForField)?;

    // Random polynomial f(x) = secret + c_1*x + ... + c_{t-1}*x^{t-1}.
    let mut coefficients = Vec::with_capacity(threshold);
    coefficients.push(secret_element);
    for _ in 1..threshold {
        coefficients.push(random_element(rng)?);
    }

    let (threshold_u32, share_count_u32) = (
        u32::try_from(threshold).expect("checked above"),
        u32::try_from(share_count).expect("checked above"),
    );
    let mut shares = Vec::with_capacity(share_count);
    for index in 1..=share_count_u32 {
        let x = FieldElement::from(index);
        let mut value = FieldElement::from(0u64);
        for coeff in coefficients.iter().rev() {
            value = value * x + *coeff;
        }
        shares.push(Share::new(threshold_u32, share_count_u32, index, value)?);
    }
    Ok(shares)
}

/// Reconstructs a secret from at least `threshold` shares.
///
/// Shares must agree on version, threshold, and share count metadata and
/// carry distinct non-zero indices. Only the first `threshold` valid shares
/// are used; extra shares are ignored.
///
/// # Errors
///
/// - [`SecretSharingError::EmptyInput`] if `shares` is empty.
/// - [`SecretSharingError::IncompatibleMetadata`] if shares disagree on
///   version, threshold, or share count.
/// - [`SecretSharingError::DuplicateShareIndex`] or
///   [`SecretSharingError::InvalidShareIndex`] on bad indices.
/// - [`SecretSharingError::InsufficientShares`] if fewer than `threshold`
///   consistent shares are provided.
#[allow(clippy::similar_names)]
pub fn reconstruct(shares: &[Share]) -> Result<SecretBytes, SecretSharingError> {
    if shares.is_empty() {
        return Err(SecretSharingError::EmptyInput);
    }
    if shares.len() > MAX_SHARE_COUNT {
        return Err(SecretSharingError::InvalidShareCount);
    }

    let first = &shares[0];
    if shares.iter().any(|s| {
        s.version != first.version
            || s.threshold != first.threshold
            || s.share_count != first.share_count
    }) {
        return Err(SecretSharingError::IncompatibleMetadata);
    }

    let threshold = first.threshold as usize;
    for s in shares {
        if s.index == 0 || s.index as usize > first.share_count as usize {
            return Err(SecretSharingError::InvalidShareIndex);
        }
    }
    for i in 1..shares.len() {
        if shares[i..].iter().any(|s| s.index == shares[i - 1].index) {
            return Err(SecretSharingError::DuplicateShareIndex);
        }
    }

    if shares.len() < threshold {
        return Err(SecretSharingError::InsufficientShares);
    }

    let used = &shares[..threshold];
    let mut secret = FieldElement::zero();
    for (i, si) in used.iter().enumerate() {
        let xi = FieldElement::from(si.index);
        let mut lagrange = FieldElement::one();
        for (j, sj) in used.iter().enumerate() {
            if i == j {
                continue;
            }
            let xj = FieldElement::from(sj.index);
            // lagrange *= xj / (xj - xi)
            lagrange *= xj
                * (xj - xi)
                    .inverse()
                    .ok_or(SecretSharingError::ReconstructionFailure)?;
        }
        secret += si.value * lagrange;
    }

    let bytes = element_to_be_bytes(&secret);
    // Strip the big-endian zero padding back down to the canonical
    // (leading-zero-free) representation produced by `split`.
    let first_nonzero = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    if first_nonzero == bytes.len() {
        return Ok(SecretBytes::new(vec![0u8]));
    }
    Ok(SecretBytes::new(bytes[first_nonzero..].to_vec()))
}

/// Strips leading zero bytes from a secret, returning an error for empty input.
fn canonical_secret_bytes(secret: &SecretBytes) -> Result<Vec<u8>, SecretSharingError> {
    let bytes = secret.as_bytes();
    if bytes.is_empty() {
        return Err(SecretSharingError::EmptyInput);
    }
    let first_nonzero = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    if first_nonzero == bytes.len() {
        // All-zero secret: keep a single zero byte so it round-trips.
        return Ok(vec![0u8]);
    }
    Ok(bytes[first_nonzero..].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::FIELD_ELEMENT_SIZE;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    fn rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    #[test]
    fn split_reconstruct_round_trip() {
        let mut r = rng();
        let secret = SecretBytes::new(vec![0xde, 0xad, 0xbe, 0xef]);
        let shares = split(&secret, 3, 5, &mut r).expect("valid");
        assert_eq!(shares.len(), 5);
        let recovered = reconstruct(&shares[1..4]).expect("valid");
        assert_eq!(recovered.as_bytes(), &[0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn invalid_parameters_are_rejected() {
        let mut r = rng();
        let secret = SecretBytes::new(vec![1]);
        assert_eq!(
            split(&secret, 1, 5, &mut r),
            Err(SecretSharingError::InvalidThreshold)
        );
        assert_eq!(
            split(&secret, 3, 2, &mut r),
            Err(SecretSharingError::ThresholdGreaterThanCount)
        );
        assert_eq!(
            split(&secret, 2, 0, &mut r),
            Err(SecretSharingError::InvalidShareCount)
        );
        assert_eq!(
            split(&SecretBytes::new(Vec::new()), 2, 2, &mut r),
            Err(SecretSharingError::EmptyInput)
        );
        let too_big = SecretBytes::new(vec![0xff; FIELD_ELEMENT_SIZE + 1]);
        assert_eq!(
            split(&too_big, 2, 2, &mut r),
            Err(SecretSharingError::SecretTooLargeForField)
        );
    }

    #[test]
    fn insufficient_and_inconsistent_shares_fail() {
        let mut r = rng();
        let secret = SecretBytes::new(vec![9, 9]);
        let shares = split(&secret, 3, 5, &mut r).expect("valid");
        assert!(matches!(
            reconstruct(&shares[..2]),
            Err(SecretSharingError::InsufficientShares)
        ));
        assert!(matches!(
            reconstruct(&[]),
            Err(SecretSharingError::EmptyInput)
        ));

        let mut mixed = shares.clone();
        mixed[0] = Share::new(4, 5, 1, mixed[0].value).expect("valid");
        assert!(matches!(
            reconstruct(&mixed),
            Err(SecretSharingError::IncompatibleMetadata)
        ));

        let mut dup = shares.clone();
        dup[1] = Share::new(
            dup[0].threshold,
            dup[0].share_count,
            dup[0].index,
            dup[1].value,
        )
        .expect("valid");
        assert!(matches!(
            reconstruct(&dup),
            Err(SecretSharingError::DuplicateShareIndex)
        ));

        let mut zero_index = shares.clone();
        zero_index[0] = Share {
            index: 0,
            ..shares[0].clone()
        };
        assert!(matches!(
            reconstruct(&zero_index),
            Err(SecretSharingError::InvalidShareIndex)
        ));
    }
}
