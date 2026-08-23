//! Prime field used for Shamir secret sharing.
//!
//! Shares live in the scalar field of the ed25519 curve (`ark_ed25519::Fr`),
//! i.e. the prime field of order
//!
//! ```text
//! p = 2^252 + 27742317777372353535851937790883648493
//! ```
//!
//! This modulus was selected because it is a well-known, heavily audited
//! prime (the Curve25519 group order), it provides roughly 252 bits of
//! security margin for information-theoretic secret sharing, and the
//! `ark-ff` implementation is constant-time, `no_std`-friendly, and free of
//! `unsafe` code. Field elements are always serialized as fixed-size
//! big-endian byte strings of [`FIELD_ELEMENT_SIZE`] bytes.

use crate::error::SecretSharingError;
use ark_ed25519::Fr;
use ark_ff::{BigInteger, PrimeField};
use rand_core::RngCore;

/// The prime field element type used for shares.
pub type FieldElement = Fr;

/// Serialized size in bytes of a field element (big-endian, fixed width).
pub const FIELD_ELEMENT_SIZE: usize = 32;

/// Big-endian representation of the field modulus.
///
/// `p = 2^252 + 27742317777372353535851937790883648493`.
const MODULUS_BE: [u8; FIELD_ELEMENT_SIZE] = [
    0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6, 0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed,
];

/// Converts an exact big-endian byte string (strictly below the modulus)
/// into a field element without reduction.
fn exact_element_from_be(buf: &[u8; FIELD_ELEMENT_SIZE]) -> FieldElement {
    let mut limbs = [0u64; 4];
    for (i, limb) in limbs.iter_mut().enumerate() {
        let start = (3 - i) * 8;
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&buf[start..start + 8]);
        *limb = u64::from_be_bytes(chunk);
    }
    FieldElement::from_bigint(ark_ff::BigInt::new(limbs)).expect("value below modulus fits")
}

/// Interprets `bytes` as a big-endian integer and converts it to a field
/// element.
///
/// The conversion is exact: if the integer represented by `bytes` is greater
/// than or equal to the field modulus (or longer than
/// [`FIELD_ELEMENT_SIZE`] bytes), [`SecretSharingError::SecretTooLargeForField`]
/// is returned instead of reducing modulo `p`.
pub fn element_from_be_bytes(bytes: &[u8]) -> Result<FieldElement, SecretSharingError> {
    if bytes.len() > FIELD_ELEMENT_SIZE {
        return Err(SecretSharingError::SecretTooLargeForField);
    }
    let mut buf = [0u8; FIELD_ELEMENT_SIZE];
    buf[FIELD_ELEMENT_SIZE - bytes.len()..].copy_from_slice(bytes);
    if buf >= MODULUS_BE {
        return Err(SecretSharingError::SecretTooLargeForField);
    }
    Ok(exact_element_from_be(&buf))
}

/// Converts a field element to its canonical fixed-width big-endian bytes.
#[must_use]
pub fn element_to_be_bytes(element: &FieldElement) -> [u8; FIELD_ELEMENT_SIZE] {
    let mut le = element.into_bigint().to_bytes_le();
    le.reverse();
    let mut out = [0u8; FIELD_ELEMENT_SIZE];
    out.copy_from_slice(&le);
    out
}

/// Samples a uniformly distributed field element using rejection sampling.
///
/// Values at or above the modulus are rejected and redrawn, so every field
/// element is equally likely.
pub fn random_element<R: RngCore>(rng: &mut R) -> Result<FieldElement, SecretSharingError> {
    for _ in 0..128 {
        let mut buf = [0u8; FIELD_ELEMENT_SIZE];
        rng.fill_bytes(&mut buf);
        if buf < MODULUS_BE {
            return Ok(exact_element_from_be(&buf));
        }
    }
    Err(SecretSharingError::RngFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_small_values() {
        for v in [&[0u8][..], &[1], &[0, 42], &[0xff; 31]] {
            let e = element_from_be_bytes(v).expect("valid");
            assert_eq!(&element_to_be_bytes(&e)[32 - v.len()..], v);
            assert!(element_to_be_bytes(&e)[..32 - v.len()]
                .iter()
                .all(|b| *b == 0));
        }
    }

    #[test]
    fn rejects_values_at_or_above_modulus() {
        // Exactly the modulus.
        assert_eq!(
            element_from_be_bytes(&MODULUS_BE),
            Err(SecretSharingError::SecretTooLargeForField)
        );
        // Modulus minus one is fine.
        let mut below = MODULUS_BE;
        below[31] -= 1;
        assert!(element_from_be_bytes(&below).is_ok());
        // Longer input.
        assert_eq!(
            element_from_be_bytes(&[0xff; 33]),
            Err(SecretSharingError::SecretTooLargeForField)
        );
    }

    #[test]
    fn zero_round_trips() {
        let e = element_from_be_bytes(&[]).expect("empty is zero");
        assert!(element_to_be_bytes(&e) == [0u8; 32]);
    }
}
