//! Integer / arithmetic boundary regression tests (Phase 10, Part C).
//!
//! Verifies that the integer and field-conversion layers handle boundary
//! values correctly: `0`, `1`, `u64::MAX`, and the field modulus `p - 1`.
//! These are the values most likely to trigger off-by-one, wraparound, or
//! canonicalization bugs.

use ark_ed25519::Fr;
use ark_ff::{BigInteger, One, PrimeField};
use payment::{decompose, reference_range_check, Amount, AmountUnit};
use secret_sharing::field::element_from_be_bytes;

fn be32(value: u64) -> Vec<u8> {
    Fr::from(value).into_bigint().to_bytes_be()
}

#[test]
fn amount_encode_decode_boundaries() {
    for value in [0u64, 1, u64::MAX] {
        let amount = Amount {
            value,
            unit: AmountUnit::Cents,
        };
        let decoded = Amount::decode(&amount.encode()).expect("round-trips");
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.unit, AmountUnit::Cents);
    }
}

#[test]
fn field_element_boundaries_accepted() {
    // 0, 1, u64::MAX, and p-1 are all valid canonical field elements.
    let valid: Vec<Vec<u8>> = vec![
        be32(0),
        be32(1),
        be32(u64::MAX),
        (-Fr::one()).into_bigint().to_bytes_be(), // p - 1
    ];
    for bytes in valid {
        let elt = element_from_be_bytes(&bytes).expect("in-range element");
        // Re-encoding must be canonical and stable.
        let re = element_from_be_bytes(&elt.into_bigint().to_bytes_be()).expect("stable");
        assert_eq!(elt, re);
    }
}

#[test]
fn field_element_at_or_above_modulus_rejected() {
    // All-0xFF is far above p and must be rejected.
    assert!(element_from_be_bytes(&[0xFFu8; 32]).is_err());
    // The canonical modulus itself (p) is not a valid field element.
    // p = (p - 1) + 1; construct by adding one to the p-1 encoding.
    let mut p_minus_one = (-Fr::one()).into_bigint().to_bytes_be();
    // Increment the big-endian representation by one.
    let mut carry = 1u8;
    for b in p_minus_one.iter_mut().rev() {
        let (v, c) = b.overflowing_add(carry);
        *b = v;
        carry = c as u8;
    }
    assert!(element_from_be_bytes(&p_minus_one).is_err());
}

#[test]
fn reference_range_check_boundaries() {
    assert!(reference_range_check(0, 0).is_ok());
    assert!(reference_range_check(0, u64::MAX).is_ok());
    assert!(reference_range_check(u64::MAX, u64::MAX).is_ok());
    assert!(reference_range_check(1, 0).is_err());
    assert!(reference_range_check(u64::MAX, u64::MAX - 1).is_err());
    assert!(reference_range_check(u64::MAX, 0).is_err());
}

#[test]
fn decompose_boundaries() {
    assert!(decompose(0).iter().all(|b| !*b));
    assert!(decompose(u64::MAX).iter().all(|b| *b));

    // Reconstruct from bits and confirm it equals the original value.
    let reconstruct = |v: u64| -> u64 {
        decompose(v)
            .iter()
            .enumerate()
            .fold(0u64, |acc, (i, bit)| acc + ((*bit as u64) << i))
    };
    assert_eq!(reconstruct(0), 0);
    assert_eq!(reconstruct(1), 1);
    assert_eq!(reconstruct(u64::MAX), u64::MAX);
    assert_eq!(reconstruct(12345678901234567890), 12345678901234567890);
}
