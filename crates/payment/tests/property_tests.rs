//! Property tests for the payment domain.
//!
//! - The plaintext range check and the compiled circuit gadget agree
//!   on every `(amount, limit)` pair with `amount ≤ limit`.
//! - Canonical encodings round-trip byte-for-byte.
//! - Payment ids are deterministic.

use ark_ff::Zero;
use payment::{
    circuit_range_check_outputs, decompose, reference_range_check, Amount, AmountUnit, Payment,
    PaymentStatement,
};
use proptest::prelude::*;

/// Strategy: `0 ≤ amount ≤ limit ≤ 4096`.
fn amount_limit_pairs() -> impl Strategy<Value = (u64, u64)> {
    (0u64..=4096u64).prop_flat_map(|limit| (0..=limit).prop_map(move |amount| (amount, limit)))
}

fn sample_statement(seed: u8, value: u64) -> PaymentStatement {
    PaymentStatement {
        payment_id: crypto_core::Digest::new([seed; 32]),
        amount: Amount {
            value,
            unit: AmountUnit::Cents,
        },
        recipient_commitment: crypto_core::Digest::new([seed.wrapping_add(1); 32]),
        policy_id: policy::PolicyId::from_digest(crypto_core::Digest::new(
            [seed.wrapping_add(2); 32],
        )),
        circuit_id: circuit::CircuitId::from_digest(crypto_core::Digest::new(
            [seed.wrapping_add(3); 32],
        )),
        protocol_version: 1,
        nonce: [seed.wrapping_add(4); 32],
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn reference_and_circuit_range_checks_agree((amount, limit) in amount_limit_pairs()) {
        // Reference side: accepts exactly the in-range pairs.
        let reference_ok = reference_range_check(amount, limit).is_ok();

        // Circuit side: all four published outputs vanish exactly when
        // the constraint holds.
        let outputs = circuit_range_check_outputs(amount, limit);
        let circuit_ok = outputs.iter().all(|v| v.is_zero());

        prop_assert_eq!(reference_ok, circuit_ok);
    }

    #[test]
    fn statements_round_trip_byte_for_byte(seed in any::<u8>(), value in any::<u64>()) {
        let statement = sample_statement(seed, value);
        let canonical = statement.encode();
        let decoded =
            PaymentStatement::decode(&canonical).expect("fixed-width statement decodes");
        prop_assert_eq!(decoded.encode(), canonical);
    }

    #[test]
    fn payments_round_trip_byte_for_byte(
        version in any::<u8>(),
        raw_id in any::<[u8; 32]>(),
        value in any::<u64>(),
        recipient in any::<[u8; 32]>(),
        nonce in any::<[u8; 32]>(),
    ) {
        let payment = Payment {
            version,
            payment_id: raw_id,
            amount: Amount { value, unit: AmountUnit::Cents },
            recipient_commitment: crypto_core::Digest::new(recipient),
            nonce,
        };
        let canonical = payment.encode();
        prop_assert_eq!(payment.encode(), canonical);
    }

    #[test]
    fn payment_ids_are_deterministic(
        version in any::<u8>(),
        raw_id in any::<[u8; 32]>(),
        value in any::<u64>(),
        recipient in any::<[u8; 32]>(),
        nonce in any::<[u8; 32]>(),
    ) {
        let payment = Payment {
            version,
            payment_id: raw_id,
            amount: Amount { value, unit: AmountUnit::Cents },
            recipient_commitment: crypto_core::Digest::new(recipient),
            nonce,
        };
        prop_assert_eq!(payment.payment_id(), payment.payment_id());
    }

    #[test]
    fn decompositions_reconstruct_any_u64(value in any::<u64>()) {
        let bits = decompose(value);
        let mut rebuilt = 0u64;
        for (index, bit) in bits.iter().enumerate() {
            rebuilt |= u64::from(*bit) << index;
        }
        prop_assert_eq!(rebuilt, value);
    }
}
