//! The payment object: the payer-side record of what is being paid.
//!
//! A [`Payment`] bundles every payment attribute, carries a fresh
//! [`Payment::nonce`] for replay protection, and derives its semantic
//! id via domain-separated hashing of the canonical encoding.

use crypto_core::{CanonicalEncode, Digest, HashFunction, Sha256Hash};

/// Domain separator for semantic payment ids.
pub const PAYMENT_ID_DOMAIN: &[u8] = b"private-payment-auth/payment/v1";

/// Current payment-object encoding version.
pub const PAYMENT_ENCODING_VERSION: u8 = 1;

/// Byte length of the payment identifier and nonce fields.
pub const PAYMENT_ID_LEN: usize = 32;
/// Byte length of the replay-protection nonce.
pub const NONCE_LEN: usize = 32;

/// A payment record with a fresh nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payment {
    /// Payment-record format version.
    pub version: u8,
    /// Raw 32-byte payment identifier (uniqueness is an application
    /// concern; see ADR 0009 for the replay model).
    pub payment_id: [u8; PAYMENT_ID_LEN],
    /// The amount being paid.
    pub amount: crate::amount::Amount,
    /// Commitment binding the payment to its intended recipient.
    pub recipient_commitment: Digest,
    /// Fresh per-payment randomness for replay protection.
    pub nonce: [u8; NONCE_LEN],
}

impl Payment {
    /// Canonical encoding length:
    /// `version(1) ‖ payment_id(32) ‖ amount(10) ‖ recipient(32) ‖ nonce(32)`.
    pub const ENCODED_LEN: usize =
        1 + PAYMENT_ID_LEN + crate::amount::Amount::ENCODED_LEN + DIGEST_LEN + NONCE_LEN;

    /// Returns the canonical encoding of this payment.
    ///
    /// Layout:
    /// `version(u8) ‖ payment_id(32B) ‖ amount(version u8 ‖ value u64
    /// BE ‖ unit u8) ‖ recipient_commitment(32B) ‖ nonce(32B)`.
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        const _: () = assert!(
            crate::amount::Amount::ENCODED_LEN == 10,
            "payment layout assumes fixed-width amounts"
        );
        let mut out = [0u8; Self::ENCODED_LEN];
        let mut offset = 0;
        out[offset] = self.version;
        offset += 1;
        out[offset..offset + PAYMENT_ID_LEN].copy_from_slice(&self.payment_id);
        offset += PAYMENT_ID_LEN;
        let encoded_amount = self.amount.encode();
        out[offset..offset + encoded_amount.len()].copy_from_slice(&encoded_amount);
        offset += encoded_amount.len();
        out[offset..offset + DIGEST_LEN].copy_from_slice(self.recipient_commitment.as_bytes());
        offset += DIGEST_LEN;
        out[offset..offset + NONCE_LEN].copy_from_slice(&self.nonce);
        out
    }

    /// Semantic identity of this payment:
    /// `SHA-256("private-payment-auth/payment/v1" ‖ canonical_encoding)`.
    ///
    /// Deterministic by construction; two payments with equal ids have
    /// identical canonical encodings.
    pub fn payment_id(&self) -> Digest {
        Sha256Hash::hash_domain(PAYMENT_ID_DOMAIN, &self.encode()).into()
    }
}

impl CanonicalEncode for Payment {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.encode());
    }
}

const DIGEST_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::AmountUnit;

    fn sample() -> Payment {
        Payment {
            version: 1,
            payment_id: [7u8; PAYMENT_ID_LEN],
            amount: crate::amount::Amount {
                value: 1234,
                unit: AmountUnit::Cents,
            },
            recipient_commitment: Digest::new([0xaa; 32]),
            nonce: [0x55u8; NONCE_LEN],
        }
    }

    #[test]
    fn encoding_is_deterministic_and_fixed_width() {
        let payment = sample();
        assert_eq!(payment.encode(), payment.encode());
        assert_eq!(payment.encode().len(), Payment::ENCODED_LEN);
        assert_eq!(Payment::ENCODED_LEN, 107);
    }

    #[test]
    fn payment_ids_are_deterministic_and_discriminating() {
        let payment = sample();
        assert_eq!(payment.payment_id(), payment.payment_id());

        let mut other = payment;
        other.amount.value += 1;
        assert_ne!(payment.payment_id(), other.payment_id());

        other = payment;
        other.nonce = [0x56u8; NONCE_LEN];
        assert_ne!(
            payment.payment_id(),
            other.payment_id(),
            "nonce binds the id"
        );
    }
}
