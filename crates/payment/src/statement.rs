//! The public payment statement.
//!
//! A [`PaymentStatement`] identifies a payment, its amount, its
//! recipient, and the policy under which it requests authorization. It
//! is pure public data with a canonical, injective encoding so it can
//! be hashed, logged, and compared safely.

use crypto_core::{CanonicalEncode, Digest};
use policy::PolicyId;

/// Current payment-statement encoding version.
pub const STATEMENT_VERSION: u8 = 1;

/// Byte length of a payment identifier.
pub const PAYMENT_ID_LEN: usize = 32;

/// Public description of the payment being authorized.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentStatement {
    /// Unique identifier of this payment.
    pub payment_id: [u8; PAYMENT_ID_LEN],
    /// The amount to transfer.
    pub amount: u64,
    /// Commitment binding the payment to its intended recipient.
    pub recipient_commitment: Digest,
    /// The [`policy::PolicyId`] this payment is authorized under.
    pub policy_id: PolicyId,
}

impl PaymentStatement {
    /// Returns the canonical encoding of this statement.
    ///
    /// Layout:
    /// `version(u8) ‖ payment_id(32B) ‖ amount(u64 BE) ‖
    /// recipient_commitment(32B) ‖ policy_id(32B)` — fixed width and
    /// injective.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 32 + 8 + 32 + 32);
        self.encode_into(&mut out);
        out
    }

    /// Appends the canonical encoding to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(STATEMENT_VERSION);
        out.extend_from_slice(&self.payment_id);
        out.extend_from_slice(&self.amount.to_be_bytes());
        self.recipient_commitment.encode(out);
        CanonicalEncode::encode(&self.policy_id, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(amount: u64) -> PaymentStatement {
        PaymentStatement {
            payment_id: [7u8; PAYMENT_ID_LEN],
            amount,
            recipient_commitment: Digest::new([0xaa; 32]),
            policy_id: PolicyId::from_digest(Digest::new([0x11; 32])),
        }
    }

    #[test]
    fn encoding_is_deterministic_and_fixed_width() {
        let statement = sample(1234);
        assert_eq!(statement.encode(), statement.encode());
        assert_eq!(statement.encode().len(), 1 + 32 + 8 + 32 + 32);
    }

    #[test]
    fn distinct_statements_have_distinct_encodings() {
        let base = sample(100);
        let variants = [
            sample(101),
            PaymentStatement { payment_id: [8u8; PAYMENT_ID_LEN], ..base.clone() },
            PaymentStatement {
                recipient_commitment: Digest::new([0xbb; 32]),
                ..base.clone()
            },
            PaymentStatement {
                policy_id: PolicyId::from_digest(Digest::new([0x22; 32])),
                ..base.clone()
            },
        ];
        for variant in &variants {
            assert_ne!(base.encode(), variant.encode());
        }
    }
}
