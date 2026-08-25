//! The public payment statement being authorized.
//!
//! A [`PaymentStatement`] binds the semantic payment id, amount,
//! recipient commitment, and replay-protection nonce to the policy and
//! circuit under which authorization is requested. It is pure public
//! data with a fixed-width injective canonical encoding; decoding is
//! strict — wrong versions, truncation, and trailing bytes are all
//! rejected.

use circuit::CircuitId;
use crypto_core::Digest;
use policy::PolicyId;

use crate::amount::{Amount, AmountError};

/// Current statement-encoding version.
///
/// Phase 8 replaced the phase 7 layout (raw `u64` amount, no
/// circuit/protocol binding) with the layout below.
pub const STATEMENT_VERSION: u8 = 2;

/// Byte length of the nonce.
pub const NONCE_LEN: usize = 32;

/// Public description of the payment being authorized.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PaymentStatement {
    /// Semantic payment id (see [`crate::payment::Payment::payment_id`]).
    pub payment_id: Digest,
    /// The amount being paid.
    pub amount: Amount,
    /// Commitment binding the payment to its intended recipient.
    pub recipient_commitment: Digest,
    /// The policy this payment is authorized under.
    pub policy_id: PolicyId,
    /// The compiled policy circuit the proof attests. Must equal the
    /// circuit rebuilt by the verifier.
    pub circuit_id: CircuitId,
    /// The proof protocol version the artifact targets.
    pub protocol_version: u8,
    /// Fresh per-statement randomness for replay protection.
    pub nonce: [u8; NONCE_LEN],
}

impl PaymentStatement {
    /// Fixed canonical encoding length.
    pub const ENCODED_LEN: usize = 1
        + 32 // payment_id
        + Amount::ENCODED_LEN
        + 32 // recipient_commitment
        + 32 // policy_id
        + 32 // circuit_id
        + 1 // protocol_version
        + NONCE_LEN;

    /// Returns the canonical encoding of this statement.
    ///
    /// Layout:
    /// `version(u8) ‖ payment_id(32B) ‖ amount(10B) ‖
    /// recipient_commitment(32B) ‖ policy_id(32B) ‖ circuit_id(32B) ‖
    /// protocol_version(u8) ‖ nonce(32B)`.
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        let mut offset = 0;
        out[offset] = STATEMENT_VERSION;
        offset += 1;
        out[offset..offset + 32].copy_from_slice(self.payment_id.as_bytes());
        offset += 32;
        let encoded_amount = self.amount.encode();
        out[offset..offset + encoded_amount.len()].copy_from_slice(&encoded_amount);
        offset += encoded_amount.len();
        out[offset..offset + 32].copy_from_slice(self.recipient_commitment.as_bytes());
        offset += 32;
        out[offset..offset + 32].copy_from_slice(self.policy_id.as_digest().as_bytes());
        offset += 32;
        out[offset..offset + 32].copy_from_slice(self.circuit_id.as_digest().as_bytes());
        offset += 32;
        out[offset] = self.protocol_version;
        offset += 1;
        out[offset..offset + NONCE_LEN].copy_from_slice(&self.nonce);
        out
    }

    /// Parses a statement, rejecting unknown versions, truncation, and
    /// trailing bytes.
    ///
    /// # Errors
    ///
    /// - [`StatementError::MalformedEncoding`] for short inputs.
    /// - [`StatementError::InvalidVersion`] for unknown versions.
    /// - [`AmountError`] variants propagated from amount parsing.
    /// - [`StatementError::TrailingBytes`] if extra bytes remain.
    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() < Self::ENCODED_LEN {
            return Err(StatementError::MalformedEncoding);
        }
        if bytes.len() > Self::ENCODED_LEN {
            return Err(StatementError::TrailingBytes);
        }
        let mut cursor = 0;
        let version = bytes[cursor];
        cursor += 1;
        if version != STATEMENT_VERSION {
            return Err(StatementError::InvalidVersion);
        }
        let payment_id =
            Digest::from(<[u8; 32]>::try_from(&bytes[cursor..cursor + 32]).expect("fixed"));
        cursor += 32;
        let amount = Amount::decode(&bytes[cursor..cursor + Amount::ENCODED_LEN])?;
        cursor += Amount::ENCODED_LEN;
        let recipient_commitment =
            Digest::from(<[u8; 32]>::try_from(&bytes[cursor..cursor + 32]).expect("fixed"));
        cursor += 32;
        let policy_id = PolicyId::from_digest(Digest::from(
            <[u8; 32]>::try_from(&bytes[cursor..cursor + 32]).expect("fixed"),
        ));
        cursor += 32;
        let circuit_id = CircuitId::from_digest(Digest::from(
            <[u8; 32]>::try_from(&bytes[cursor..cursor + 32]).expect("fixed"),
        ));
        cursor += 32;
        let protocol_version = bytes[cursor];
        cursor += 1;
        let nonce = <[u8; NONCE_LEN]>::try_from(&bytes[cursor..cursor + NONCE_LEN]).expect("fixed");
        Ok(Self {
            payment_id,
            amount,
            recipient_commitment,
            policy_id,
            circuit_id,
            protocol_version,
            nonce,
        })
    }
}

/// Errors produced by statement parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatementError {
    /// Unknown encoding version.
    InvalidVersion,
    /// Truncated encoding.
    MalformedEncoding,
    /// Non-empty trailing bytes after a complete statement.
    TrailingBytes,
    /// Invalid amount payload.
    InvalidAmount(AmountError),
}

impl core::fmt::Display for StatementError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidVersion => f.write_str("unsupported statement version"),
            Self::MalformedEncoding => f.write_str("truncated statement encoding"),
            Self::TrailingBytes => f.write_str("trailing bytes after statement"),
            Self::InvalidAmount(err) => write!(f, "invalid amount: {err}"),
        }
    }
}

impl std::error::Error for StatementError {}

impl From<AmountError> for StatementError {
    fn from(err: AmountError) -> Self {
        match err {
            AmountError::InvalidVersion => Self::InvalidVersion,
            AmountError::MalformedEncoding => Self::MalformedEncoding,
            other => Self::InvalidAmount(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::AmountUnit;

    fn sample() -> PaymentStatement {
        PaymentStatement {
            payment_id: Digest::new([1u8; 32]),
            amount: Amount {
                value: 4242,
                unit: AmountUnit::Cents,
            },
            recipient_commitment: Digest::new([2u8; 32]),
            policy_id: PolicyId::from_digest(Digest::new([3u8; 32])),
            circuit_id: CircuitId::from_digest(Digest::new([4u8; 32])),
            protocol_version: 1,
            nonce: [9u8; NONCE_LEN],
        }
    }

    #[test]
    fn round_trips_and_is_fixed_width() {
        let statement = sample();
        assert_eq!(statement.encode().len(), PaymentStatement::ENCODED_LEN);
        assert_eq!(PaymentStatement::decode(&statement.encode()), Ok(statement));
    }

    #[test]
    fn distinct_fields_change_the_encoding() {
        let base = sample();
        let mutations = [
            PaymentStatement {
                payment_id: Digest::new([0xff; 32]),
                ..base
            },
            PaymentStatement {
                amount: Amount {
                    value: base.amount.value + 1,
                    unit: AmountUnit::Cents,
                },
                ..base
            },
            PaymentStatement {
                recipient_commitment: Digest::new([0xff; 32]),
                ..base
            },
            PaymentStatement {
                policy_id: PolicyId::from_digest(Digest::new([0xff; 32])),
                ..base
            },
            PaymentStatement {
                circuit_id: CircuitId::from_digest(Digest::new([0xff; 32])),
                ..base
            },
            PaymentStatement {
                protocol_version: base.protocol_version + 1,
                ..base
            },
            PaymentStatement {
                nonce: [0xff; NONCE_LEN],
                ..base
            },
        ];
        let base_bytes = base.encode();
        for mutation in &mutations {
            assert_ne!(mutation.encode(), base_bytes);
            assert_eq!(PaymentStatement::decode(&mutation.encode()), Ok(*mutation));
        }
    }

    #[test]
    fn rejects_malformed_and_trailing_bytes() {
        let encoded = sample().encode();

        assert_eq!(
            PaymentStatement::decode(&encoded[..PaymentStatement::ENCODED_LEN - 1]),
            Err(StatementError::MalformedEncoding)
        );
        let mut trailing = encoded.to_vec();
        trailing.push(0u8);
        assert_eq!(
            PaymentStatement::decode(&trailing),
            Err(StatementError::TrailingBytes)
        );

        let mut bad_version = encoded;
        bad_version[0] = 0xfe;
        assert_eq!(
            PaymentStatement::decode(&bad_version),
            Err(StatementError::InvalidVersion)
        );

        // Corrupting the nested amount's unit tag surfaces as an
        // amount error mapped into the statement error type.
        let mut bad_amount = encoded;
        bad_amount[1 + 32 + 9] = 0xff;
        assert_eq!(
            PaymentStatement::decode(&bad_amount),
            Err(StatementError::InvalidAmount(AmountError::UnknownUnit))
        );
    }
}
