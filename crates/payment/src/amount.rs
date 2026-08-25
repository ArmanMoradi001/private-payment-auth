//! Payment amounts with explicit integer units.
//!
//! An [`Amount`] is an exact `u64` count of a named [`AmountUnit`].
//! `u64::MAX` is the maximum representable amount. Conversion from
//! field elements is deliberately **not** provided: field values may
//! exceed or wrap around the `u64` range, and any amount that did not
//! originate as a `u64` must be rejected rather than silently reduced.
//! The range-check gadget (`policy::range_check`) proves in-circuit
//! that the committed field value lies within `[0, 2^64)` without ever
//! casting it.

use crypto_core::CanonicalEncode;

/// Current amount encoding version.
pub const AMOUNT_ENCODING_VERSION: u8 = 1;

/// The integer unit an [`Amount`] is denominated in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AmountUnit {
    /// Hundredths of the settlement currency.
    Cents,
}

impl AmountUnit {
    /// One-byte canonical tag for this unit.
    pub fn tag(self) -> u8 {
        match self {
            Self::Cents => 1,
        }
    }

    /// Parses a unit from its canonical tag.
    ///
    /// # Errors
    ///
    /// Returns [`AmountError::UnknownUnit`] for any byte other than a
    /// known tag.
    pub fn from_tag(tag: u8) -> Result<Self, AmountError> {
        match tag {
            1 => Ok(Self::Cents),
            _ => Err(AmountError::UnknownUnit),
        }
    }
}

/// An exact payment amount: a `u64` value plus its unit.
///
/// The maximum representable amount is `u64::MAX`. There is no
/// conversion from field elements; see the module documentation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Amount {
    /// The value in units of [`Self::unit`].
    pub value: u64,
    /// The denomination of `value`.
    pub unit: AmountUnit,
}

/// Errors produced by amount parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AmountError {
    /// Unknown unit tag.
    UnknownUnit,
    /// Encoding version mismatch.
    InvalidVersion,
    /// Truncated encoding.
    MalformedEncoding,
    /// Non-empty trailing bytes after a complete encoding.
    TrailingBytes,
}

impl core::fmt::Display for AmountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::UnknownUnit => "unknown amount unit",
            Self::InvalidVersion => "unsupported amount encoding version",
            Self::MalformedEncoding => "truncated amount encoding",
            Self::TrailingBytes => "trailing bytes after amount encoding",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for AmountError {}

impl Amount {
    /// Canonical encoding length: `version(u8) ‖ value(u64 BE) ‖ unit(u8)`.
    pub const ENCODED_LEN: usize = 1 + 8 + 1;

    /// Returns the canonical encoding:
    /// `version(u8) ‖ value(u64 BE) ‖ unit(u8)`.
    pub fn encode(&self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[0] = AMOUNT_ENCODING_VERSION;
        out[1..9].copy_from_slice(&self.value.to_be_bytes());
        out[9] = self.unit.tag();
        out
    }

    /// Parses the canonical encoding; rejects wrong versions and
    /// trailing bytes.
    ///
    /// # Errors
    ///
    /// - [`AmountError::MalformedEncoding`] for short inputs.
    /// - [`AmountError::InvalidVersion`] for unknown versions.
    /// - [`AmountError::UnknownUnit`] for unknown unit tags.
    /// - [`AmountError::TrailingBytes`] if more than
    ///   [`Amount::ENCODED_LEN`] bytes are supplied.
    pub fn decode(bytes: &[u8]) -> Result<Self, AmountError> {
        if bytes.len() < Self::ENCODED_LEN {
            return Err(AmountError::MalformedEncoding);
        }
        if bytes.len() > Self::ENCODED_LEN {
            return Err(AmountError::TrailingBytes);
        }
        if bytes[0] != AMOUNT_ENCODING_VERSION {
            return Err(AmountError::InvalidVersion);
        }
        let value = u64::from_be_bytes(bytes[1..9].try_into().expect("fixed width"));
        let unit = AmountUnit::from_tag(bytes[9])?;
        Ok(Self { value, unit })
    }
}

impl CanonicalEncode for Amount {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.encode());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_round_trips() {
        for value in [0u64, 1, 42, u64::MAX] {
            let amount = Amount {
                value,
                unit: AmountUnit::Cents,
            };
            let encoded = amount.encode();
            assert_eq!(encoded.len(), Amount::ENCODED_LEN);
            assert_eq!(Amount::decode(&encoded), Ok(amount));
        }
    }

    #[test]
    fn layout_is_exact() {
        let amount = Amount {
            value: 0x0102_0304_0506_0708,
            unit: AmountUnit::Cents,
        };
        assert_eq!(
            amount.encode(),
            [
                AMOUNT_ENCODING_VERSION,
                0x01,
                0x02,
                0x03,
                0x04,
                0x05,
                0x06,
                0x07,
                0x08,
                1, // Cents tag
            ]
        );
    }

    #[test]
    fn malformed_inputs_are_rejected() {
        let amount = Amount {
            value: 5,
            unit: AmountUnit::Cents,
        };
        let encoded = amount.encode();

        assert_eq!(
            Amount::decode(&encoded[..9]),
            Err(AmountError::MalformedEncoding)
        );
        assert_eq!(
            Amount::decode(&[encoded.as_slice(), &[0xff]].concat()),
            Err(AmountError::TrailingBytes)
        );
        let mut bad_version = encoded;
        bad_version[0] = 0xff;
        assert_eq!(
            Amount::decode(&bad_version),
            Err(AmountError::InvalidVersion)
        );
        let mut bad_unit = encoded;
        bad_unit[9] = 0xff;
        assert_eq!(Amount::decode(&bad_unit), Err(AmountError::UnknownUnit));
    }

    #[test]
    fn max_value_is_representable() {
        // u64::MAX is the documented ceiling; it must encode/decode
        // exactly with no clamping or wrapping.
        let max = Amount {
            value: u64::MAX,
            unit: AmountUnit::Cents,
        };
        assert_eq!(Amount::decode(&max.encode()), Ok(max));
    }
}
