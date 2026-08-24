//! Core identifiers for the fixed 3-party MPCitH model.

use crate::error::MpcithError;

/// The concrete prime field used across the MPCitH layer: the ed25519
/// scalar field, matching `secret-sharing` and the default circuit
/// instantiation.
pub type FieldElement = ark_ed25519::Fr;

/// Number of virtual parties per repetition. Fixed by design; this is
/// *not* the n-party model of the `mpc` crate.
pub const PARTY_COUNT: u8 = 3;

/// Byte length of a view-commitment digest (SHA-256).
pub const DIGEST_LEN_MPCITH: usize = 32;

/// Byte length of per-view commitment randomness.
pub const RANDOMNESS_LEN_MPCITH: usize = 32;

/// Identifies one of the three virtual parties (values 0, 1, 2 only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartyId(u8);

impl PartyId {
    /// Creates a party id, rejecting anything outside `0..3`.
    pub fn new(value: u8) -> Result<Self, MpcithError> {
        if value >= PARTY_COUNT {
            return Err(MpcithError::InvalidChallenge);
        }
        Ok(Self(value))
    }

    /// Returns the underlying value (guaranteed `< 3`).
    pub fn get(self) -> u8 {
        self.0
    }

    /// The two parties that are not this one, in ascending order.
    pub fn others(self) -> [PartyId; 2] {
        match self.0 {
            0 => [Self(1), Self(2)],
            1 => [Self(0), Self(2)],
            _ => [Self(0), Self(1)],
        }
    }
}

/// Identifies one independent MPCitH repetition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RepetitionId(pub u32);

impl RepetitionId {
    /// Wraps a raw index as a repetition id.
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Returns the underlying index.
    pub fn get(self) -> u32 {
        self.0
    }
}

/// The verifier's per-repetition challenge: which single party's view
/// stays hidden while the other two are opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Challenge {
    /// The party whose view will NOT be opened.
    pub hidden_party: PartyId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn party_ids_accept_only_zero_one_two() {
        assert!(PartyId::new(0).is_ok());
        assert!(PartyId::new(1).is_ok());
        assert!(PartyId::new(2).is_ok());
        assert_eq!(PartyId::new(3).unwrap_err(), MpcithError::InvalidChallenge);
        assert_eq!(
            PartyId::new(255).unwrap_err(),
            MpcithError::InvalidChallenge
        );
    }

    #[test]
    fn others_cover_the_complement_in_order() {
        assert_eq!(
            PartyId::new(0).unwrap().others(),
            [PartyId::new(1).unwrap(), PartyId::new(2).unwrap()]
        );
        assert_eq!(
            PartyId::new(1).unwrap().others(),
            [PartyId::new(0).unwrap(), PartyId::new(2).unwrap()]
        );
        assert_eq!(
            PartyId::new(2).unwrap().others(),
            [PartyId::new(0).unwrap(), PartyId::new(1).unwrap()]
        );
    }

    #[test]
    fn repetition_ids_wrap_raw_values() {
        let id = RepetitionId::new(7);
        assert_eq!(id.get(), 7);
        assert_eq!(id, RepetitionId::new(7));
    }
}
