//! Property-based tests for canonical encoding and commitments.

use crypto_core::{commit, open, CanonicalEncode, CommitmentRandomness, Sha256Backend};
use proptest::prelude::*;

prop_compose! {
    fn arb_randomness()(bytes in prop::collection::vec(any::<u8>(), 32)) -> CommitmentRandomness {
        CommitmentRandomness::new(bytes.into()).expect("32 bytes")
    }
}

proptest! {
    #[test]
    fn valid_commitment_always_opens(
        message in prop::collection::vec(any::<u8>(), 0..512),
        randomness in arb_randomness(),
    ) {
        let commitment = commit::<Sha256Backend>(&message, &randomness);
        prop_assert!(open::<Sha256Backend>(&commitment, &message, &randomness));
    }

    #[test]
    fn modified_message_fails_to_open(
        message in prop::collection::vec(any::<u8>(), 1..512),
        index in any::<usize>(),
        byte in any::<u8>(),
        randomness in arb_randomness(),
    ) {
        let mut modified = message.clone();
        let i = index % modified.len();
        if modified[i] == byte {
            modified[i] = byte ^ 0x01;
        } else {
            modified[i] = byte;
        }
        let commitment = commit::<Sha256Backend>(&message, &randomness);
        prop_assert!(!open::<Sha256Backend>(&commitment, &modified, &randomness));
    }

    #[test]
    fn encoding_round_trip_preserves_values(
        bytes in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let mut encoded = Vec::new();
        (&bytes[..]).encode(&mut encoded);

        // Manually decode: 4-byte BE length prefix followed by the payload.
        prop_assert!(encoded.len() >= 4);
        let len = u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;
        prop_assert_eq!(len, bytes.len());
        prop_assert_eq!(&encoded[4..], &bytes[..]);

        // Encoding is deterministic.
        let mut again = Vec::new();
        (&bytes[..]).encode(&mut again);
        prop_assert_eq!(encoded, again);
    }
}
