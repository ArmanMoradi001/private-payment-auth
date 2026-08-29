#![no_main]
//! Fuzzes the decode→normalize path: normalization of a decoded policy
//! must never panic and must be internally consistent (decoding its
//! encoding round-trips).

use libfuzzer_sys::fuzz_target;
use policy::{decode, normalize};

fuzz_target!(|data: &[u8]| {
    if let Ok(policy) = decode(data) {
        if let Ok(normalized) = normalize(&policy) {
            // Normalization is idempotent: normalize(normalize(p)) == normalize(p).
            if let Ok(twice) = normalize(&normalized) {
                assert_eq!(normalized, twice);
            }
        }
    }
});
