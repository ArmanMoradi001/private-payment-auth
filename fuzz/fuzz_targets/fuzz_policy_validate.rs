#![no_main]
//! Fuzzes the decode→validate path: a successfully decoded policy must
//! validate (or report a clean `PolicyError`) without panicking.

use libfuzzer_sys::fuzz_target;
use policy::{decode, validate};

fuzz_target!(|data: &[u8]| {
    if let Ok(policy) = decode(data) {
        let _ = validate(&policy);
    }
});
