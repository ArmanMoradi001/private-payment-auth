#![no_main]
//! Fuzzes `policy::decode`: adversarial bytes must never panic and must
//! either decode to a valid `Policy` or return `Err`.

use libfuzzer_sys::fuzz_target;
use policy::decode;

fuzz_target!(|data: &[u8]| {
    let _ = decode(data);
});
