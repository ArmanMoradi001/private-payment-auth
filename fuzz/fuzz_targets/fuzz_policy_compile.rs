#![no_main]
//! Fuzzes the decode→compile path: a decoded, valid policy must compile
//! (or report a clean `PolicyError`) without panicking. Catches crashes
//! in the circuit compiler on adversarial but well-formed policy trees.

use libfuzzer_sys::fuzz_target;
use ark_ed25519::Fr;
use policy::compile_with_layout;

fuzz_target!(|data: &[u8]| {
    if let Ok(bytes) = policy::decode(data) {
        let _ = compile_with_layout::<Fr>(&bytes);
    }
});
