#![no_main]
//! Fuzzes `sdk::deserialize`: adversarial bytes must never panic and
//! must either decode to a valid [`Authorization`] or return
//! `Err`. Bounded memory: the decoder reads only the input slice plus
//! a small stack of fixed-size temporaries and never performs a
//! non-clamped allocation.

use libfuzzer_sys::fuzz_target;
use sdk::deserialize;

fuzz_target!(|data: &[u8]| {
    // The decoder's contract: well-formed bytes → Ok, anything else →
    // Err. It must never panic, never overflow, and never allocate
    // unboundedly. We don't act on the result beyond making sure the
    // call returns — panics are the failure mode the harness detects.
    let _ = deserialize(data);
});