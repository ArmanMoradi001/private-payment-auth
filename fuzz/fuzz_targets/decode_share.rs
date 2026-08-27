#![no_main]
use libfuzzer_sys::fuzz_target;
use secret_sharing::Share;
use ark_ed25519::Fr;

fuzz_target!(|data: &[u8]| {
    // Decoding arbitrary bytes must never panic; it may return Ok or Err.
    let _ = Share::<Fr>::decode(data);
});
