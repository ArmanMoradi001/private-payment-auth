#![no_main]
use libfuzzer_sys::fuzz_target;
use secret_sharing::Share;

fuzz_target!(|data: &[u8]| {
    // Decoding arbitrary bytes must never panic; it may return Ok or Err.
    let _ = Share::decode(data);
});
