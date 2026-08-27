#![no_main]
use libfuzzer_sys::fuzz_target;
use circuit::deserialize;
use ark_ed25519::Fr;

fuzz_target!(|data: &[u8]| {
    let _ = deserialize::<Fr>(data);
});
