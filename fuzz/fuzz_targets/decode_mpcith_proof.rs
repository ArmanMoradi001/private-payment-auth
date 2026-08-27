#![no_main]
use libfuzzer_sys::fuzz_target;
use mpcith::decode_proof;

fuzz_target!(|data: &[u8]| {
    let _ = decode_proof(data);
});
