#![no_main]
use libfuzzer_sys::fuzz_target;
use proof::{deserialize_proof, Statement};

fuzz_target!(|data: &[u8]| {
    let _ = deserialize_proof(data);
    let _ = Statement::decode(data);
});
