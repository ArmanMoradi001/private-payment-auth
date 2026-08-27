#![no_main]
use libfuzzer_sys::fuzz_target;
use payment::{Amount, PaymentStatement};

fuzz_target!(|data: &[u8]| {
    let _ = Amount::decode(data);
    let _ = PaymentStatement::decode(data);
});
