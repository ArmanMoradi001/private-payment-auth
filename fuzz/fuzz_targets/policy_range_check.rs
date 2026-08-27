#![no_main]
use libfuzzer_sys::fuzz_target;
use payment::range_check::reference_range_check;

fuzz_target!(|data: &[u8]| {
    // Derive two u64s from the fuzz input and exercise the range-check
    // boundary. This path has no decoder, so we fuzz the numeric boundary
    // directly to ensure it never panics on adversarial inputs.
    if data.len() >= 16 {
        let mut v = [0u8; 8];
        let mut l = [0u8; 8];
        v.copy_from_slice(&data[0..8]);
        l.copy_from_slice(&data[8..16]);
        let _ = reference_range_check(u64::from_le_bytes(v), u64::from_le_bytes(l));
    }
});
