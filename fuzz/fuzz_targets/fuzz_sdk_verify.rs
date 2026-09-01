#![no_main]
//! Fuzzes `sdk::verify` against random `Authorization` artifacts while
//! presenting a known-valid `(Payment, Policy)` context. The harness
//! feeds arbitrary bytes: if `sdk::deserialize` succeeds the resulting
//! artifact is passed to `verify`. The call must never panic, must
//! always terminate, and must never allocate unboundedly. Bounded
//! memory: the SDK verifier reads only the supplied slices plus a
//! small stack of fixed-size temporaries.

use crypto_core::{Digest, SecretBytes};
use libfuzzer_sys::fuzz_target;
use payment::{Amount, AmountUnit, Payment};
use policy::{credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK};
use sdk::{deserialize, Sdk, SdkConfig};

/// Builds a fixed, valid `(Payment, Policy)` pair the fuzz target
/// reuses across invocations. The policy is a 2-of-3 threshold plus
/// an `AmountAtMost(100)` cap; the payment amount is 75 cents.
/// Mirrors the in-crate fixtures.
fn context() -> (Payment, Policy) {
    let secrets: Vec<SecretBytes> = (0..3)
        .map(|i| SecretBytes::new(vec![(i as u8) + 1, 0x0c, 0x0d]))
        .collect();
    let members: Vec<Policy> = secrets
        .iter()
        .map(|s| Policy::Credential(CredentialId::from_commitment(credential_commitment(s))))
        .collect();
    let policy = Policy::And(vec![
        Policy::Threshold {
            k: ThresholdK::new(2),
            members,
        },
        Policy::AmountAtMost(AmountLimit::new(100)),
    ]);

    let payment = Payment {
        version: 1,
        payment_id: [0x42; 32],
        amount: Amount {
            value: 75,
            unit: AmountUnit::Cents,
        },
        recipient_commitment: Digest::new([0x11; 32]),
        nonce: [0x33; 32],
    };
    (payment, policy)
}

fuzz_target!(|data: &[u8]| {
    // 1. Try to decode the artifact. Decoding must be panic-free
    //    (already exercised by `fuzz_authorization_decode`); here we
    //    additionally exercise the verify path.
    let Ok(auth) = deserialize(data) else {
        return;
    };

    // 2. Run the verifier against a known-valid (Payment, Policy).
    //    The SDK is constructed with the SHA-256 backend (the only
    //    one this SDK build supports) and self_verify disabled so
    //    the harness does no extra proving work. The verify path is
    //    pure: it takes no witness and reads only public data.
    let (payment, policy) = context();
    let sdk = Sdk::new(SdkConfig::default());

    // The verifier may legitimately reject (`Invalid(...)`) or error
    // (`Err(...)`) on adversarial inputs; both are acceptable. What
    // is NOT acceptable is panicking, allocating unboundedly, or
    // hanging. The harness detects panics; bounded memory is upheld
    // by construction (the verifier reads only the supplied slices
    // plus small fixed-size temporaries).
    let _ = std::hint::black_box(sdk.verify(&payment, &policy, &auth));
});