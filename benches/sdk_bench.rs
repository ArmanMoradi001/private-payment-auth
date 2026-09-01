//! Criterion benchmarks for the SDK orchestration layer.
//!
//! These measurements characterize the public API a downstream
//! consumer actually pays for: `authorize`, `verify`, the round-trip,
//! the optional self-verify default, and the canonical serialization
//! for the produced artifact. They sit on top of the lower-level
//! payment/proof benchmarks already in the workspace, but they
//! reflect the *true* cost of the SDK workflow including binding
//! re-derivation and (when enabled) the independent re-verification
//! the SDK runs before returning an authorization.
//!
//! Recorded sizes (proof + header + binding fields) are written to
//! stdout at the end of the suite so the report can quote them
//! without rerunning.

use criterion::{criterion_group, criterion_main, Criterion};
use crypto_core::{CryptoBackend, Digest, SecretBytes, Sha256Backend};
use payment::{Amount, AmountUnit, Payment, PrivateWitness};
use policy::{credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sdk::{authorization_id, deserialize, serialize, Sdk, SdkConfig, VerificationResult};

const LIMIT: u64 = 100;
const SEED_AUTHORIZE: u64 = 7;
const SEED_BUILD_AUTH: u64 = 8;

/// Builds the canonical 2-of-3 threshold + 100-cent cap fixture used
/// across the SDK test suite. The returned witness satisfies the
/// policy for a 75-cent payment.
fn fixture() -> (Payment, Policy, PrivateWitness) {
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
        Policy::AmountAtMost(AmountLimit::new(LIMIT)),
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
    let witness = PrivateWitness::new(secrets, payment.amount, LIMIT);
    (payment, policy, witness)
}

/// Returns a default-config SDK (SHA-256 backend, self_verify = true).
fn sdk_default() -> Sdk {
    Sdk::new(SdkConfig::default())
}

/// Returns an SDK with self_verify disabled so we can isolate the
/// cost of `prove` from the cost of the optional follow-up verify.
fn sdk_no_self_verify() -> Sdk {
    let cfg = SdkConfig::new(
        SdkConfig::default().protocol_version(),
        Sha256Backend::ID,
        SdkConfig::default().repetitions(),
        false,
    );
    Sdk::new(cfg)
}

/// Generates one authorization artifact (self_verify enabled) using a
/// fresh seeded RNG.
fn build_authorization(
    sdk: &Sdk,
    payment: &Payment,
    policy: &Policy,
    witness: &PrivateWitness,
) -> sdk::Authorization {
    sdk.authorize(
        payment,
        policy,
        witness,
        &mut ChaCha20Rng::seed_from_u64(SEED_BUILD_AUTH),
    )
    .expect("authorize")
}

fn bench_authorize_with_self_verify(c: &mut Criterion) {
    let (payment, policy, witness) = fixture();
    let sdk = sdk_default();
    c.bench_function("sdk/authorize_with_self_verify", |b| {
        b.iter(|| {
            sdk.authorize(
                std::hint::black_box(&payment),
                std::hint::black_box(&policy),
                std::hint::black_box(&witness),
                &mut ChaCha20Rng::seed_from_u64(SEED_AUTHORIZE),
            )
            .expect("authorize")
        })
    });
}

fn bench_authorize_without_self_verify(c: &mut Criterion) {
    let (payment, policy, witness) = fixture();
    let sdk = sdk_no_self_verify();
    c.bench_function("sdk/authorize_without_self_verify", |b| {
        b.iter(|| {
            sdk.authorize(
                std::hint::black_box(&payment),
                std::hint::black_box(&policy),
                std::hint::black_box(&witness),
                &mut ChaCha20Rng::seed_from_u64(SEED_AUTHORIZE),
            )
            .expect("authorize")
        })
    });
}

fn bench_verify_only(c: &mut Criterion) {
    let (payment, policy, witness) = fixture();
    let sdk = sdk_default();
    let auth = build_authorization(&sdk, &payment, &policy, &witness);
    c.bench_function("sdk/verify_only", |b| {
        b.iter(|| {
            let result = sdk
                .verify(
                    std::hint::black_box(&payment),
                    std::hint::black_box(&policy),
                    std::hint::black_box(&auth),
                )
                .expect("verify");
            assert_eq!(result, VerificationResult::Valid);
            result
        })
    });
}

fn bench_serialize(c: &mut Criterion) {
    let (payment, policy, witness) = fixture();
    let sdk = sdk_default();
    let auth = build_authorization(&sdk, &payment, &policy, &witness);
    c.bench_function("sdk/serialize", |b| {
        b.iter(|| serialize(std::hint::black_box(&auth)))
    });
}

fn bench_deserialize(c: &mut Criterion) {
    let (payment, policy, witness) = fixture();
    let sdk = sdk_default();
    let auth = build_authorization(&sdk, &payment, &policy, &witness);
    let bytes = serialize(&auth);
    c.bench_function("sdk/deserialize", |b| {
        b.iter(|| deserialize(std::hint::black_box(&bytes)).expect("deserialize"))
    });
}

fn bench_identity(c: &mut Criterion) {
    let (payment, policy, witness) = fixture();
    let sdk = sdk_default();
    let auth = build_authorization(&sdk, &payment, &policy, &witness);
    c.bench_function("sdk/authorization_id", |b| {
        b.iter(|| authorization_id(std::hint::black_box(&auth)))
    });
}

/// Prints a one-shot artifact report on the first call. Criterion
/// invokes each benchmark function once during warmup before measuring,
/// so this is the cheapest place to emit a side-channel-free report.
fn report_once() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let (payment, policy, witness) = fixture();
        let sdk = sdk_default();
        let auth = build_authorization(&sdk, &payment, &policy, &witness);
        let bytes = serialize(&auth);
        eprintln!(
            "sdk_bench: artifact version={} protocol={} backend={:?} payment_id_prefix={:02x?} proof_reps={} bytes={}",
            auth.version(),
            auth.protocol_version(),
            auth.backend_id(),
            &auth.payment_id()[..4],
            auth.proof().repetitions().len(),
            bytes.len(),
        );
    });
}

/// Comparator bench: `prove` (no self-verify) vs `prove + self-verify`
/// (default) vs `verify-only`, all under the same fixture. This is
/// what the suite is for: a one-glance summary of the SDK's relative
/// costs. Criterion runs each function as a separate bench, so we
/// register them individually with descriptive names and let the
/// harness print them side-by-side.
fn bench_compare_pipeline(c: &mut Criterion) {
    report_once();
    let (payment, policy, witness) = fixture();
    let sdk_sv = sdk_default();
    let sdk_nv = sdk_no_self_verify();
    let auth = build_authorization(&sdk_sv, &payment, &policy, &witness);

    let mut group = c.benchmark_group("sdk/pipeline_compare");
    group.bench_function("prove_only", |b| {
        b.iter(|| {
            sdk_nv
                .authorize(
                    std::hint::black_box(&payment),
                    std::hint::black_box(&policy),
                    std::hint::black_box(&witness),
                    &mut ChaCha20Rng::seed_from_u64(SEED_AUTHORIZE),
                )
                .expect("authorize")
        })
    });
    group.bench_function("prove_plus_self_verify", |b| {
        b.iter(|| {
            sdk_sv
                .authorize(
                    std::hint::black_box(&payment),
                    std::hint::black_box(&policy),
                    std::hint::black_box(&witness),
                    &mut ChaCha20Rng::seed_from_u64(SEED_AUTHORIZE),
                )
                .expect("authorize")
        })
    });
    group.bench_function("verify_only", |b| {
        b.iter(|| {
            sdk_sv
                .verify(
                    std::hint::black_box(&payment),
                    std::hint::black_box(&policy),
                    std::hint::black_box(&auth),
                )
                .expect("verify")
        })
    });
    group.finish();
}

criterion_group!(
    benches,
    bench_authorize_with_self_verify,
    bench_authorize_without_self_verify,
    bench_verify_only,
    bench_serialize,
    bench_deserialize,
    bench_identity,
    bench_compare_pipeline,
);
criterion_main!(benches);
