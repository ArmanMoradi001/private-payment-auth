# MPC Payment

A cryptographic payment authorization project built on secure
multi-party computation principles.

**Status: Phase 12 — Public SDK, end-to-end tests, fuzzing,
benchmarks, and architecture documentation.**

The workspace now provides a stable public SDK (`crates/sdk`) that
turns `(Payment, Policy, PrivateWitness)` into an immutable,
self-contained `Authorization` artifact, plus a witness-free
verifier that downstream consumers can run independently. The
lower-level crates (`crypto-core`, `secret-sharing`, `mpc`, `mpcith`,
`circuit`, `policy`, `payment`, `proof`, `verifier`) implement the
MPCitH authorization pipeline; the SDK is the orchestration layer
on top.

## Purpose

This project provides cryptographic payment authorization built on
secure multi-party computation (MPC) principles: a payment is
authorized by producing a proof that a set of parties jointly
evaluated the authorization policy over secret inputs, without
revealing those inputs.

## Philosophy

Security-first: correctness, constant-time operations, and audited
dependencies take priority over performance and features. Every
change is gated by format checks, strict lints, tests in debug and
release modes, dependency auditing, and license/policy enforcement
via `cargo deny`. Panics in decoders are treated as bugs; the SDK
decoder rejects malformed input with `Err`, never via `unwrap`.

## Layout

- `crates/sdk` — public SDK: `authorize`/`verify`/`serialize`/`deserialize`
- `crates/payment` — payment domain types and end-to-end pipeline
- `crates/policy` — typed policy AST, normalization, evaluator, compiler
- `crates/proof` — non-interactive proof interface and backend binding
- `crates/mpcith` — MPC-in-the-Head construction (3-party model)
- `crates/mpc` — additive-sharing MPC layer over the ed25519 scalar field
- `crates/circuit` — arithmetic DAG circuit representation
- `crates/crypto-core` — primitives: hashing, commitments, secret containers
- `crates/secret-sharing` — Shamir secret sharing
- `crates/verifier` — standalone verification entry point
- `tests/*` — integration, property, adversarial, and SDK tests
- `benches/*` — Criterion benchmarks
- `fuzz/*` — cargo-fuzz targets (decode paths + verify path)
- `docs/` — architecture, decisions (ADRs), threat model
- `.github/workflows/ci.yml` — CI pipeline
- `deny.toml`, `clippy.toml`, `rustfmt.toml` — lint/licensing policy
- `rust-toolchain.toml` — pinned stable toolchain with `rustfmt` and `clippy`

## Quick start

```toml
[dependencies]
sdk = { path = "crates/sdk" }
payment = { path = "crates/payment" }
policy = { path = "crates/policy" }
crypto-core = { path = "crates/crypto-core" }
rand_chacha = "0.3"
rand_core = "0.6"
```

```rust,no_run
use crypto_core::{Digest, SecretBytes};
use payment::{Amount, AmountUnit, Payment, PrivateWitness};
use policy::{credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sdk::{serialize, Sdk, SdkConfig, VerificationResult};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a 2-of-3 threshold + 100-cent-cap policy.
    let secrets: Vec<SecretBytes> = (0..3)
        .map(|i| SecretBytes::new(vec![(i as u8) + 1, 0x0c, 0x0d]))
        .collect();
    let members: Vec<Policy> = secrets
        .iter()
        .map(|s| Policy::Credential(CredentialId::from_commitment(credential_commitment(s))))
        .collect();
    let policy = Policy::And(vec![
        Policy::Threshold { k: ThresholdK::new(2), members },
        Policy::AmountAtMost(AmountLimit::new(100)),
    ]);

    let payment = Payment {
        version: 1,
        payment_id: [0x42; 32],
        amount: Amount { value: 75, unit: AmountUnit::Cents },
        recipient_commitment: Digest::new([0x11; 32]),
        nonce: [0x33; 32],
    };
    let witness = PrivateWitness::new(secrets, payment.amount, 100);

    // Authorize.
    let sdk = Sdk::new(SdkConfig::default());
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk.authorize(&payment, &policy, &witness, &mut rng)?;

    // Verify (no witness required).
    match sdk.verify(&payment, &policy, &auth)? {
        VerificationResult::Valid => println!("authorization verified"),
        VerificationResult::Invalid(why) => println!("rejected: {why:?}"),
    }

    // Persist or transmit.
    let bytes = serialize(&auth);
    println!("serialized {} bytes", bytes.len());

    Ok(())
}
```

See [`docs/architecture/sdk.md`](docs/architecture/sdk.md) for the
full SDK surface, lifecycle, binding rules, and limitations, and
[`docs/decisions/0012-sdk-public-boundary.md`](docs/decisions/0012-sdk-public-boundary.md)
for the design rationale.