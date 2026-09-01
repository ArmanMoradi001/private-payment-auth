# SDK Architecture

> **Status: Phase 12 — public SDK, end-to-end tests, adversarial tests,
> property tests, fuzzing, benchmarks, and architecture documentation.**
> The `sdk` crate is the project's single stable public entry point. It
> is a thin orchestration layer over `payment`, `policy`, `proof`,
> `mpcith`, `mpc`, and `crypto-core` and does not introduce any new
> cryptographic primitive, MPC protocol, or proof system.

## Purpose

The SDK turns the workspace's lower-level building blocks into a
small, well-typed surface that downstream consumers can rely on for
the two real workflows they care about:

1. **Prove**: given a `(Payment, Policy, PrivateWitness)`, produce
   an immutable [`Authorization`] artifact attesting that the
   witness satisfies the policy under the bound payment.
2. **Verify**: given a `(Payment, Policy, Authorization)`, decide
   whether the artifact is sound — without ever needing the witness.

The SDK is the *only* path through which applications should access
the cryptographic pipeline. The lower-level crates are exposed
internally for testing and orchestration but are not part of the
documented stable surface; see [dependency-boundaries.md](dependency-boundaries.md).

## Recommended public API

```text
sdk::Sdk                 — orchestration object (holds an SdkConfig)
sdk::SdkConfig           — frozen configuration (backend, self-verify, ...)
sdk::Sdk::authorize      — produce an Authorization
sdk::Sdk::verify         — validate an Authorization against (Payment, Policy)
sdk::Authorization       — immutable artifact (proof + bindings)
sdk::serialize           — canonical byte encoding
sdk::deserialize         — strict decoder
sdk::authorization_id    — domain-separated semantic id of an Authorization
sdk::SdkError            — high-level error enum
sdk::VerificationResult  — Valid / Invalid(VerificationFailure)
sdk::VerificationFailure — PaymentMismatch, PolicyMismatch, ...
sdk::AUTHORIZATION_VERSION, sdk::SUPPORTED_PROTOCOL_VERSIONS
```

This is the full surface a downstream application needs; everything
else (`payment::*`, `policy::*`, `proof::*`) is reachable only
through internal crates and is **not** part of the stable
contract.

### A minimal end-to-end example

```rust,no_run
use crypto_core::{Digest, SecretBytes};
use payment::{Amount, AmountUnit, Payment, PrivateWitness};
use policy::{credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sdk::{serialize, Sdk, SdkConfig, VerificationResult};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build the policy: 2-of-3 threshold + 100-cent cap.
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

    // 2. Build the payment record.
    let payment = Payment {
        version: 1,
        payment_id: [0x42; 32],
        amount: Amount { value: 75, unit: AmountUnit::Cents },
        recipient_commitment: Digest::new([0x11; 32]),
        nonce: [0x33; 32],
    };

    // 3. The satisfying witness (the credential secrets).
    let witness = PrivateWitness::new(secrets, payment.amount, 100);

    // 4. Authorize.
    let sdk = Sdk::new(SdkConfig::default());
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk.authorize(&payment, &policy, &witness, &mut rng)?;

    // 5. The verifier only needs (Payment, Policy, Authorization) — no witness.
    match sdk.verify(&payment, &policy, &auth)? {
        VerificationResult::Valid => println!("authorization verified"),
        VerificationResult::Invalid(why) => println!("rejected: {why:?}"),
    }

    // 6. Persist or transmit the artifact.
    let bytes = serialize(&auth);
    println!("serialized {} bytes", bytes.len());

    Ok(())
}
```

## Verification workflow

Verification is independent and pure: it takes **no witness, no
secret material, and no RNG**. It is the function a payment receiver,
a merchant, or an auditor runs to decide whether to accept a payment
authorization.

```text
verify(payment, policy, authorization)
   │
   ├── 1. Backend alignment: authorization.backend_id == config.backend_id ?
   │       ↳ mismatch → Err(SdkError::BackendMismatch)
   │       ↳ unknown   → Err(SdkError::BackendUnsupported)
   │
   ├── 2. Artifact version stamp == AUTHORIZATION_VERSION ?
   │       ↳ no → Invalid(VersionMismatch)
   │
   ├── 3. Recompute policy_id(policy) and circuit_id(policy) from the
   │      supplied (normalized) policy. Compare to the artifact's
   │      recorded policy_id / circuit_id.
   │       ↳ disagreement → Invalid(PolicyMismatch) / CircuitMismatch
   │
   ├── 4. authorization.payment_id == payment.payment_id ?
   │       ↳ no → Invalid(PaymentMismatch)
   │
   └── 5. Delegate the cryptographic check to payment::verify_payment_authorization,
          which rebuilds the statement, compiles the circuit from the
          (normalized) policy, and runs the underlying proof::Verifier.
           ↳ failure → Invalid(ProofInvalid)
           ↳ success → Valid
```

The checks happen in this fixed order. Every binding field is
checked *before* any cryptographic work, so the verifier fails fast
on tampered metadata without burning cycles on a doomed proof
verification. This is documented and exercised by
`tests/sdk_adversarial_tests.rs`.

## Authorization lifecycle

The `Authorization` artifact is the unit of transfer between parties
who do not share secrets.

1. **Generation** — `Sdk::authorize(payment, policy, witness, rng)`
   returns an `Authorization`. Generation includes an optional
   self-verification step (`SdkConfig::self_verify`, default `true`)
   that re-runs the verifier on the freshly built artifact to catch
   pipeline-internal inconsistencies before the artifact leaves the
   prover.
2. **Serialization** — `serialize(&auth)` produces a
   deterministic byte vector with no secret material. The layout is
   documented in [`crates/sdk/src/encoding.rs`][encoding].
3. **Deserialization** — `deserialize(bytes)` is strict: any
   truncation, trailing byte, unknown version, unknown backend, or
   malformed inner proof is rejected with an `SdkError`. The decoder
   never panics and never allocates unboundedly.
4. **Verification** — `Sdk::verify(payment, policy, &auth)` returns
   `VerificationResult::Valid` or `Invalid(VerificationFailure)`.
   This call is pure and stateless.
5. **Identity** — `authorization_id(&auth)` returns a domain-separated
   SHA-256 digest over the canonical encoding. Two authorizations
   share an id exactly when they bind the same payment/policy/circuit
   to the same proof under the same protocol/backend.

[encoding]: ../../crates/sdk/src/encoding.rs

## Artifact structure

The artifact is a fixed-layout, secret-free bundle:

| Field             | Width       | Source                                  |
|-------------------|-------------|------------------------------------------|
| `version`         | 1 byte      | Always `AUTHORIZATION_VERSION`           |
| `protocol_version`| 1 byte      | `SdkConfig::protocol_version()`          |
| `backend_id`      | 16 bytes    | The `BackendId` the proof was produced with |
| `payment_id`      | 32 bytes    | `Payment::payment_id` (semantic id)      |
| `policy_id`       | 32 bytes    | `Policy::policy_id` of the normalized policy |
| `circuit_id`      | 32 bytes    | `payment_circuit_id(normalized policy)`  |
| `proof`           | variable    | The MPCitH non-interactive proof         |

The total serialized size is `114 + |proof|`. With the workspace
default of 12 Fiat–Shamir repetitions on the canonical 2-of-3 +
amount-cap fixture, the proof occupies ≈17.9 MB; this is the number
recorded by `benches/sdk_bench.rs`.

The artifact contains **no secret material** by design: every secret
input was absorbed into MPCitH view commitments inside the proof,
and the proof redacts its hidden material in `Debug`.

## Binding rules

Each authorization is cryptographically bound to:

- **A payment** — the proof's Fiat–Shamir transcript includes the
  payment id, amount, recipient commitment, and nonce; the artifact
  records `payment_id` for fast rejection.
- **A policy** — the artifact records `policy_id`; the verifier
  recomputes it from the supplied policy and rejects on mismatch
  *before* attempting proof verification.
- **A circuit** — the artifact records `circuit_id`; the verifier
  recompiles the policy and rejects on mismatch.
- **A backend** — both the artifact and the SDK config must point at
  the same `BackendId`; cross-backend submission is a hard
  configuration error (`BackendMismatch`), never silently accepted.
- **A protocol version** — encoded in the artifact and enforced by
  the decoder (`SUPPORTED_PROTOCOL_VERSIONS`).
- **An artifact version** — encoded in the artifact and enforced by
  the decoder (`AUTHORIZATION_VERSION`); bumped whenever the
  on-the-wire layout changes incompatibly.

## Replay semantics

Replays are defeated *cryptographically* at the protocol level: the
proof is bound to a specific `(payment, policy, nonce, …)` tuple, so
the same proof bytes never verify under a different statement — even
one differing only in nonce.

Freshness enforcement beyond that (preventing the *same* artifact
from being presented twice for the *same* payment) is an
**application-layer concern** that is *not* part of the SDK's
contract. A payment receiver should track observed authorizations
(typically keyed by `authorization_id(payment, policy, auth)`) and
reject duplicates. See
[0012-sdk-public-boundary.md](../decisions/0012-sdk-public-boundary.md)
for the rationale.

## Compatibility rules

The artifact decoders reject unknown versions and unknown backends
with hard errors rather than silently guessing:

- **Artifact version** mismatch → `SdkError::VersionUnsupported`.
- **Protocol version** outside `SUPPORTED_PROTOCOL_VERSIONS`
  → `SdkError::VersionUnsupported`.
- **Backend id** outside `proof::encoding::SUPPORTED_BACKEND_IDS`
  → `SdkError::BackendUnsupported`.

There is no silent upgrade or downgrade path. A newer artifact is
rejected by an older decoder (safe), and an older artifact is
rejected by a newer decoder only when its version stamps are
explicitly retired (deliberate, opt-in). See ADR
[0012](../decisions/0012-sdk-public-boundary.md).

## Public / private boundaries

| Symbol                                  | Visibility | Notes |
|-----------------------------------------|------------|-------|
| `sdk::Sdk`                              | public     |       |
| `sdk::Sdk::authorize`, `verify`         | public     |       |
| `sdk::Sdk::authorize_sha256`, etc.      | public     | Convenience wrappers |
| `sdk::Sdk::authorize_with::<B>`         | public     | Generic; backend dispatch |
| `sdk::Sdk::verify_with::<B>`            | public     | Generic; backend dispatch |
| `sdk::SdkConfig` and all its getters    | public     |       |
| `sdk::Authorization`, all getters      | public     | Immutable after construction |
| `sdk::serialize` / `deserialize`        | public     | Canonical encoding |
| `sdk::authorization_id` / `AuthorizationId` | public |       |
| `sdk::SdkError`, `VerificationResult`, `VerificationFailure` | public |       |
| `sdk::SUPPORTED_PROTOCOL_VERSIONS`, `AUTHORIZATION_VERSION` | public | |
| `crates::payment::*`, `policy::*`, etc. | internal   | Not stable; reachable via path deps but not re-exported |

`Authorization`'s fields are private and exposed only through
getters; the SDK refuses to expose mutable references. Constructors
are limited to `Authorization::new`, which exists for the SDK's own
test code but accepts any combination of values, so callers who
construct one manually can no longer claim the artifact is genuine
— they should treat anything not produced by `Sdk::authorize` as
adversarial.

## Self-verification

The default `SdkConfig` enables `self_verify = true`, so
`Sdk::authorize` runs an *independent* `Sdk::verify` on the freshly
produced artifact before returning it. This is a defense-in-depth
check: any inconsistency between the prove path and the verify
path inside the same SDK build surfaces as
`SdkError::SelfVerificationFailed` instead of being silently
emitted.

Cost: the self-verify step is one full proof verification (see
`benches/sdk_bench.rs` for measurements — typically a fraction of
the prove cost on the canonical fixture). Applications that need
maximum throughput and can tolerate the (very low) risk of a
pipeline bug can disable it via `SdkConfig::new(..., false)`. The
property tests (`tests/sdk_property_tests.rs`) and the adversarial
tests both exercise the default-on behavior.

## Limitations

- **SHA-256 only.** The current SDK build supports only the
  `Sha256Backend`; selecting the SHAKE256 backend at the config
  level returns `BackendUnsupported`. The protocol already binds
  backends so a future SHAKE256 build can be deployed without
  disturbing the SHA-256 build.
- **No replay ledger.** Duplicate detection is application-layer;
  the SDK will re-verify the same artifact indefinitely.
- **No signature on the artifact.** The proof itself is the only
  authentication; there is no external signature on the binding
  fields. A trusted relay could swap `(payment, policy)` for another
  pair the verifier expects, but the proof's Fiat–Shamir binding
  prevents it from producing a valid alternative.
- **In-circuit credential binding is still a placeholder.** The
  commitment digest is compared inside the circuit as a stand-in for
  an arithmetizable hash; see the [threat
  model](../security/threat-model.md) for the full discussion.
- **Large artifact size.** A 12-repetition proof on the canonical
  fixture occupies ≈17.9 MB. Production deployments needing
  smaller artifacts should reduce `DEFAULT_REPETITIONS` only after
  an explicit soundness/cost tradeoff study.

See ADR [0012](../decisions/0012-sdk-public-boundary.md) and the
[threat model](../security/threat-model.md) for the full design
discussion and the SDK's place in the project's security posture.