# MPC Payment — Privacy-Preserving Cryptographic Payment Authorization

Authorize payments by *proving* policy compliance, not by *revealing* secrets.

**Status: Phase 12 — Public SDK, end-to-end tests, fuzzing, benchmarks, and
architecture documentation.**

This workspace implements a zero-knowledge, MPC-in-the-Head (MPCitH)
authorization pipeline: a prover holding credential secrets and amount
witnesses produces a self-contained, immutable `Authorization` artifact
attesting that a payment satisfies a spending policy. A verifier — a
merchant, receiver, or auditor — checks that artifact from
`(Payment, Policy, Authorization)` alone. No witness, no secret shares,
no commitment randomness ever crosses the prover/verifier boundary.

The stable entry point is `crates/sdk`, a pure orchestration layer with
no new cryptography of its own. Everything cryptographic lives in the
layers below it (`crypto-core`, `secret-sharing`, `mpc`, `mpcith`,
`circuit`, `policy`, `payment`, `proof`, `verifier`).

## What is proven

The proven relation is, informally:

> *I know credential secrets `s₁…sₙ` and integer amount witnesses such
> that `SHA-256(domain ‖ sᵢ) = CredentialIdᵢ` for the required
> credentials, `0 ≤ amount ≤ limit < 2⁶⁴`, and the policy tree over
> those leaves evaluates to true — all bound to this exact
> `(payment_id, amount, recipient_commitment, policy, circuit, nonce)`.*

Concretely, `Sdk::authorize(&payment, &policy, &witness, &mut rng)`:

1. Validates the payment record and the policy shape.
2. Normalizes the policy and derives `policy_id` / `circuit_id`.
3. Builds a bound `PaymentStatement` (payment id, typed amount,
   recipient commitment, policy/circuit ids, protocol version, nonce).
4. Runs the plaintext `AuthorizationRelation` as a gate — refusal to
   prove a non-satisfying witness.
5. Compiles the normalized policy to an arithmetic circuit and proves
   it through the abstract `proof` interface (MPCitH + Fiat–Shamir).
6. Bundles the result into an immutable `Authorization`, optionally
   self-verifying before returning.

`Sdk::verify(&payment, &policy, &auth)` re-derives every binding,
fails fast on tampered metadata, and only then runs the cryptographic
proof check. It takes no witness and no RNG; it is pure and stateless.

## Privacy architecture

Secrets stay on the prover side by construction, not by convention:

- **Zero-knowledge execution via MPC-in-the-Head.** Each of `R`
  repetitions simulates exactly 3 virtual parties over an
  additive-sharing MPC layer on the ed25519 scalar field
  (`ark_ed25519::Fr`, `p = 2²⁵² + 27742317777372353535851937790883648493`).
  All three party views are committed (`SHA-256`,
  domain `private-payment-auth/mpcith/view/v1`, fresh 32-byte
  randomness) *before* the Fiat–Shamir challenge arrives; two views
  are then opened. The hidden party appears only through commitments
  plus public broadcast material. Per-repetition soundness error is
  1/3; the default `R = 12` gives forgery probability ≈ `(1/3)¹² ≈
  1.9·10⁻⁶`.
- **Fiat–Shamir transcript binding.** Challenges are derived from
  `DOMAIN_FS ‖ backend_id ‖ protocol_version ‖ statement ‖ circuit_id ‖
  policy_id ‖ commitments`, so a proof for one statement verifies
  under no other statement — including one differing only in nonce.
  Security rests on the Fiat–Shamir random-oracle heuristic (ROM; QROM
  analysis is out of scope).
- **Credential commitments.** A credential is the digest
  `SHA-256("private-payment-auth/credential/v2" ‖ secret)`. The
  reference evaluator and circuit compiler share one commitment
  function so they cannot drift.
- **Secret hygiene.** `SecretBytes` / `CommitmentRandomness` are
  `Zeroize` + `ZeroizeOnDrop` with redacted `Debug`
  (`SecretBytes([REDACTED])`); `PartyView` and `PrivateWitness` wipe
  on drop; shares redact their values. Digest and commitment
  comparisons use `subtle::ConstantTimeEq`. Error types
  (`CryptoCoreError`, `SdkError`, `VerificationFailure`) carry
  categories, never secret bytes, share values, or proof internals.
  There is no global RNG, no `SystemTime`, no `thread_rng` in library
  code — only caller-supplied `CryptoRngCore`.
- **Public by design.** Circuits carry structure only; transcript
  hooks carry node ids, never values. `Authorization` bytes contain
  no secret material — secrets were absorbed into view commitments
  inside the proof.

## Cryptographic construction

| Layer | What it contributes |
| --- | --- |
| `crypto-core` | Only home of raw primitives: `Digest` (constant-time eq), `HashFunction` with length-framed `hash_domain`, hash commitments (`randomness ‖ len ‖ message`), canonical encodings, field arithmetic, Fiat–Shamir transcripts, pluggable `CryptoBackend` (`Sha256Backend` default, `Shake256Backend` SHA-3 XOF option). `#![forbid(unsafe_code)]`. |
| `secret-sharing` | Classic Shamir sharing over the ed25519 scalar field. Information-theoretic hiding below threshold; no VSS, no complaint mechanism — honest-dealer model, documented in the threat model. |
| `mpc` | Additive-sharing evaluation with Beaver triples; mirrors every circuit gate. Dual-evaluator property tests enforce `reference_eval == reveal(mpc_eval)`. |
| `circuit` | Arithmetic DAG (`SecretInput`, `PublicInput`, `Constant`, `Add`, `Mul`) with positional topological ids, strict validation, injective canonical encoding, and hash-bound `CircuitId = SHA-256("private-payment-auth/circuit/v1" ‖ encoding)`. |
| `mpcith` | 3-party commit-then-open proofs with an independent verifier that re-implements semantics from public data only. No secret leakage from proofs or transcripts by design. |
| `proof` | Non-interactive `Prover` / `Verifier` over MPCitH: Fiat–Shamir transform, backend-pinned verification (`backend_id ≠ B::ID` rejected before any crypto work), serialization, repetition caps. |
| `policy` | Typed recursive AST (`AmountAtMost`, `Credential`, `Threshold{k,members}`, `And`, `Or`), bounded validation, single canonical `normalize` shared by evaluator and compiler, versioned encoding, `PolicyId = SHA-256("private-payment-auth/policy/v2" ‖ encoding)`, deterministic compilation with Fermat zero-indicator gadgets (`x^(p−1) ∈ {0,1}`) and genuine-boolean amount leaves. |
| `payment` | Domain types (`Amount` as exact `u64` + unit, `Payment` + semantic id, `PaymentStatement` with fixed-width encoding), `PrivateWitness` with dual 64-bit decompositions proving `0 ≤ amount ≤ limit` over the integers (no field wrap-around), statement-bound circuits (`amount`, recipient commitment, payment id multiplied into the root wire). |
| `verifier` / `sdk` | Standalone verification and the stable public surface: `Sdk`, `SdkConfig`, `Authorization`, `serialize`/`deserialize`, `authorization_id`, `SdkError`, `VerificationResult`/`VerificationFailure`. Explicit backend dispatch, pre-cryptographic binding checks, default self-verification. |

Backend agility note: `Shake256Backend` changes only the hash/XOF
assumption (SHA-2 → SHA-3 sponge/XOF). It does not by itself make the
system post-quantum — field, MPCitH soundness, and commitment framing
are unchanged. High-assurance deployments should issue and require
*both* a SHA-256 and a SHAKE256 proof. See
[`docs/security/cryptographic-assumptions.md`](docs/security/cryptographic-assumptions.md).

## The authorization artifact

Fixed-layout, deterministic, secret-free (`114 + |proof|` bytes):

| Field | Width | Binds |
| --- | --- | --- |
| `version` | 1 B | Always `AUTHORIZATION_VERSION` (rejected otherwise) |
| `protocol_version` | 1 B | Must be in `SUPPORTED_PROTOCOL_VERSIONS` |
| `backend_id` | 16 B | Proof-producing backend; verifier must align or get `BackendMismatch` |
| `payment_id` | 32 B | Semantic payment id |
| `policy_id` | 32 B | Normalized policy this proof satisfies |
| `circuit_id` | 32 B | Circuit the normalized policy compiled to |
| `proof` | variable | MPCitH non-interactive proof (≈17.9 MB at 12 repetitions on the canonical 2-of-3 + cap fixture) |

Lifecycle: `authorize → serialize → deserialize (strict, panic-free,
bounded) → verify → authorization_id` (domain-separated SHA-256 over
the canonical encoding; equal ids ⟺ byte-identical bindings + proof).

Verification order is fixed: backend alignment → version → policy/circuit
re-derivation → payment binding → cryptographic check. Tampered metadata
fails fast, before any proof work.

Replay model: a proof is bound to one `(payment, policy, nonce)` tuple
and cannot be rebound — but re-presenting the *same* artifact
re-verifies. Double-spend / duplicate suppression is an
application-layer ledger over `(payment_id, authorization_id)`, not a
cryptographic property. Artifacts carry no timestamp or expiry. See
[`docs/security/threat-model.md`](docs/security/threat-model.md).

## Honest limitations

This project documents what it does *not* yet provide:

- Credential checks inside circuits compare commitment digests by field
  equality; the real SHA-256 runs outside the circuit. A custom-tooled
  malicious prover could satisfy a credential leaf without the
  preimage. Production needs an arithmetization-friendly hash
  (e.g. Poseidon/Rescue-style) in-circuit.
- Soundness is probabilistic (`(1/3)^R`) under the Fiat–Shamir
  heuristic — not a formally proven ROM/QROM reduction in this codebase.
- Verifier correctness is assumed, not machine-checked. Zeroization
  uses `Zeroize` without `mlock` / volatile-write guarantees; there is
  no dudect/valgrind constant-time CI gate.
- No replay ledger, no freshness oracle, no backend auto-negotiation,
  no version migration path, no hybrid dual-hash proof (compose two
  proofs manually if needed).

## Assurance and hardening

Security-first: correctness and audited dependencies over performance.
Every change is gated by formatting, strict Clippy lints, debug +
release tests, `cargo deny` (advisories, bans, licenses), and
panic-free decoder discipline (`Err`, never `unwrap` on untrusted bytes).

- `tests/*` — integration (`smoke`), policy/payment property suites,
  cross-backend vectors, Fiat–Shamir / MPCitH / state-machine
  regressions, constant-time and parser-robustness tests, SDK
  end-to-end / adversarial / property / serialization suites.
- `crates/payment/tests` — payment-level property and integration tests.
- `fuzz/fuzz_targets/*` — `cargo-fuzz` over `decode_circuit`,
  `decode_mpcith_proof`, `decode_payment`, `decode_proof`,
  `decode_share`, `fuzz_authorization_decode`, `fuzz_sdk_verify`,
  `fuzz_policy_{decode,validate,normalize,compile}`,
  `policy_range_check`.
- `benches/*`, `crates/payment/benches`, `crates/policy/benches` —
  Criterion benchmarks including `sdk_bench` (authorize ±
  self-verify, verify-only, encode/decode, `authorization_id`).
- `docs/` — architecture (`overview`, `sdk`, `policy-model`,
  `dependency-boundaries`), decisions (ADRs 0001–0012), security
  (`threat-model` with a 10-actor catalog, `cryptographic-assumptions`,
  `fuzzing`, `policy-security`, `randomness-audit`,
  `clone-ownership-audit`).
- `.github/workflows/ci.yml` + `scripts/run_local_ci.sh` — CI pipeline
  and its local mirror. Pinned toolchain
  (`rust-toolchain.toml`); `#![forbid(unsafe_code)]` everywhere.

## Layout

- `crates/sdk` — public SDK: `authorize`/`verify`/`serialize`/`deserialize`/`authorization_id`
- `crates/payment` — payment domain types and end-to-end pipeline
- `crates/policy` — typed policy AST, normalization, evaluator, compiler
- `crates/proof` — non-interactive proof interface and backend binding
- `crates/mpcith` — MPC-in-the-Head construction (3-party model)
- `crates/mpc` — additive-sharing MPC layer over the ed25519 scalar field
- `crates/circuit` — arithmetic DAG circuit representation
- `crates/crypto-core` — primitives: hashing, commitments, secret containers, backends
- `crates/secret-sharing` — Shamir secret sharing
- `crates/verifier` — standalone verification entry point
- `tests/*` — integration, property, adversarial, and SDK tests
- `crates/payment/tests` — payment-level tests
- `benches/*`, `crates/payment/benches`, `crates/policy/benches` — Criterion benchmarks
- `fuzz/fuzz_targets/*` — cargo-fuzz targets (decode paths, verify, policy)
- `docs/` — architecture, decisions (ADRs), security and threat model
- `.github/workflows/ci.yml` — CI pipeline
- `deny.toml`, `clippy.toml`, `rustfmt.toml` — lint/licensing policy
- `rust-toolchain.toml` — pinned stable toolchain with `rustfmt` and `clippy`
- `scripts/run_local_ci.sh` — local mirror of the CI checks

## End-to-end in 30 seconds

Add the SDK plus the domain types (secrets live in `crypto-core`):

```toml
[dependencies]
sdk = { path = "crates/sdk" }
payment = { path = "crates/payment" }
policy = { path = "crates/policy" }
crypto-core = { path = "crates/crypto-core" }
rand_chacha = "0.3"
rand_core = "0.6"
```

The privacy boundary is the point of the example: the prover holds the
witness, the verifier never sees it — only public bytes cross the wire.

```rust,no_run
use crypto_core::{Digest, SecretBytes};
use payment::{Amount, AmountUnit, Payment, PrivateWitness};
use policy::{credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sdk::{authorization_id, deserialize, serialize, Sdk, SdkConfig, VerificationResult};

// --- Prover side: (payment, policy, witness) -> bytes ---
fn authorize(payment: &Payment, policy: &Policy, witness: &PrivateWitness) -> Vec<u8> {
    let sdk = Sdk::new(SdkConfig::default());
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let auth = sdk.authorize(payment, policy, witness, &mut rng).unwrap();
    // `witness` is zeroized on drop; `auth` carries no secret material.
    serialize(&auth)
}

// --- Verifier side: (payment, policy, bytes) -> accept / reject ---
fn verify(payment: &Payment, policy: &Policy, bytes: &[u8]) -> bool {
    let sdk = Sdk::new(SdkConfig::default());
    let auth = deserialize(bytes).expect("strict decoder rejects malformed bytes");
    // Optional: deduplicate resubmissions with this stable id.
    let _id = authorization_id(&auth);
    matches!(sdk.verify(payment, policy, &auth), Ok(VerificationResult::Valid))
}

fn main() {
    // 2-of-3 credentials plus a 100-cent cap.
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

    let bytes = authorize(&payment, &policy, &PrivateWitness::new(secrets, payment.amount, 100));
    assert!(verify(&payment, &policy, &bytes));
}
```

See [`docs/architecture/sdk.md`](docs/architecture/sdk.md) for the
full SDK surface, lifecycle, binding rules, and limitations,
[`docs/architecture/overview.md`](docs/architecture/overview.md) for the
layered design,
[`docs/security/threat-model.md`](docs/security/threat-model.md) for the
adversary catalog and remaining risks, and
[`docs/decisions/0012-sdk-public-boundary.md`](docs/decisions/0012-sdk-public-boundary.md)
for the public-boundary rationale.

## License

Dual-licensed under `MIT OR Apache-2.0`, as declared in `Cargo.toml`:

- [`LICENSE-MIT`](LICENSE-MIT)
- [`LICENSE-APACHE`](LICENSE-APACHE)

You may use this software under the terms of either license.
