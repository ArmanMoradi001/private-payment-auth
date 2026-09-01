# ADR 0012: SDK Public Boundary

- **Status:** Accepted (Phase 12)
- **Deciders:** protocol engineering
- **Date:** 2026-09-01

## Context

Phase 12 stabilizes the `sdk` crate as the project's single,
documented, public entry point. Several design decisions need
explicit rationale so future contributors know what is and is not
the SDK's job:

1. The SDK must not silently reimplement cryptographic primitives;
   it must be a pure orchestration layer over the verified lower
   crates.
2. The SDK's self-verification default trades a measurable cost for
   pipeline-bug detection; the cost and rationale should be
   documented honestly.
3. Backend handling has been carefully designed across Phase 9 and
   Phase 12; the SDK's exact role in that scheme must be captured
   here.
4. Replay semantics sit on a seam between cryptographic
   (Fiat–Shamir) and application-layer (deduplication ledger)
   guarantees. Which side does what?

This ADR records the SDK's choices for each.

## Decision

### 1. The SDK is an orchestration layer, not a second verifier

The SDK does not contain a single cryptographic primitive. Every
operation it performs delegates to a lower crate:

- payment validation, statement construction, plaintext relation
  check, and proof delegation → `payment::*`
- policy validation, normalization, id derivation, and circuit
  compilation → `policy::*`
- proof encoding, Fiat–Shamir transformation, repetition count → `proof::*`
- hashing, commitments, field arithmetic → `crypto-core::*`

The SDK's only "new" logic is plumbing: backend dispatch on
configuration, deterministic nonce derivation off the binding
triple, and canonical byte-layout assembly. This means a bug in the
SDK cannot masquerade as a bug in the proof system, and the proof
system's test surface remains the proof system.

The same architectural rule is enforced at the dependency level
(see [`docs/architecture/dependency-boundaries.md`][dep]): no crate
above the SDK may depend on `sdk`, and `sdk` may not depend on
`verifier` or `policy` (the SDK uses their public APIs only).

[dep]: ../architecture/dependency-boundaries.md

### 2. Self-verification default

`SdkConfig::self_verify` defaults to `true`. When enabled,
`Sdk::authorize` runs an independent `Sdk::verify` on the freshly
produced artifact before returning it. The cost is approximately
one full proof verification (measured at ≈10–30 ms on the canonical
fixture; see `benches/sdk_bench.rs`); the benefit is that any
internal inconsistency between the prove path and the verify path
in the same build — a `panic`, a binding mismatch, a forgotten
recompute — surfaces as `SdkError::SelfVerificationFailed` instead
of being silently emitted to the caller.

We accept this cost as the default because:

- The prover is the **most security-sensitive code path** in the
  project. A pipeline bug that emits an invalid authorization is a
  direct forgery vulnerability.
- The cost is small relative to `prove` (≈30 ms vs ≈100 ms on the
  canonical fixture, ≈30%).
- Disabling the check silently on every build would create a
  regression risk: someone refactors the verify path and the prover
  keeps working but no longer matches. The self-verify default makes
  that class of regression a unit test failure, not a security
  advisory.

Applications with strong throughput requirements can opt out via
`SdkConfig::new(..., false)`. The property tests
(`tests/sdk_property_tests.rs`) and the adversarial tests
(`tests/sdk_adversarial_tests.rs`) both exercise the default-on
behavior, so opt-out is a deliberate, reviewable decision rather
than a silent footgun.

### 3. Backend handling and compatibility

The SDK never silently picks a backend. Concretely:

- **Generation.** `Sdk::authorize` reads
  `SdkConfig::backend_id()` and dispatches to the matching
  monomorphized backend. An unknown configured backend returns
  `SdkError::BackendUnsupported`. There is no automatic fallback.
- **Verification.** `Sdk::verify` checks that
  `Authorization::backend_id() == SdkConfig::backend_id()` *first*,
  returning `SdkError::BackendMismatch` on disagreement. There is no
  attempt to re-verify the proof under the configured backend.
- **Serialization.** The decoder rejects unknown `BackendId`s with
  `SdkError::BackendUnsupported`. It does not silently coerce them
  to a default.
- **Cross-backend.** A SHA-256 artifact presented under a
  `SHAKE256`-configured verifier is rejected as `BackendMismatch`,
  not silently re-encoded.

This is the explicit hard-rejection policy from ADR 0010 extended
to the SDK surface. It means the workspace can ship multiple
backend builds side by side: a SHA-256-only SDK and a
SHAKE256-only SDK each have unambiguous, non-overlapping valid
artifacts, and the binding is enforced by the wire format rather
than by convention. The current build supports SHA-256 only;
adding SHAKE256 is a follow-up that does not require any change to
the on-the-wire layout.

### 4. Replay semantics: protocol guarantees vs application-layer enforcement

The SDK enforces replay semantics on **two layers**, and it is
important to keep them distinct:

- **Cryptographic (automatic).** A proof is bound to its specific
  `(payment, policy, nonce, …)` tuple via Fiat–Shamir. The same
  proof bytes verify under no other statement, including
  re-submissions differing only in nonce. This is enforced by the
  proof system and is not an SDK responsibility.

- **Application layer (not enforced).** Detecting that the *same*
  authorization is presented twice for the *same* payment — even
  with the same valid binding triple — is not enforced by the
  cryptographic layer. The SDK has no replay ledger, no
  `(payment_id, authorization_id)` set, and no expiry timestamp
  inside the artifact.

Why the asymmetry? The cryptographic layer can enforce uniqueness
*within a single statement* because the statement includes the
nonce; it cannot enforce uniqueness *across resubmissions of the
same statement* without knowing what "the same statement" means in
the application's domain. A payment system that cares about
double-spend must track observed `authorization_id`s (or, more
typically, `payment_id`s) itself and refuse duplicates. The SDK
deliberately does not pretend to do this — doing so silently would
be worse than documenting the seam.

This split is documented at the API level (`Sdk::verify` has no
ledger parameter; the verification-only call is pure), at the
artifact level (no timestamp / expiry field), and at the
documentation level (`docs/architecture/sdk.md` and
`docs/security/threat-model.md`).

## Consequences

- The `sdk` crate is the only public surface documented as
  stable. Lower crates (`payment`, `policy`, `proof`, `mpcith`,
  `mpc`, `crypto-core`, `secret-sharing`) remain internal, even
  though they are reachable via path dependencies for testing.
- The default `Sdk` configuration is safe (self-verify on, SHA-256
  backend, version checked) but not the fastest. Power users can
  opt out via `SdkConfig::new`; the property tests guarantee that
  opt-out remains the only way to opt out.
- A backend bump (e.g. SHA-256 → SHAKE256) requires a new SDK
  build with the new backend wired through `backend_from_id`. The
  on-the-wire layout does not change.
- Consumers who need double-spend protection must maintain their
  own authorization ledger. The SDK will not duplicate or
  accidentally mask this requirement.

## Alternatives considered

- **Make the SDK a verifier.** Rejected: a second verifier
  implementation would either (a) duplicate the existing verifier
  and create a maintenance / divergence hazard, or (b) import the
  existing verifier, in which case the SDK is a wrapper, not a
  verifier.
- **Always self-verify.** Rejected: forces every caller to pay the
  ≈30 % overhead even in trusted-internal use cases. The
  opt-in/opt-out knob gives both safety and flexibility without
  sacrificing defaults.
- **Bake the application ledger into the SDK.** Rejected: the SDK
  cannot know which deduplication key matters to a given
  application (payment id? authorization id? both?), and any
  default would be silently wrong for someone. Better to document
  the seam.
- **Auto-negotiate backend.** Rejected: silent auto-negotiation
  defeats the cross-version / cross-backend rejection guarantees
  from Phase 9. The SDK refuses to guess.

## References

- ADR 0008 — Private authorization (the relation model)
- ADR 0009 — Payment domain and amounts
- ADR 0010 — Crypto backend abstraction
- ADR 0011 — Policy AST and normalization
- [`docs/architecture/sdk.md`](../architecture/sdk.md)
- [`docs/security/threat-model.md`](../security/threat-model.md)