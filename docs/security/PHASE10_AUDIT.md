# Phase 10 — Consolidated Security Audit Report

**Component:** `private-payment-auth` MPC payment proving stack
**Scope:** Production-hardening review across 5 prompts. **No protocol
semantics were changed** — weaknesses found were documented as residual
risks, never silently "fixed" by altering the protocol.
**Status:** All prompts complete; `cargo test --workspace` passes (49 test
binaries, 0 failures); fuzzing harness requires nightly (see
`fuzzing.md`).

---

## 1. Methodology

1. **Static review** of every `impl fmt::Debug` / `derive(Debug)` in
   `crates/*/src` and every `println!`/`eprintln!`/`dbg!`/`todo!`/
   `unimplemented!` call site.
2. **Resource-bound review** of all decoders/parsers and the verifier.
3. **Randomness review** (see `randomness-audit.md`): every RNG/time source
   in `src` enumerated.
4. **Black-box behavioral tests** (regression + property + fuzz harness) that
   assert rejection of malformed input, prover/verifier consistency, and
   no-panic robustness.

---

## 2. Threat model (summary)

Full detail in `threat-model.md`. Ten adversarial actors modeled:

1. Malformed-input / fuzz attacker (parser)
2. Resource-exhaustion attacker (bounds)
3. Replay attacker (statement nonce)
4. Proof forger (corrupt circuit id / public inputs)
5. MPC share leaker (log/debug exposure)
6. Timing side-channel observer (constant-time)
7. Rogue verifier / challenger (challenge-source failure)
8. Commitment swapper (tampered view/commitment)
9. Cross-backend confusion attacker (Fiat–Shamir binding)
10. Weak/compromised RNG supplier (caller-supplied randomness)

---

## 3. Controls implemented (by prompt)

### Prompt 1 — Parser hardening, resource bounds, threat model
- Decoders return typed errors instead of panicking on malformed input
  (`Share::decode`, `circuit::deserialize`, `mpcith`/`proof` decoders,
  `Amount`/`PaymentStatement`).
- Global bounds introduced: `MAX_CIRCUIT_NODES`, `MAX_PROOF_REPETITIONS`,
  `MAX_REPETITIONS`, `MAX_SHARE_COUNT`, `MAX_POLICY_DEPTH`,
  `MAX_CREDENTIAL_COUNT`; new errors `ExcessiveSize`, `ExcessiveRepetitions`,
  `ExcessivePolicyDepth`, `ExcessiveCredentials`.
- Verifier rewritten **iteratively** (no recursion deepener).
- Panic-free `Share::decode`.
- Regression suites: `parser_robustness_tests.rs` (8),
  `integer_arithmetic_regression_tests.rs` (5).

### Prompt 2 — Secret lifecycle, constant-time, clone/ownership
- **All secret-bearing `Debug` impls redacted** (see §4):
  `Share`, `Share<F>`, `SecretBytes`, `CommitmentRandomness`,
  `PrivateWitness`, `BeaverTriple`, `PartyView`, `TripleShare`,
  `LocalOperation`, `Repetition`, `ProofRepetition` print `[REDACTED]` /
  counts only.
- `Zeroize` / `ZeroizeOnDrop` / manual `Drop` added to concrete secret
  holders (`PartyView`, `PrivateWitness`, `BeaverTriple`, `Share`,
  `SharedValue`, `SecretBytes`, `CommitmentRandomness`).
- Constant-time comparisons via `subtle` (`ct_eq`) for commitment opening
  and equality checks; no `==`/`!=` on secret bytes.
- Audit: `clone-ownership-audit.md`. Regression suites:
  `secret_lifecycle_tests.rs` (14), `constant_time_tests.rs` (4).

### Prompt 3 — MPCitH / Fiat-Shamir / state-machine regression + randomness
- Independent-verifier regression: `mpcith_security_regression.rs` (8)
  proves tampered commitments/views/challenges, cross-rep mixing,
  truncation, and hidden-output tampering are rejected.
- Fiat–Shamir regression: `fiat_shamir_regression.rs` (6) proves challenge
  binds to statement, backend, and full commitment transcript, and that
  tampering yields `ChallengeMismatch` / `UnsupportedBackend`.
- State-machine regression: `state_machine_regression.rs` (6) proves
  interactive-prover error paths and the ordered `commit → finish` flow.
- Randomness audit: `randomness-audit.md` — **all production randomness is
  injected via `CryptoRngCore` / `ChallengeSource`; no global, static,
  thread-local, or time-based source exists in `src`.**

### Prompt 4 — Fuzzing infrastructure + expanded property tests
- `fuzz/` cargo-fuzz harness (6 targets) for the decoders; requires
  nightly (documented in `fuzzing.md`). Excluded from the default
  workspace so stable builds are unaffected.
- `tests/property_tests_expanded.rs` (12): field laws, range-check
  semantics, decomposition round-trip, secret-sharing split/reconstruct,
  MPCitH prover→verifier consistency, Fiat–Shamir determinism/binding,
  commit/open cross-crate consistency.

---

## 4. Secret-leak review result (Prompt 5)

**Finding: no production code path leaks secret material.**

- Every `Debug` impl on a secret-bearing type was inspected and redacts
  the sensitive field(s); non-secret types (`CircuitId`, errors, `Amount`,
  `ShareContext`, `TranscriptHook`, `PublicValue`) derive `Debug` safely
  (public data only).
- `grep` for `println!`/`eprintln!`/`dbg!` across `crates/*/src` returns
  **zero** matches. The only `println!` in the tree is in
  `proof/tests/vector_tests.rs`, which is gated by `#[cfg(test)]` and
  prints only a test-case label — never built into production artifacts.
- No `todo!()` / `unimplemented!()` in `src`.
- `MpcithProof` / `NonInteractiveProof` derive `Debug`; their secret
  contents flow through the redacted `Repetition` / `ProofRepetition`
  impls, so a derived `Debug` of a full proof still redacts shares.

Redaction is locked by existing regression tests
(`secret_lifecycle_tests.rs`, `crypto_core` `SecretBytes::debug_is_redacted`).

---

## 5. Residual risks (documented, not resolved)

These are **design/trust assumptions**, not code defects introduced by
this work:

1. **Honest-majority, passive security.** The MPC layer is a 3-party
   honest-majority (2-out-of-3) *passively* secure construction. Collusion
   of 2 parties, or an *active/covert* adversary, is out of scope and is
   **not** mitigated here.
2. **Caller-supplied RNG trust.** The library never sources randomness
   itself; a caller passing a predictable `CryptoRngCore` (or a constant
   stream) would weaken security. This is caller responsibility
   (see `randomness-audit.md`).
3. **Underlying field library timing.** We enforce constant-time *comparisons*
   with `subtle`, but the field arithmetic (arkworks `Fp`) is not itself
   guaranteed constant-time for all operations; residual timing
   side-channels in the curve/field layer remain.
4. **Decoder fuzzing depth.** The fuzz harness asserts *no panic* on
   malformed bytes; it does **not** assess cryptographic soundness and only
   covers the parser layer. Higher-level properties are covered by the
   regression/property suites on stable, but fuzzing those paths requires
   nightly and was not executed in CI here.
5. **Property-test coverage is representative, not exhaustive.** Random
   circuits/witnesses exercise prover→verifier consistency but do not
   constitute a formal proof of knowledge/soundness.
6. **No formal verification / no security proof.** Hardening is validated
   by tests and review only.
7. **Public values are intentionally visible.** `PublicValue`/`Statement`
   `Debug` reveals public inputs/outputs by design; this is not secret
   material.

---

## 6. Verification evidence

- `cargo test --workspace` → **49 test binaries pass, 0 failures**
  (includes the suites listed in §3 plus pre-existing unit/integration
  tests).
- `cargo build` (stable, default workspace) succeeds; `fuzz/` is excluded
  and does not affect stable builds.
- Secret-leak static review (§4): clean.

## 7. Conclusion

The production code is hardened against malformed input, resource
exhaustion, secret leakage via logs/debug, and basic tampering/forgery at
the parser, MPCitH, Fiat–Shamir, and state-machine layers, with
deterministic, injected randomness. The residual risks above are inherent
to the protocol's trust model and the underlying libraries; they are
called out explicitly rather than silently altered.
