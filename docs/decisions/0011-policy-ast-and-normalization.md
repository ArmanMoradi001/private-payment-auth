# ADR 0011: Policy AST, Normalization, and Deterministic Compilation

- **Status:** Accepted (Phase 11)
- **Deciders:** protocol engineering
- **Date:** 2026-08-29

## Context

Phase 7 introduced a payment authorization policy as a *flat* structure:
`Threshold { k, credentials }` over a credential list, plus `AmountAtMost`
and `And`/`Or` combinators — compiled by `compile(&Policy)` to a plain
`{+, ×}` circuit. Two problems surfaced during Phase 11 hardening:

1. **Expressiveness.** A flat credential list cannot encode conditional or
   nested policy structure (e.g. *“pay up to $X, AND (Alice OR Bob must
   approve)”*). Real spending policies are trees, not flat sets.
2. **Evaluator/circuit disagreement.** The reference `evaluate` and the
   compiled circuit did not always agree: the evaluator did **not**
   normalize, but the compiler **did** (and the compiler's normalization
   incorrectly flattened *cross-type* combinators, e.g.
   `Or([And([…])])` collapsed to `Or([…])`, changing semantics). Property
   tests caught concrete cases where the circuit accepted what the evaluator
   rejected. A second bug: the amount leaf returned a constant `1` and
   published its range-check constraints as a *global* ∧, which is unsound
   under `Or`/`Threshold` composition (it required **all** amount bounds to
   hold rather than the selected branch's).

Phase 11 replaces the flat model with a fully recursive typed AST, a single
canonical normalization used by *both* the evaluator and the compiler, a
versioned canonical encoding with a `PolicyId`, and a compiler whose amount
leaf is a genuine boolean so composition is sound.

## Decision

### Typed recursive AST (`crates/policy/src/ast.rs`)

```text
Policy =
  | AmountAtMost(AmountLimit)
  | Credential(CredentialId)
  | Threshold { k: ThresholdK, members: Vec<Policy> }
  | And(Vec<Policy>)
  | Or(Vec<Policy>)
```

`CredentialId` is the *expected commitment digest*: the evaluator checks
`SHA-256("private-payment-auth/credential/v2" ‖ secret) == CredentialId`.
`AmountLimit(u64)` is a saturating cap. `ThresholdK(u16)` is `1 ≤ k ≤ 1000`.

### Single canonical normalization (`crates/policy/src/normalize.rs`)

`normalize(&policy)` produces a deterministic form consumed by **both**
`evaluate` and `compile_with_layout`. It:
- recursively normalizes children,
- **flattens only same-type** combinators (`And` into `And`, `Or` into
  `Or`; cross-type nesting is *preserved*),
- sorts each combinator's members by their canonical encoding (byte order),
- removes duplicate members,
- collapses single-child `And`/`Or` to the child.

Because both consumers normalize identically, `evaluate(p) == circuit(p)` is
structurally guaranteed rather than coincidental. `normalize` is
idempotent (property-tested).

### Versioned canonical encoding + `PolicyId` (`crates/policy/src/encoding.rs`, `identity.rs`)

`encode` emits `ENCODING_VERSION (1) ‖ tag-byte ‖ len-prefixed children`,
injective and deterministic; `decode` rejects unknown versions, bad tags,
truncation, and trailing bytes. `PolicyId = SHA-256(
"private-payment-auth/policy/v2" ‖ encoding)`, so equal ids ⟹ equal
policies. (The domain bump to `v2` reflects the new AST; the credential
commitment domain is `…/credential/v2`.)

### Reference evaluator (`crates/policy/src/evaluator.rs`)

`evaluate(&policy, &witness)` normalizes internally and returns an
`AuthorizationResult` (authorized bool + per-node outcome). It requires a
secret for **every** credential leaf (a missing secret is `WitnessMismatch`);
an unsatisfied credential simply carries a non-matching secret.

### Deterministic circuit compiler (`crates/policy/src/compiler.rs`)

`compile_with_layout::<Fr>` maps the *normalized* tree to an `{Add, Mul}`
circuit over `ark_ed25519::Fr`:

- **Credential leaf** — `indicator = 1 − (commitment − digest_field)^(p−1)`
  (Fermat zero-indicator: exactly `0` on match, exactly `1` otherwise).
- **Amount leaf** — emits the four `prove_bounded_difference` range-check
  constraints and outputs a genuine boolean
  `b = ∏ᵢ (1 − cᵢ^(p−1))` derived from those constraints via Fermat
  indicators. This is sound under `And`/`Or`/`Threshold` because `b` is a
  real boolean, not a constant.
- **Threshold** — `result = ∏ᵢ indicatorᵢ − (1 − 0^k_result)`; the
  booleanity constraint is published as a global `= 0` output
  (`range_check_outputs` counts exactly these).
- **And** `a·b`; **Or** `a + b − a·b`; **not** is expressed as `Or`/negation
  where needed.

`reference_evaluate` (on `CompiledPolicy`) re-runs the circuit over the same
normalized layout, so it agrees with `evaluate` by construction; property
tests (`tests/policy_property_tests.rs`) enforce
`circuit_never_accepts_what_evaluator_rejects` and
`satisfying_witness_agrees` over thousands of random policies.

### No cryptographic protocol change

This is purely typed-AST engineering. No proof serialization, no backend, no
Fiat–Shamir, no MPC change. The `payment` wiring binds the normalized policy's
`PolicyId` and rebuilds public inputs from the **normalized** policy (so the
verifier's `policy_public_inputs` must normalize too — a bug fixed in
Phase 11).

## Alternatives considered

- **Keep the flat `Threshold{credentials}` model.** Rejected: cannot express
  nested/conditional policies and already disagreed with the evaluator.
- **Text DSL / JSON policy format.** Rejected for this phase (explicitly
  out of scope); the typed AST is the single source of truth and the only
  thing serialized.
- **Arithmetizable in-circuit hash (Poseidon/Rescue) for credential
  commitment.** Deferred: the credential commitment is still supplied to the
  circuit as a *secret-input field element* verified by digest equality; the
  real SHA-256 runs outside the circuit. This remains a documented limitation
  (see the threat model), not a solved problem.
- **Flatten cross-type combinators during normalization.** Rejected: it
  changes policy semantics (`Or([And([a,b])])` is not `Or([a,b])`) and was
  the root cause of the evaluator/circuit mismatch.

## Consequences

### Positive

- Arbitrary nested spending policies are expressible and evaluate/compile
  identically.
- `normalize` is the *single* source of canonical form for both evaluator
  and compiler; equivalence is property-tested, not assumed.
- The amount leaf is now a real boolean; `Or`/`Threshold` composition is
  sound (no longer requires all amount bounds to hold).
- Encoding is versioned and injective; `PolicyId` gives tamper-evident policy
  identity.
- Robustness: `decode`/`validate`/`normalize`/`compile` are fuzzed
  (`fuzz/fuzz_targets/fuzz_policy_*.rs`) and bounded.

### Negative / risks

- The in-circuit credential check is still a **placeholder**: commitment
  digest equality is a secret-input field element, so a malicious prover with
  custom tooling could satisfy it without knowing the preimage. Production
  needs an arithmetizable hash inside the circuit (open limitation).
- Normalization sorts by encoding, so the *circuit* order depends on encoded
  bytes; verifier and prover must both normalize (enforced, but easy to
  regress — covered by property tests).
- `PolicyWitness` requires every credential secret present; consumers must
  assemble a complete witness even for unsatisfiable branches.

## Verification

- `tests/policy_tests.rs` (15 unit/adversarial tests),
  `tests/policy_property_tests.rs` (proptest equivalence + idempotence +
  round-trip), `tests/parser_robustness_tests.rs` (node/arity bounds).
- `crates/payment/tests/payment_tests.rs` (end-to-end, statement binding).
- `fuzz/fuzz_targets/fuzz_policy_{decode,validate,normalize,compile}.rs`
  (`cargo +nightly fuzz run …`).
- `crates/policy/benches/policy_bench.rs` (`cargo bench -p policy`).
- `cargo test --workspace`, `cargo clippy --workspace --all-targets
  --all-features -- -D warnings`, `cargo fmt --all -- --check`.
