# Policy Model (Phase 11)

This document describes the `policy` crate's typed AST, normalization,
encoding, evaluation semantics, and deterministic circuit compilation. It is
the authoritative reference for `crates/policy/`. See ADR
[0011](../decisions/0011-policy-ast-and-normalization.md) for the design
rationale and rejected alternatives.

## Scope

Pure typed-AST engineering for spending-policy definition, validation,
canonicalization, evaluation, and circuit compilation. **No cryptographic
protocol changes** — no proof serialization, backend, Fiat–Shamir, or MPC
logic is touched. The crate depends only on `crypto-core`, `circuit`, and
`ark-ff`.

## AST (`ast.rs`)

```text
Policy =
  | AmountAtMost(AmountLimit)        // u64 saturating cap
  | Credential(CredentialId)         // expected SHA-256 commitment digest
  | Threshold { k: ThresholdK, members: Vec<Policy> }
  | And(Vec<Policy>)                 // all members must hold
  | Or(Vec<Policy>)                  // at least one member must hold
```

- `CredentialId([u8; 32])` is the **expected commitment digest**:
  `SHA-256("private-payment-auth/credential/v2" ‖ secret)`. The evaluator
  checks equality; the circuit receives the digest as a *secret-input field
  element* (see the placeholder limitation in the threat model).
- `AmountLimit(u64)` and `ThresholdK(u16)` are newtyped to enforce
  invariants at construction (`1 ≤ k ≤ 1000`, `0 < limit ≤ u64::MAX`).

## Validation (`validation.rs`)

`validate(&policy)` enforces structural bounds **before** any compilation:

| Constant                   | Value | Rejects                                  |
| -------------------------- | ----- | ---------------------------------------- |
| `MAX_POLICY_DEPTH`         | 100   | nesting deeper than 100                  |
| `MAX_POLICY_NODES`         | 10000 | more than 10k nodes                      |
| `MAX_THRESHOLD_ARITY`      | 1000  | `Threshold.members.len() > 1000`        |
| `MAX_COMBINATOR_CHILDREN`  | 1000  | `And`/`Or` with > 1000 children          |
| `MAX_CREDENTIAL_COUNT`     | 1000  | more than 1000 distinct credential leaves |
| `MAX_ENCODED_SIZE`         | 1 MiB | encodings larger than 1 MiB              |

It also rejects `k < 1`, `k > members.len()`, empty `And`/`Or`/`Threshold`,
and duplicate credential ids within a single policy. Errors are
`PolicyError` variants (`MaxDepthExceeded`, `MaxNodesExceeded`,
`InvalidThresholdK`, `MaxCombinatorChildrenExceeded`, `MaxCredentialCount`,
`DuplicateCredential`, `EmptyCombinator`, …).

## Normalization (`normalize.rs`)

`normalize(&policy)` returns a canonical form used by **both** `evaluate` and
`compile_with_layout`. Steps:

1. Recursively normalize every child.
2. **Flatten same-type only** — `And` children into the parent `And`, `Or`
   children into the parent `Or`. Cross-type nesting is preserved
   (`Or([And([a,b])])` stays `Or([And([a,b])])`).
3. **Sort** members by their canonical encoding (byte-ascending), so order is
   independent of source spelling.
4. **Deduplicate** members with identical encoding.
5. **Collapse** single-child `And`/`Or` to the child.

`normalize` is idempotent: `normalize(normalize(p)) == normalize(p)`
(property-tested). Both the evaluator and the compiler normalize, so they can
never disagree on canonical order.

## Encoding & identity (`encoding.rs`, `identity.rs`)

- `encode(&policy) -> Vec<u8>`: `ENCODING_VERSION (1) ‖ tag(1) ‖
  len-prefixed children`. Tags: `AmountAtMost=1, Credential=2, Threshold=3,
  And=4, Or=5`. Injective and deterministic.
- `decode(&[u8]) -> Result<Policy, PolicyError>`: rejects unknown versions,
  bad tags, truncation, over-length, and trailing bytes (panic-free, bounded).
- `policy_id(&policy) -> PolicyId`: `SHA-256(
  "private-payment-auth/policy/v2" ‖ encode(p))`. Equal ids ⟹ equal policies.

## Reference evaluator (`evaluator.rs`)

`evaluate(&policy, &witness) -> Result<AuthorizationResult, PolicyError>`:

- Normalizes the policy, then walks the normalized tree.
- `Credential(id)` authorized iff the witness supplies a secret whose
  `SHA-256("…/credential/v2" ‖ secret) == id`. A **missing** secret is a
  `WitnessMismatch`; an unsatisfiable branch simply carries a non-matching
  secret.
- `AmountAtMost(limit)` authorized iff `witness.amount ≤ limit`.
- `And` authorized iff all members; `Or` iff any member; `Threshold{k}`
  authorized iff ≥ `k` members authorized.
- Returns `authorized: bool` plus a per-node `NodeOutcome` trace.

## Circuit compiler (`compiler.rs`)

`compile<F: PrimeField>(&policy)` and `compile_with_layout::<Fr>(&policy)`
(`Fr = ark_ed25519::Fr`) map the **normalized** tree to an `{Add, Mul}`
circuit. The compiler uses two arithmetic gadgets:

- **Fermat zero-indicator** `x^(p−1) ∈ {0,1}` exactly (no prover freedom),
  giving exact booleans for credential match and range-check windows.
- **Combinator composition** `And ⇒ a·b`, `Or ⇒ a + b − a·b`
  (`Threshold` via an indicator product and a booleanity constraint).

`CompiledPolicy<F>` carries `circuit`, `secret_slots`, `public_slots`,
`auxiliary_targets`, `range_check_outputs` (the count of published booleanity
constraints), and `metadata` (node/input/gate counts).

### Amount leaf soundness

The amount leaf emits the four `prove_bounded_difference` range-check
constraints and outputs a genuine boolean
`b = ∏ᵢ (1 − cᵢ^(p−1))` derived from them. Because `b` is a real `0/1`
value, `Or`/`Threshold` composition correctly requires *only the selected
branch's* amount bound to hold — the earlier unsound design (constant `1` plus
a global ∧) is removed.

### Auxiliary solving

Nested thresholds need a fixpoint: an outer discriminant depends on an inner
root that depends on inner auxiliary inputs. `build_inputs` solves auxiliaries
by iterating evaluation to a fixed point rather than a single forward pass.

## Evaluation equivalence

`CompiledPolicy::reference_evaluate(&policy, &witness)` re-runs the circuit
over the same normalized layout consumed by `evaluate`. Property tests
(`tests/policy_property_tests.rs`) enforce, over thousands of random policies:

- `circuit_never_accepts_what_evaluator_rejects`,
- `satisfying_witness_agrees`,
- `normalize` idempotence, `PolicyId` stability, encode/decode round-trip,
  and compilation determinism.

## Fuzzing & benchmarking

- `fuzz/fuzz_targets/fuzz_policy_{decode,validate,normalize,compile}.rs`
  (`cargo +nightly fuzz run …`) — adversarial bytes must never panic.
- `crates/policy/benches/policy_bench.rs` (`cargo bench -p policy`) —
  validation, normalization, encoding, `PolicyId`, compile, evaluate.
