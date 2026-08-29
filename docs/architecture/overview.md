# Architecture Overview

> **Status: Phase 11 — typed policy AST, normalization, and deterministic
> compilation.** All prior layers are implemented. Phase 11 replaces the flat
> Phase 7 policy model with a fully recursive typed `Policy` AST (`Threshold`
> over arbitrary member policies, `And`, `Or`, `Credential`, `AmountAtMost`),
> a single canonical `normalize` used by *both* the reference evaluator and the
> circuit compiler (closing the evaluator/circuit disagreement caught by
> property tests), a versioned injective encoding with a `PolicyId`, and a
> compiler whose amount leaf is a genuine boolean so composition is sound. The
> `verifier` and `sdk` crates remain *intended* architecture only.

## Purpose

This project provides cryptographic payment authorization built on
secure multi-party computation (MPC) principles: a payment is authorized
by producing a proof that a set of parties jointly evaluated the
authorization policy over secret inputs, without revealing those inputs.

## Layered Design

The system is organized in strict layers. Dependencies may only point
downward; see [dependency-boundaries.md](dependency-boundaries.md) for
the enforced rules.

```
            +-----+
            | sdk |                 public entry point
            +-----+
       -------|-------------------
        +---------+  +-------+     application layer
        | payment |  | sdk   |
        +---------+  +-------+
             |          |
        +---------+ +--------+    authorization layer
        | policy  | | verifier|
        +---------+ +--------+
             |
        +---------+              proof layer
        | proof   |
        +---------+
             |
        +---------+              protocol layer
        | mpcith  |
        +---------+
             |
        +---------+              MPC layer
        | mpc     |
        +---------+
             |
   +---------------+ +--------+
   | secret-sharing| | crypto-core | primitives layer
   +---------------+ +--------+
```

## Crates

| Crate             | Intended responsibility |
| ----------------- | ----------------------- |
| `crypto-core`     | Foundational traits and implementations: hashing, commitments, canonical encoding, secret handling, randomness, field arithmetic, Fiat–Shamir transcripts. Depends on nothing internal. |
| `secret-sharing`  | Shamir-style secret sharing and reconstruction of keys and protocol inputs, built on `crypto-core`. |
| `mpc`             | The MPC protocol layer: distributed evaluation of the authorization computation over shared secrets. |
| `mpcith`          | MPC-in-the-Head constructions that turn `mpc` protocol executions into zero-knowledge proof components. |
| `policy`          | Authorization policy definition and evaluation: spending limits, multi-party approval rules, time locks, and their commitments. |
| `proof`           | The abstract zero-knowledge proof interface built on `mpcith`, including Fiat–Shamir transformation and serialization of proofs. |
| `payment`         | End-to-end payment authorization orchestration: composes proofs and policies into authorization flows. Deliberately insulated from the MPC layers. |
| `verifier`        | Standalone verification of authorization artifacts, independent of the proving side. |
| `sdk`             | The single stable public entry point for external consumers, re-exporting curated APIs from the crates above. |

## `crypto-core` Abstractions (Phase 1)

Implemented abstractions and their contracts:

- **`Digest`** — fixed-size (32-byte) typed hash output. Hex-formatted in
  `Debug`/`Display`; equality is constant-time (`subtle::ConstantTimeEq`)
  behind both an explicit `ct_eq` and the standard `PartialEq`, so
  ordinary `==` never leaks through timing.
- **`SecretBytes`** — owned secret container wrapping a `Vec<u8>` with
  `Zeroize` + `ZeroizeOnDrop`; its `Debug` output is always
  `SecretBytes([REDACTED])`, preventing accidental secret leakage into
  logs. Mutable access exists solely for filling fresh randomness.
- **`HashFunction`** — algorithm-agnostic trait (`hash`, `hash_domain`);
  `Sha256Hash` is the first implementation. `hash_domain` canonically
  length-frames the domain, making cross-domain collisions impossible.
- **`CanonicalEncode`** — injective canonical encoding: variable-length
  data is framed with a 4-byte big-endian length; fixed-size values
  (`Digest`) are written raw. Implemented for `&[u8]` and `SecretBytes`.
- **Commitments** — `commit::<H>(message, &randomness)` computes
  `H(canonical(randomness) ‖ len_be32(message) ‖ message)`; `open` is
  constant-time. Randomness is exactly 32 bytes and zeroizing.

All operations are `#![forbid(unsafe_code)]` and error via a single
`CryptoCoreError`.

## `secret-sharing` (Phase 2)

Implemented in the `secret-sharing` crate on top of `crypto-core`:

- **Prime field** — shares live in the scalar field of ed25519
  (`ark_ed25519::Fr`, `p = 2^252 + 27742317777372353535851937790883648493`)
  via `ark-ff`. Byte↔element conversion is exact: any value at or above
  the modulus is rejected with `SecretTooLargeForField` rather than
  reduced.
- **`Share`** — carries `version`, `threshold`, `share_count`,
  `index` (non-zero), and a field-element `value`. `Debug` redacts the
  value so shares can be logged without leaking secret material.
- **Canonical encoding** — fixed 45-byte layout:
  `version(1) ‖ threshold(4 BE) ‖ share_count(4 BE) ‖ index(4 BE) ‖ value(32 BE)`.
  Decoding rejects trailing bytes, unsupported versions, zero/out-of-range
  indices, and values ≥ p.
- **`split(secret, t, n)`** — validates `1 < t ≤ n`, maps the secret into
  the field (canonicalized by stripping leading zero bytes), and evaluates
  a random degree-`(t-1)` polynomial at `x = 1..=n`.
- **`reconstruct(shares)`** — enforces consistent metadata, distinct
  non-zero indices, and `len ≥ t`; Lagrange-interpolates the first `t`
  shares at `x = 0` and returns the canonical secret as `SecretBytes`.

Testing: unit tests, Python-generated cross-implementation vectors
(`tests/vectors/`), proptest round-trip/threshold properties, and
Criterion benchmarks. See ADR [0003](../decisions/0003-secret-sharing.md)
for design rationale.

## `circuit` (Phase 4)

Implemented in the new `circuit` crate on top of `crypto-core` and
`mpc`:

- **Arithmetic DAG** — a `Circuit<F>` is an ordered vector of
  [`Node`]s (`SecretInput`, `PublicInput`, `Constant`, `Add`, `Mul`);
  binary gates reference operands directly by `NodeId`. Ids are
  assigned in construction order and must reference strictly earlier
  nodes, so the node vector *is* a deterministic topological order —
  no separate wire/edge list.
- **Validation** — `Circuit::validate` rejects invalid references,
  forward/self references, input-count mismatches, and empty or
  dangling output declarations.
- **Builder** — `CircuitBuilder` assigns ids deterministically
  (`0, 1, 2, ...`) and returns validated circuits from `build()`.
- **Canonical encoding** — hand-rolled injective serialization:
  `version(u8) || num_nodes(u32) || [tagged node encodings] ||
  num_outputs(u32) || [output ids]`. Constants are full-width
  big-endian field elements; trailing bytes, truncation, unknown
  versions/tags, and invalid structures are rejected.
- **Identity** — `CircuitId = SHA-256("private-payment-auth/circuit/v1"
  || canonical_encoding)` via the domain-separated `Sha256Hash`; any
  change to constants, operations, ordering, inputs, or outputs
  changes the id (mutation-tested).
- **Transcript seam** — `TranscriptHook` records structural events
  (`Input` / `Operation` / `Open` / `Output`) carrying only node ids,
  never values; hooks are optional (`None` costs nothing).
- **Dual evaluators** — `eval_reference` computes ground truth over
  raw field elements with zero dependency on protocol logic;
  `eval_mpc` mirrors every gate onto the additive-sharing MPC layer.
  Property tests enforce `reference_eval == reveal(mpc_eval)` over
  randomized circuits.

See ADR [0005](../decisions/0005-arithmetic-circuit-layer.md) for the
design rationale.

## `mpcith` (Phase 5)

Implemented in the new `mpcith` crate over `circuit`, `mpc`, and
`crypto-core`:

- **Fixed 3-party model** — every repetition simulates exactly three
  virtual parties (`PartyId` ∈ {0,1,2}); this is deliberately *not*
  the n-party model of the `mpc` simulator.
- **Views** — a `PartyView` records one party's full execution:
  input shares, per-gate local operations (`Add`, `MulPublic`,
  `BeaverMul` with the global masks and its result share), Beaver
  triple shares, and broadcast mask contributions. `Debug` output is
  redacted for all share-bearing fields.
- **Commit-then-open** — all three views are committed (SHA-256 via
  `crypto_core::commit`, fresh 32-byte randomness, domain
  `private-payment-auth/mpcith/view/v1`) *before* the challenge
  arrives from an injectable `ChallengeSource`; the two non-hidden
  views are then opened. Soundness error per repetition: 1/3.
- **Independent verifier** — replays each opened view from public
  data only, checking commitments in constant time, per-party algebra
  (`d = x − a`, `e = y − b`, `z = c + d·b + e·a + d·e`), global mask
  reconstruction from all parties' broadcasts, and the final output
  sum against the statement. The hidden party's broadcast
  contributions and output share are included in the response — both
  are public by construction.
- **Canonical encoding** — hand-rolled injective serialization for
  views, challenges, repetitions, and whole proofs; version byte,
  strict lengths, trailing-byte rejection.
- **Transcripts** — `MpcithTranscript` records commitments,
  challenges, and opened views per repetition in deterministic order;
  no commitment randomness and no hidden-party state.

Fiat–Shamir is intentionally deferred; see ADR
[0006](../decisions/0006-mpcith.md).

## `policy` (Phase 11)

Implemented in the `policy` crate over `crypto-core`, `circuit`, and
`ark-ff`. The Phase 7 flat model (`Threshold {k, credentials}` + `AmountAtMost`
+ `And`/`Or`) is **replaced** by a fully recursive typed AST; see ADR
[0011](../decisions/0011-policy-ast-and-normalization.md) and
[policy-model.md](policy-model.md).

- **Typed AST** — `Policy` is `AmountAtMost(AmountLimit)`,
  `Credential(CredentialId)` (the expected SHA-256 commitment digest, domain
  `private-payment-auth/credential/v2`), `Threshold { k, members: Vec<Policy>
  }`, `And(Vec<Policy>)`, or `Or(Vec<Policy>)`. Arbitrary nesting is allowed.
- **Validation** — `validate` enforces depth (100), node (10k), credential
  (1k), arity, and combinator-child (1k) bounds, plus `1 ≤ k ≤ members.len()`
  and no duplicate credentials; it is panic-free and bounded.
- **Single canonical normalization** — `normalize` (same-type flattening only,
  encoding-sorted, dedup, singleton-collapse) is consumed by **both** the
  reference evaluator and the circuit compiler, so `evaluate(p)` and
  `circuit(p)` cannot disagree on canonical order. `normalize` is idempotent.
- **Versioned encoding + identity** — injective tag-prefixed encoding
  (`ENCODING_VERSION = 1`); `PolicyId = SHA-256(
  "private-payment-auth/policy/v2" ‖ encoding)`. Equal ids imply equal
  policies. `decode` is panic-free and trailing-byte-rejecting.
- **Reference evaluator** — `evaluate(&policy, &witness)` returns
  `AuthorizationResult` over the normalized tree; requires every credential
  secret present (`WitnessMismatch` otherwise).
- **Deterministic compiler** — `compile_with_layout::<Fr>(&Policy)` maps the
  *normalized* tree onto a plain `{+, ×}` circuit with fixed gate order, so
  equal policies yield identical `CircuitId`s. Two arithmetic gadgets:
  - *Fermat zero-indicator* `x^(p−1) ∈ {0,1}` exactly — exact credential-match
    and amount-window booleans with no prover freedom.
  - *Combinator composition* — `And ⇒ a·b`, `Or ⇒ a + b − a·b`, `Threshold`
    via an indicator product and a published booleanity constraint. The amount
    leaf outputs a **genuine boolean** (`∏(1 − cᵢ^(p−1))` over its four
    range-check constraints), so `Or`/`Threshold` composition is sound (it no
    longer requires all amount bounds to hold).
- **Input layouts** — `compile_with_layout` returns `secret_slots`,
  `public_slots`, `auxiliary_targets`, and `range_check_outputs` (the count of
  published booleanity constraints) so consumers assemble witness/statement
  vectors positionally; auxiliaries are solved by a fixed-point iteration in
  `build_inputs` (nested thresholds depend on inner roots).
- **Equivalence property-tested** — `tests/policy_property_tests.rs` enforces
  `circuit_never_accepts_what_evaluator_rejects` and `satisfying_witness_agrees`
  over thousands of random policies; fuzz targets cover `decode`/`validate`/
  `normalize`/`compile`.

See ADR [0008](../decisions/0008-private-authorization.md) for the
authorization-relation design, and [0011](../decisions/0011-policy-ast-and-normalization.md)
for the Phase 11 rationale.

## `payment` (Phase 7)

Implemented in the `payment` crate over `policy`, `proof`,
`crypto-core`, `mpc`, and `circuit`:

- **`PaymentStatement`** — public payment data (`payment_id[32]`,
  `amount: u64`, `recipient_commitment`, `policy_id`) with a fixed-
  width injective canonical encoding.
- **`PrivateWitness`** — zeroizing credential secrets validated against
  the policy's declared count and size limits.
- **`AuthorizationRelation`** — the plaintext reference semantics:
  policy-id binding, witness shape, per-credential hash checks,
  threshold counting, amount caps, combined through the policy tree;
  cross-checked against the compiled circuit's reference evaluation.
- **Statement binding** — the compiled circuit is extended with three
  public leaves (`amount`, recipient commitment, payment id)
  multiplied into the root wire. The bound root evaluates to
  `b₁b₂b₃` for honest runs — fully verifier-recomputable — and puts
  the payment data inside the Fiat–Shamir transcript, so any tampered
  statement field invalidates existing proofs.
- **`authorize` / `verify_authorization`** — end-to-end proving and
  verification delegating to the abstract `proof` interface only.
  Verifiers rebuild circuit, public inputs, and expected outputs from
  public data alone; no witness material exists on that side.

### Payment domain and bounded amounts (Phase 8)

- **`Amount`** — an exact `u64` count of a named unit (currently
  `Cents`), canonically encoded `version ‖ value(u64 BE) ‖ unit`.
  `u64::MAX` is the ceiling; conversion from field elements is
  deliberately absent so no wrapped value can masquerade as money.
- **`Payment`** — payer-side record with a fresh 32-byte nonce;
  semantic id `SHA-256("private-payment-auth/payment/v1" ‖ encoding)`.
- **Bound statement** — `PaymentStatement` now pins the semantic
  payment id, typed amount, recipient commitment, policy id, circuit
  id, protocol version, and nonce in a fixed-width encoding with a
  strict decoder (truncation, trailing bytes, unknown versions all
  rejected).
- **Sound range check** — the phase 7 window-exclusion amount gadget
  was removed and replaced by dual bit-decomposition: the witness
  commits 64 digits of the amount and 64 digits of its difference to
  the limit; published booleanity/reconstruction sums must be exactly
  zero. This proves `0 ≤ amount ≤ limit < 2^64` over the integers,
  closing the wrap-around hole. See ADR
  [0009](../decisions/0009-payment-domain-and-amounts.md).

Remaining known limitation: credential binding inside circuits still
uses commitment-digest equality as a placeholder for in-circuit
hashing (see the threat model).

## `crypto-core` Backend Abstraction (Phase 9)

The hard constraint for this phase was *non-displacement*: SHA-256 stays
the default and every existing SHA-256 test vector remains byte-identical.
The abstraction therefore adds a selectable backend without altering the
default bytes.

- **`CryptoBackend` trait** — `hash(data)`, `hash_domain(domain, data)`,
  `expand(domain, data, out_len)` (XOF-like), `commit(message,
  randomness)` (legacy-compatible framing), `const ID: BackendId`,
  `const DIGEST_LEN: usize`, plus `GenericDigest<B>` carrying the
  backend tag.
- **`BackendId`** — a 16-byte opaque tag (`sha256-v1…` / `shake256-v1…`)
  written into every serialized proof and read by the Fiat–Shamir
  derivation, so a proof can never verify under a different backend.
- **`Sha256Backend`** — `hash` equals the historical `Sha256Hash::hash`
  exactly; `commit` reproduces the legacy `canonical(randomness) ‖
  len(message) ‖ message` framing; `expand` is iterative SHA-256. Default
  for every generic parameter (`Prover`, `Verifier`, `MpcithProver`,
  `MpcithVerifier`, `ProtocolConfig`).
- **`Shake256Backend`** — native SHAKE256 XOF for `expand`; 32-byte
  digests for protocol compatibility. Produces *different* digests than
  SHA-256 on identical input, which is exactly what makes backend binding
  meaningful.
- **`ProtocolConfig<B>`** — repetitions count plus the backend marker;
  constructed per proof so the prover, the FS derivation, and the view
  commitments all share one `B`.
- **Binding in proofs** — `NonInteractiveProof` carries `backend_id`;
  `Verifier::<B>::verify` rejects any proof whose `backend_id ≠ B::ID`
  with `UnsupportedBackend` *before* doing any cryptographic work, which
  defeats both cross-backend acceptance and post-hoc relabeling.
- **Binding in Fiat–Shamir** — `fs_input` prepends `DOMAIN_FS ‖ B::ID ‖
  PROTOCOL_VERSION` before the statement/transcript, so the challenge
  space is backend-specific.

All backends are exercised by `crypto-core/tests/backend_tests.rs`,
`crypto-core/tests/fuzz_ready_tests.rs`, and
`proof/tests/adversarial_backend_tests.rs`; the SHAKE256 path is
validated against independent Python vectors in `tests/shake256_vectors.rs`
and `crates/proof/tests/vectors/`.

See ADR [0010](../decisions/0010-crypto-backend.md) for the design
rationale, and [cryptographic-assumptions.md](security/cryptographic-assumptions.md)
for what backend agility does and does *not* guarantee.

## Key Invariants

1. Only `crypto-core` may contain raw cryptographic primitives.
2. `payment` and `verifier` depend on the *abstract* `proof` interface,
   never on `mpc` or `mpcith` directly.
3. All code is `#![forbid(unsafe_code)]`.
4. Every crate documents its future responsibility via crate-level docs.
5. Circuit node ids are positional and topological; operands must
   reference strictly earlier nodes.
6. The reference evaluator never calls MPC functions; equivalence
   between the two evaluators is property-tested, not assumed.
7. The MPCitH verifier never calls prover code; it re-implements
   circuit semantics from scratch.
8. MPCitH repetitions share nothing: fresh input sharings, triples,
   and commitment randomness per repetition.
