# Architecture Overview

> **Status: Phase 5 — MPCitH layer added.** The primitives, additive
> MPC, arithmetic-circuit, and MPC-in-the-Head layers are implemented;
> the Fiat–Shamir/proof abstraction and the application stack
> (`proof`, `policy`, `verifier`, `payment`, `sdk`) remain *intended*
> architecture only.

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
