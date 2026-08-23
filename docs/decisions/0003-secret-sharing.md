# ADR 0003: secret-sharing — Shamir over ark-ed25519 Fr with Canonical Fixed-Size Encoding

- **Status:** Accepted
- **Date:** 2026-08-23
- **Phase:** 2 (`secret-sharing` crate)

## Context

Phase 2 requires distributing keys and protocol inputs across parties.
The scheme must be simple, information-theoretically private below the
threshold, and composable with `crypto-core`'s secret-handling
conventions.

## Decision 1: Shamir secret sharing

Shamir's polynomial scheme was selected over alternatives:

- **vs. additive sharing**: additive `(n, n)` sharing cannot tolerate
  lost parties; Shamir gives a tunable threshold `t ≤ n` and remains
  perfectly private for any minority of shares.
- **vs. CRT-based (Asmuth–Bloom) schemes**: Shamir is linear, needs no
  coprime-modulus machinery, and is the standard substrate the MPC layer
  will build on (degree reductions, multiplication protocols all assume
  polynomial shares).
- **Simplicity**: ~60 lines of field arithmetic; easy to test against
  independent implementations (the Python vector generator).

Known limitation, accepted: classic Shamir has no malicious security and
no dealer verification. Verifiable secret sharing is deferred; see
threat-model.md for the resulting deployment constraints.

## Decision 2: Prime field — `ark-ed25519::Fr` via `ark-ff` 0.4

Shares live in the scalar field of ed25519,
`p = 2^252 + 27742317777372353535851937790883648493`.

- **Well-documented prime**: the Curve25519 group order is among the
  most scrutinized constants in deployed cryptography.
- **Security margin**: ~252 bits means each share leaks zero information
  about the secret regardless of adversary computation (perfect secrecy);
  the field size only bounds *secret length*, not security level.
- **Implementation quality**: `ark-ff` is constant-time, extensively
  tested, `no_std`-capable, carries no `unsafe`, and is already part of
  the ark ecosystem this repository may reuse in later phases. It
  supports the exact `CryptoRngCore`/`rand_core@0.6` interface used by
  `crypto-core`.
- **Exact byte conversion**: `element_from_be_bytes` compares against
  the modulus before conversion, so values ≥ p are rejected with
  `SecretTooLargeForField` instead of being silently reduced — reduction
  would silently corrupt secrets whose top bits happen to exceed p.

Consequence: **secrets are limited to ≤ 32 bytes representing integers
strictly below p** (~252 bits). Longer inputs must be hashed or split
before sharing; this limitation is documented in the threat model.

## Decision 3: Canonical fixed-size share encoding

Wire format: `version(1) ‖ threshold(4 BE) ‖ share_count(4 BE) ‖
index(4 BE) ‖ value(32 BE)` = exactly 45 bytes.

- **Canonical, injective**: every share has exactly one encoding;
  decoding rejects trailing bytes, unknown versions, zero/out-of-range
  indices, and values ≥ p. This matches ADR 0002's stance that encodings
  feeding hashes or cross-party comparison must be unambiguous.
- **Fixed size**: constant length makes framing trivial, bounds memory,
  and rules out length-ambiguity bugs entirely (no variable-length
  fields).
- **Metadata travels with every share**: threshold/share_count/version
  redundancy lets reconstruction detect mixing shares from different
  splits (`IncompatibleMetadata`) instead of silently reconstructing a
  wrong value.
- **No Serde on the wire**: same rationale as ADR 0002; serde support in
  tests is confined to reading JSON vectors.

## Consequences

- Reconstruction canonicalizes output by stripping leading zeros; inputs
  with leading zeros are normalized at split time. Round-trip holds for
  canonical secrets and is covered by property tests.
- Polynomial coefficients are drawn by rejection sampling to avoid
  modular-reduction bias.
- Testing strategy: unit tests, Python-generated deterministic vectors
  (cross-implementation check), proptest round-trip/threshold
  properties, Criterion benchmarks.
