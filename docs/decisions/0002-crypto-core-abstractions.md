# ADR 0002: crypto-core Abstractions — Algorithm Agnosticism, Explicit Encoding, Dedicated Secret Types

- **Status:** Accepted
- **Date:** 2026-08-23
- **Phase:** 1 (`crypto-core` foundations)

## Context

Phase 1 introduced the first real cryptographic code: `Digest`,
`SecretBytes`, `HashFunction`/`Sha256Hash`, `CanonicalEncode`, and
hash-based commitments. Three design choices required explicit
decisions.

## Decision 1: Algorithm-agnostic traits

Hashing is abstracted behind the `HashFunction` trait; commitments are
generic over it. Rationale:

- **Upstream layers stay abstract**: `proof`, `mpcith`, and `payment`
  are parameterized by behavior, not by SHA-256. Swapping or adding a
  hash (e.g., for a future Poseidon-based field hash) must not require
  touching anything above `crypto-core`.
- **Testability**: known-answer and property tests can be written once
  against the trait.
- **Cost is low**: monomorphization keeps generic callers at zero
  runtime overhead.

## Decision 2: Explicit canonical encoding instead of Serde

Serialization of values that feed hashes uses a hand-written
`CanonicalEncode` trait, not Serde. Rationale:

- **Canonical form is a security property.** Hash input encodings must
  be injective — two distinct logical structures must never hash to the
  same value. Serde formats (JSON, CBOR) permit multiple encodings of
  the same logical value (field ordering, optional fields, map key
  ordering), which is exactly the ambiguity class behind
  serialization-based forgery bugs.
- **Minimal attack surface**: our encoding is ~20 lines of length
  framing with no parser, no recursion limits, no deserialization of
  untrusted data at all in this layer.
- **No accidental transitive dependencies**: Serde derives would pull
  proc-macro machinery into the most security-critical crate for zero
  benefit here.
- Serde remains permitted *outside* `crypto-core` (e.g., test-vector
  loading uses serde_json as a dev-dependency only).

## Decision 3: Dedicated secret types

Secrets live in purpose-built types (`SecretBytes`,
`CommitmentRandomness`) rather than raw `Vec<u8>`/arrays. Rationale:

- **Zeroization by construction**: `ZeroizeOnDrop` wipes memory when the
  container dies; there is no way to hold secret bytes without this
  guarantee inside these types.
- **Leak-resistant observability**: redacted `Debug` implementations
  make it impossible to leak secrets through `{:?}` logging — verified
  by tests — which is the single most common real-world leakage path.
- **Type-level intent**: a function signature taking
  `&CommitmentRandomness` documents that the argument is sensitive and
  enforces the 32-byte invariant at the type level, eliminating a class
  of length-confusion bugs.
- **Constant-time discipline**: comparisons on secret-derived values are
  exposed only via `subtle`-backed methods.

## Consequences

- Every future primitive must define its canonical encoding explicitly
  and document injectivity.
- Adding an algorithm means adding one trait impl plus vectors;
  upstream code is untouched.
- If `mlock`/guard pages or volatile zeroization become requirements,
  they can be added inside the secret types without API changes.
