# ADR 0010: Cryptographic Backend Abstraction

- **Status:** Accepted (Phase 9)
- **Deciders:** protocol engineering
- **Date:** 2026-08-26

## Context

The protocol's hash / XOF usage was historically hard-wired to SHA-256.
Two pressures motivate change:

1. **Post-quantum readiness.** SHA-3 (SHAKE256) is widely viewed as a
   safer choice against known quantum attacks on SHA-2. We want a path to
   swap the hash layer without rewriting every call site.
2. **Hedging / agility.** Selecting one primitive per proof, and binding the
   proof to that choice, lets a deployment require multiple backends later
   without restructuring the codebase.

A hard constraint from the start: **do not replace SHA-256 globally** and
**keep every existing SHA-256 test vector byte-identical.** SHA-256 remains
the default.

## Decision

Introduce a `CryptoBackend` trait in `crypto-core` with two implementations:

- `Sha256Backend` — the default. Its `hash` is exactly the historical
  `Sha256Hash::hash`; its `commit` keeps the legacy framing
  `canonical(randomness) ‖ len(message) ‖ message`. All default-path bytes
  are unchanged.
- `Shake256Backend` — a SHA-3 XOF. `expand` is native SHAKE256; digests are
  32 bytes for protocol compatibility.

Bind the backend everywhere it matters:

- `GenericDigest<B>` carries the backend type tag.
- `ProtocolConfig<B>` selects the backend for a whole proof.
- `NonInteractiveProof` stores a 16-byte `BackendId`; `Verifier::<B>::verify`
  rejects proofs whose `backend_id ≠ B::ID` *before* any crypto work
  (`UnsupportedBackend`).
- The Fiat–Shamir `fs_input` prepends `DOMAIN_FS ‖ B::ID ‖ PROTOCOL_VERSION`
  so challenges are backend-specific.

Generic parameters use trailing defaults (`Prover<'a, R, B = Sha256Backend>`)
so existing call sites that do not specify a backend keep compiling against
SHA-256.

## Alternatives considered

- **Macro/feature-flag swap.** Selecting the backend at compile time via a
  Cargo feature. Rejected: it prevents a single binary from accepting both
  backends and complicates verification/services that must support multiple.
- **Replace SHA-256 entirely with SHAKE256.** Rejected outright — it
  violates the byte-identical constraint and discards the audited SHA-256
  path.
- **Per-call backend arguments without a proof-level binding.** Rejected:
  without embedding `BackendId` in the proof, a SHAKE256 proof could be
  verified under SHA-256 (or relabeled), defeating the agility guarantee.

## Consequences

### Positive

- SHA-256 is untouched; all legacy vectors pass unchanged.
- Producing a proof under an alternative backend is a one-line config change.
- Cross-backend forgery is structurally impossible: verifiers reject
  mismatched `BackendId` before doing work.
- Independent Python vectors cover `Shake256Backend` and the FS derivation
  (`tests/shake256_vectors.rs`, `crates/proof/tests/vectors/`).

### Negative / risks

- The abstraction is *not* by itself post-quantum security; only the hash
  layer moves. A real PQ upgrade also needs a PQ field/arithmetic layer.
- No hybrid hedging is automatic; requiring two backends is a deployment
  decision, not a library default.
- More code paths (both backends) must be maintained and tested; the
  `Shake256Backend` path has proportionally less production exposure than
  SHA-256 until it is deployed.
- Implementors must thread `B` through new code; forgetting it (or using a
  concrete backend where a generic was intended) silently pins SHA-256.

## Verification

- `crypto-core/tests/backend_tests.rs`, `fuzz_ready_tests.rs`.
- `proof/tests/adversarial_backend_tests.rs` (cross-backend rejection +
  `UnsupportedBackend` on tampered ids).
- `cargo test --workspace` (all SHA-256 vectors intact), `cargo clippy
  --workspace --all-targets --all-features -- -D warnings`, `cargo fmt`,
  `cargo bench --no-run`.
