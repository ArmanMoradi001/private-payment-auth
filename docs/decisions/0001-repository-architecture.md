# ADR 0001: Repository Architecture — Cargo Workspace with Layered Crates

- **Status:** Accepted
- **Date:** 2026-08-22
- **Phase:** 0 (Repository Foundation)

## Context

This project implements cryptographic payment authorization using MPC and
MPC-in-the-Head proof techniques. Such systems mix very different
concerns: low-level primitives, distributed protocols, proof machinery,
business policy, and a public API. Cryptographic code also carries
elevated review, auditing, and isolation requirements.

We must decide the repository and code organization before any
implementation begins.

## Decision

Use a single **Cargo workspace** with **nine layered crates** under
`crates/`, connected only by path dependencies in strictly downward
directions (see `docs/architecture/dependency-boundaries.md`).

## Rationale

### Separation of concerns

Each crate owns exactly one responsibility (`crypto-core` = primitives,
`mpc` = protocols, `proof` = proofs, `policy` = rules, `payment` =
orchestration, `verifier` = independent checking). This yields:

- Narrow, auditable API surfaces. Security review of `crypto-core` does
  not require reading business logic.
- The critical invariant that `payment`/`verifier` depend on the abstract
  proof interface — never on MPC internals — is enforced *structurally*
  by the dependency graph rather than by convention.

### Compile times

Workspace-wide rebuilds are incremental per crate: changes to `policy`
do not recompile `crypto-core` or `mpc`. Parallel compilation across
crates keeps full builds fast as the codebase grows. CI can also cache
per-crate artifacts effectively.

### Dependency isolation

- Features and third-party dependencies can be confined to the layer
  that needs them (e.g., benchmark-only or serialization deps never leak
  into `crypto-core`).
- `#![forbid(unsafe_code)]` can be applied uniformly now and selectively
  relaxed later, per crate, with explicit justification.
- The `sdk` crate acts as a firewall: external consumers cannot reach
  internal crates directly.

### Single workspace vs. multiple repositories

One workspace keeps all crates versioned and tested atomically: every CI
run exercises the exact dependency graph that will ship. Splitting repos
this early would add versioning friction without benefit while the
architecture is still evolving.

## Consequences

- Dependency direction violations are the main architectural risk;
  they are documented in `dependency-boundaries.md` and will be
  mechanically checked in CI.
- The root manifest doubles as an infrastructure package hosting
  cross-cutting integration tests and Criterion benchmarks.
- Crate boundaries may need adjustment as the design solidifies; moving
  code between crates is expected to be cheap precisely because concerns
  are already separated.
