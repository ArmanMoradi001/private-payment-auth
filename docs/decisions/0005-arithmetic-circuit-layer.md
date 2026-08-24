# ADR 0005: Arithmetic Circuit Layer

* Status: Accepted (Phase 4)
* Deciders: mpc crate maintainers
* Date: 2026-08

## Context

Phases 1–3 produced cryptographic primitives (`crypto-core`) and an
additive-sharing MPC layer with Beaver-triple multiplication
(`mpc`). To authorize a payment we need a precise, verifiable
description of *what is being computed* — the authorization policy —
that can be evaluated both in plaintext (for testing/simulation) and
under MPC (for confidential execution), and whose identity can be
committed to and later proven via MPCitH.

## Decision

Introduce the `circuit` crate defining arithmetic circuits over the
prime field, with five design choices:

### 1. DAG as ordered node vector; operands reference `NodeId`s directly

Nodes are stored in one `Vec<Node>` where binary gates hold their
operand ids inline. We explicitly reject a separate edge/wire list or
gate-table indirection:

- The vector index *is* the node id, making references cheap and the
  structure trivially serializable.
- Requiring operands to be strictly earlier nodes makes the stored
  order a topological order: validation is linear, evaluation is a
  single forward pass, and no cycle detection is ever needed.
- Determinism: identical builder call sequences produce byte-identical
  circuits — a prerequisite for hash-based identity.

### 2. Deterministic id assignment

`CircuitBuilder` assigns ids `0, 1, 2, ...` in insertion order.
Deterministic assignment means circuit construction is reproducible,
canonical encoding is stable across builds, and transcripts recorded
by node id remain meaningful across executions.

### 3. Hash-based semantic identity

A circuit's id is `SHA-256("private-payment-auth/circuit/v1" ||
canonical_encoding)` using the existing domain-separated `Sha256Hash`
from `crypto-core`. Consequences:

- Any change to constants, operations, node ordering, input counts, or
  output set changes the id (covered by explicit mutation tests).
- The canonical encoding is hand-rolled and injective (tagged nodes,
  fixed-width big-endian constants, length-counted sections); bincode
  and friends were rejected to keep the encoding fully specified and
  auditable byte-for-byte, matching the project's canonical-encoding
  conventions from Phase 1.
- Future policy commitments can pin a policy by its `CircuitId`.

### 4. Separate reference and MPC evaluators

Two evaluators implement the same semantics:

- `eval_reference` operates on raw field elements and depends only on
  `ark-ff` — never on `mpc`. It is ground truth for tests, benches,
  and debugging, and cannot drift into protocol behavior because it
  has no access to any.
- `eval_mpc` maps every gate onto shared-value operations:
  leaves → `share_input`, `Add` → local share addition, `Mul` → one
  Beaver triple. It returns shares and reveals nothing automatically;
  opening values is always an explicit caller action (recorded as an
  `Open` transcript event).

Equivalence between the two is enforced by property tests over
randomized DAGs (`reference == reveal(mpc_eval)`), so protocol bugs
surface as test failures rather than silent mis-authorization.

### 5. Optional structural transcript hooks

`TranscriptHook` records `Input` / `Operation` / `Open` / `Output`
events carrying node ids only. Hooks are passed as
`Option<&mut TranscriptHook>`: disabled evaluation allocates nothing.
This fixes the emission points now so MPCitH integration (Phase 5+)
can turn event logs into Fiat–Shamir transcripts without changing
evaluator call sites — while structurally excluding secret values
from anything that could become public.

## Consequences

- The statement layer is complete: policies become circuits, and
  circuit ids become committable identities.
- The proof stack (`mpcith`, `proof`) now has a concrete artifact
  shape to consume (node-order transcripts).
- Circuit constants use full-width big-endian field encodings; the
  encoding version byte (`1`) allows future evolution.
- Known limitation (tracked in the threat model): circuit ids are not
  yet authenticated; substitution detection requires the future
  policy/verifier layers to commit to ids.

## Alternatives considered

- **Shamir-based sharing inside the circuit layer** — rejected: MPC
  gates need additive sharing; Shamir remains in `secret-sharing` for
  key handling only.
- **Generic DSL / IR with explicit wires (e.g., R1CS-like)** —
  rejected for this phase as over-engineered; the node-vector DAG
  covers +/* policies with far less machinery and can be extended
  later if richer constraint systems are needed.
- **bincode/serde serialization** — rejected: non-canonical across
  configurations and versions; identity hashing demands a frozen,
  injective format.
