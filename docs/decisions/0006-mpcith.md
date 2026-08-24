# ADR 0006: MPC-in-the-Head Layer

* Status: Accepted (Phase 5)
* Deciders: mpcith crate maintainers
* Date: 2026-08

## Context

Phase 4 produced arithmetic circuits and dual evaluators. To make an
execution *provable* we adopt MPC-in-the-Head (MPCitH): run the MPC
protocol "in the head" of the prover, commit to every party's view,
and let a challenge decide which views are opened. The proof layer
(`proof` crate) will later wrap this with Fiat–Shamir to produce
non-interactive zero-knowledge-style authorization artifacts.

## Decision

### 1. Fixed 3-party model

Each repetition simulates exactly three virtual parties. Rationale:

- With k parties the cheating party hides among k candidates, giving
  per-repetition soundness error 1/k; k = 3 is the smallest k that
  keeps the "which view is corrupted" uncertainty meaningful while
  minimizing triple cost, commitment size, and replay work.
- A fixed k makes encodings, transcripts, and benchmarks concrete
  (`PartyId` is one byte constrained to {0,1,2}) instead of carrying
  n-party generality no current consumer needs.
- This is deliberately *not* the generic simulator of `mpc`; mpcith
  implements its own tight 3-party execution loop.

### 2. Challenge model

Challenges arrive through the injectable `ChallengeSource` trait:
`RandomChallengeSource` (production, CSPRNG) and
`DeterministicChallengeSource` (tests force each hidden party).
Commitments are formed strictly before the challenge is drawn —
enforced by construction in `prove_repetition`. **Fiat–Shamir is
deferred** until the transcript format has stabilized; see below.

### 3. View definition

A `PartyView` captures everything a verifier could ever need about one
party's execution: its shares of the secret inputs, the local result
share for every gate touching shared state (tagged with the output
node id so misalignment is detectable), its Beaver triple shares in
usage order, and the mask contributions it broadcast. Views never mix
repetitions: every view is stamped with its `RepetitionId`.

Two subtleties drove the operation semantics:

- *Mixed addition*: adding a public value v to a 3-party additive
  sharing must update exactly one party's share; updating all three
  injects 3·v into the opened sum (caught by tests).
- *Beaver constant folding*: the public term d·e of
  `z = c + d·b + e·a + d·e` lands in party 0's share only.

### 4. Commitment scheme

Views are committed with `crypto_core::commit::<Sha256Hash>` over the
canonical view encoding framed by the domain
`private-payment-auth/mpcith/view/v1`, with fresh 32-byte randomness
per view per repetition. Verification recomputes and compares in
constant time (`subtle` underneath). Reusing the audited Phase-1
primitive avoids inventing new assumptions.

### 5. Beaver verification

For every multiplication the verifier checks three layers:

1. *Local algebra*: each opened party's broadcast contribution equals
   `x_i − a_i` (resp. `y_i − b_i`) using its claimed input share and
   triple share.
2. *Global masks*: `d`, `e` are reconstructed as the sum over all
   three parties' contributions — the hidden party's contributions are
   included in the response because they are public in any honest
   execution (parties broadcast them to open d and e anyway).
3. *Share correctness*: each opened party's recorded result share must
   equal `c_i + d·b_i + e·a_i + d·e` (+d·e only for party 0), using the
   globally reconstructed masks. Finally the output sum over all
   parties must match the statement's expected outputs; the hidden
   party contributes only its output share, so cheating there escapes
   exactly when that party is hidden (the standard 2/3 argument).

### 6. Transcript structure

`MpcithTranscript` records, per repetition in id order: commitments,
challenge, opened views, hidden broadcasts, and hidden output shares —
everything public, nothing secret, no commitment randomness. This is
the artifact the future Fiat–Shamir transform will hash to derive
challenges, and later what `verifier`/`payment` will consume.

### 7. Why Fiat–Shamir is deferred

FS freezes the transcript format and the challenge derivation into a
security-critical, hard-to-change contract. Deferring lets us:
validate the interactive protocol against adversarial tests first;
finalize what belongs in a transcript (e.g., whether circuit ids are
absorbed); and choose the FS domain-separation design deliberately in
the `proof` crate ADR. The cost is explicit: until FS exists, proofs
are interactive and a prover that can choose challenges adaptively
trivially wins by hiding its corrupted party.

## Consequences

- The authorization flow can now be *proven*, not just simulated.
- Proof size grows linearly with repetitions × circuit size (opened
  views dominate); batching/compression is future work.
- Known limitations are tracked in the threat model: probabilistic
  soundness, trusted local triples, no quantum hiding claim.

## Alternatives considered

- **Generic n-party MPCitH** — rejected for this phase: unused
  flexibility, larger proofs, more complex encodings.
- **Sigma-protocol style proofs per gate** — rejected: many round
  trips, weaker composition with the existing sharing semantics.
- **Garbled-circuit based ZK (ZKB++ style bit decomposition)** —
  deferred: our policies are pure field arithmetic today; a boolean
  layer can be added on top of the same commit/challenge skeleton if
  comparisons/ranges become necessary.
