# Threat Model (Skeleton)

> **Status: initial skeleton — Phase 0.** No cryptographic implementation
> exists yet. Assumptions and goals below are placeholders to be refined
> before and during implementation. Nothing here is a final claim.

## Assets

What must be protected:

- **Secret keys / secret shares** held by parties participating in
  authorization.
- **Payment request data**: amounts, counterparties, policy inputs that
  may be confidential.
- **Policy definitions** whose integrity must be guaranteed.
- **Authorization artifacts** (proofs, transcripts) whose forgery or
  replay would violate the system's guarantees.
- *(Open: are transaction metadata or party identities part of the
  confidential asset set?)*

## Adversaries

Considered adversary classes:

- **External network attacker**: observes or tampers with communication.
- **Malicious protocol participant**: deviates arbitrarily from the MPC
  protocol (deviating from semi-honest vs. malicious security is an open
  question).
- **Malicious client / SDK consumer**: attempts to forge authorization
  artifacts or bypass policy.
- **Side-channel attacker**: measures timing, memory, or cache behavior
  of implementations.
- *(Open: do we consider compromise of a threshold of parties? Compromise
  of the verifier environment?)*

## Trust Assumptions

Placeholders — none finalized:

- [ ] Number of corrupted parties tolerated `(t, n)` — TBD.
- [ ] Communication channels: authenticated? private? synchronous? — TBD.
- [ ] Randomness sources available to each party — TBD.
- [ ] Cryptographic assumptions (hardness assumptions, hash model,
  ROM vs. standard model) — **deliberately not yet chosen**; to be
  documented in a dedicated ADR once primitives are selected.
- [ ] Correctness of `verifier` as a trusted component — TBD.

## Security Goals

Informal for now; formal definitions to follow after primitive selection:

1. **Unforgeability**: no adversary can produce a valid authorization
   artifact without honest protocol execution satisfying policy.
2. **Privacy of secrets**: protocol transcripts and proofs reveal nothing
   about secret shares or secret inputs beyond what is explicitly public.
3. **Policy integrity**: policies cannot be modified, substituted, or
   bypassed without detection.
4. **Sound verification**: the verifier accepts only artifacts produced
   by honest execution.
5. *(Open: which of these hold against malicious vs. semi-honest
   adversaries? What is the exact privacy definition — simulation-based
   or game-based?)*

## Open Questions

- Which concrete primitives (hashes, fields, commitment schemes) will be
  standardized in `crypto-core`, and under which assumptions?
  - *Partially resolved (Phase 1)*: SHA-256 is the default hash;
    commitments are hash-based. Formal assumptions still TBD.
- Semi-honest or malicious security for the MPC layer at Phase 1?
- Side-channel requirements: constant-time guarantees for which
  operations, verified how (e.g., dudect, valgrind-based tooling)?
  - *Partially resolved (Phase 1)*: digest and commitment comparison are
    constant-time via `subtle`; systematic verification is still open.
- Replay protection and artifact freshness: mechanism and scope?
- Audit and formal verification strategy for `crypto-core` and `proof`?

## Secret Handling Notes (Phase 1)

Current mitigations in `crypto-core`:

1. **Zeroization**: all secret material lives in zeroizing containers
   (`SecretBytes`, `CommitmentRandomness`, both `#[derive(Zeroize,
   ZeroizeOnDrop)]`). Buffers are wiped on drop even on error paths —
   e.g., a partially filled randomness buffer from a failed RNG is still
   zeroized.
2. **Redaction in logs**: secret types implement `Debug`/`Display` that
   print only placeholders (`SecretBytes([REDACTED])`,
   `CommitmentRandomness([REDACTED])`). Formatting a secret with `{:?}`
   can never emit its contents; this is enforced by unit tests.
3. **Constant-time comparison**: digests and commitments compare via
   `subtle::ConstantTimeEq`; no secret-derived value is compared with
   variable-time `==`.
4. **No secrets in errors**: `CryptoCoreError` variants carry no payload
   data.

Remaining gaps (tracked as open questions above): side-channel testing
tooling, memory-locking (`mlock`) is *not* used, compiler elision of
zeroization is not formally guaranteed without volatile semantics, and
there is no yet policy for secret lifetime bounds beyond drop-time
wiping.
