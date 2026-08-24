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

## Shamir Secret Sharing: Assumptions and Limitations (Phase 2)

The `secret-sharing` crate implements classic (verifier-free) Shamir
secret sharing over the ed25519 scalar field. Its security model and
limits:

### What is provided

- **Information-theoretic confidentiality below the threshold**: any set
  of fewer than `t` shares reveals exactly zero information about the
  secret (perfect secrecy of Shamir's scheme); this holds regardless of
  adversary computation power.
- **Availability above the threshold**: any `t` distinct shares fully
  determine the secret; reconstruction is deterministic.

### Assumptions

1. **Honest dealers and honest share holders**: shares are generated by
   a trusted dealer using a cryptographically secure RNG
   (`CryptoRngCore`). A biased or leaking RNG can break confidentiality.
2. **Authenticated, private share distribution**: this crate does not
   authenticate shares to their recipients. Transport must prevent
   substitution or tampering with shares in transit.
3. **Secure erasure**: reconstructed secrets are returned as
   zeroizing `SecretBytes`; callers must not persist them unprotected.

### Limitations — explicitly NOT provided

- **No malicious security**: a corrupted shareholder can supply a wrong
  share during reconstruction. There is no complaint mechanism, no
  consistency check beyond index/metadata validity, and no identification
  of cheaters. Reconstruction with any corrupted share yields garbage.
- **No verifiable secret sharing (VSS)**: shareholders cannot verify that
  the dealer dealt consistent shares. A malicious dealer can distribute
  inconsistent shares such that different subsets reconstruct different
  values.
- **No proactive/refresh support**: shares are static; there is no
  re-sharing or share refresh protocol.
- **Size restriction**: secrets must be at most 32 bytes and represent
  an integer strictly below the field modulus
  (`p = 2^252 + 27742317777372353535851937790883648493`); larger inputs
  are rejected (`SecretTooLargeForField`). Secrets are canonicalized by
  stripping leading zero bytes.
- **No threshold-crypto**: this is plain secret sharing, not threshold
  signatures or threshold encryption; no share-combinable public keys.

Consequence for upper layers: until VSS or MPC-based verification is
added, `split`/`reconstruct` may only be deployed where the dealer and
at least `t` shareholders are trusted to be honest.

## Arithmetic Circuits: Assumptions and Limitations (Phase 4)

The `circuit` crate defines the *statement* to be authorized. Its
security-relevant properties:

### What is provided

- **Deterministic semantics**: node ids are positional and
  topological; evaluation is a single forward pass, so identical call
  sequences always produce byte-identical circuits and identical
  circuit ids.
- **Hash-bound identity**: `CircuitId` is a domain-separated SHA-256
  over the canonical encoding. Substituting a different policy circuit
  (changed constant, gate, ordering, inputs, or outputs) is detected
  by id mismatch — this is what future policy-integrity checks will
  bind to.
- **No secrets in structure or transcripts**: circuits contain only
  public structure; transcript events carry node ids only, never
  field values. Secret values live solely in MPC shares until an
  explicit caller-initiated reveal.
- **Dual-evaluator equivalence**: randomized property tests enforce
  that the MPC evaluation of a circuit matches its plaintext reference
  evaluation, guarding against protocol bugs that would silently
  authorize wrong policies.

### Limitations — explicitly NOT provided

- **Circuit identity is not yet authenticated**: nothing prevents an
  attacker from substituting both a circuit and artifacts computed
  under it; binding ids into signed/committed policy commitments is
  future work (`policy` layer).
- **No overflow/range constraints beyond the field**: arithmetic wraps
  in the prime field; amount-limit policies must account for modular
  semantics.
- **Reveal policy is caller-controlled**: `reveal_output` exists so
  reveals are transcript-visible, but nothing yet *enforces* which
  outputs may be opened; enforcement belongs to the future verifier /
  policy layers.
- **Constant-time concerns do not apply** to circuit structure (it is
  public), but the MPC layer's constant-time posture is unchanged.
