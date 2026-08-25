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

## Policy and Payment Layers: Assumptions and Limitations (Phase 7)

The `policy`/`payment` stack (see ADR
[0008](../decisions/0008-private-authorization.md)) introduces the
first end-to-end authorization artifacts. Their current security
envelope:

### What is provided

- **Transcript binding**: every proof embeds the full public input
  vector — including the payment amount, recipient commitment, and
  payment id as circuit inputs — in the Fiat–Shamir derivation. Any
  modification of a statement's public field after generation breaks
  verification (`StatementMismatch`), tested adversarially.
- **Relation-checked proving**: `authorize` refuses to prove before
  the plaintext relation passes, so artifacts always correspond to a
  policy-satisfying witness under the reference semantics.
- **Policy identity**: statements carry the domain-separated
  `PolicyId`; verifier-side mismatches are rejected before any proof
  work.
- **Determinism**: identical policies compile to identical circuits
  and ids, so verifiers cannot be tricked into checking against a
  different circuit than provers used.

### Explicit limitations (updated by Phase 8)

1. **RESOLVED (Phase 8): amount comparison no longer uses raw field
   arithmetic.** The window-exclusion gadget was removed and replaced
   by dual bit-decomposition: 64 booleanity/reconstruction constraints
   pin the amount and its difference-to-limit into `[0, 2^64)`,
   proving `0 ≤ amount ≤ limit` over the integers with no wrap-around.
   Forged digit witnesses are rejected (`InvalidBitWitness` at the
   relation layer, nonzero constraint outputs in-circuit).
2. **Credential binding is still a placeholder.** In-circuit credential
   checks compare commitment digests by field equality; the real hash
   runs outside the circuit. A malicious prover with custom tooling
   could prove satisfiability without knowing the preimages.
   Production requires an arithmetizable hash (e.g., Poseidon/
   Rescue-style permutation) inside the circuit.
3. **Parameterization is provisional.** `AUTHORIZATION_REPETITIONS =
   12` gives per-artifact forgery probability ≈ (1/3)¹² ≈ 1.9·10⁻⁶;
   production parameters await the cost study phase.

### Replay protection model (Phase 8)

Authorization artifacts are bound to a specific
[`PaymentStatement`] whose canonical encoding includes a fresh
32-byte `nonce` and the semantic payment id
(`SHA-256("private-payment-auth/payment/v1" ‖ payment_encoding)`).
Both are public inputs of the bound circuit and therefore part of the
Fiat–Shamir transcript: a proof for one statement verifies under no
other statement, including re-submissions that differ only in nonce.
Verifiers SHOULD track observed `(payment_id, nonce)` pairs and reject
duplicates — uniqueness enforcement is an application/verifier-policy
concern, not a cryptographic one.

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

## MPC-in-the-Head: Assumptions and Limitations (Phase 5)

The `mpcith` crate turns circuit executions into transferable
evidence. Security-relevant properties:

### What is provided

- **Commit-before-challenge**: all three party views are committed
  with fresh randomness before the challenge exists, so the challenge
  decides which corruption (if any) is exposed.
- **2/3 per-repetition detection**: any cheating view is opened unless
  it belongs to the challenged-hidden party; R independent repetitions
  give forgery probability (1/3)^R under random challenges.
- **No secret leakage from proofs or transcripts**: opened views
  contain only shares of secrets and public broadcast masks; the
  hidden party appears solely through commitments, its broadcast
  contributions (public in any real execution), and its output share.
  `Debug` output of share-bearing types is redacted.
- **Independent verification**: the verifier re-implements semantics;
  prover bugs cannot masquerade as verifier behavior.

### Limitations — explicitly NOT provided

- **Fiat–Shamir deferred**: challenges come from an injectable source.
  Until FS lands, the proof is an *interactive* argument; a malicious
  prover who can see/choose challenges adaptively could always name
  its corrupted party as hidden. This is the single most important
  open gap (ADR 0006).
- **Soundness is probabilistic**: a 1-repetition proof accepts a
  cheated execution with probability 1/3 by design; security
  amplification requires many repetitions (and then FS).
- **Hash-based commitments are not hiding against quantum adversaries**
  and rely on SHA-256 collision resistance in the standard model;
  formal assumptions remain an open ADR item.
- **Triple generation is trusted-local**: `LocalTrustedTripleProvider`-
  style randomness inside the prover simulates an honest dealer;
  distributed triple generation is future work.
- **No replay protection across statements**: the same proof verifies
  forever against the same statement; freshness binding belongs to the
  future policy/verifier layers.
