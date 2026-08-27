# Threat Model (Skeleton)

> **Status: Phase 10 — production hardening and audit.** Decoders are now
> panic-free and bounded (see `tests/parser_robustness_tests.rs`); secret
> containers implement `Zeroize`/`ZeroizeOnDrop` (added in Phase 10 to
> `PartyView`, `PrivateWitness`, `Share`, `SharedValue`, `BeaverTriple`);
> the MPCitH dependency graph is evaluated iteratively (no recursion
> blow-up). The systematic threat-actor catalog below enumerates 10
> adversary classes, each with its targeted asset, attack surface, existing
> mitigation, and **honestly documented remaining risk** (we do *not* change
> protocol semantics to paper over weaknesses — see
> [phase-10-audit-report.md](phase-10-audit-report.md)).

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

The Phase 9 skeleton listed four informal adversary classes. Phase 10
replaces that with a concrete catalog of **10 threat actors** below
(`## Threat Actor Catalog`). Each entry lists the **asset** at risk, the
**attack surface** (concrete code/API), the **mitigation** that exists
today, and the **remaining risk** we have *not* resolved (and will not
resolve by silently changing protocol semantics).

## Threat Actor Catalog (Phase 10)

### 1. Malicious prover (forging authorization artifacts)

- **Asset**: soundness of the proof system / unforgeability of
  authorization.
- **Attack surface**: `mpcith::MpcithProver`, `proof::Prover`, the
  relation check in `payment::authorize`.
- **Mitigation**: the verifier re-implements MPC semantics independently
  (`MpcithVerifier`, `proof::Verifier`) — prover bugs cannot masquerade
  as verifier behavior. Commit-before-challenge; ≥2/3 per-repetition
  cheating detection; Fiat–Shamir challenges are jointly bound to
  `(statement, circuit_id, policy_id, backend_id, repetition, party)`
  with domain separation. `AUTHORIZATION_REPETITIONS` (12) gives forgery
  probability ≈ (1/3)¹².
- **Remaining risk**: soundness is *probabilistic* — a 1-repetition proof
  accepts a cheated execution with probability 1/3 by design; security
  amplification depends on repetition count and on the Fiat–Shamir ROM/QROM
  assumptions, which are **not formally proven** in this codebase. Credential
  binding is still a placeholder (commitment digests compared in-circuit,
  real hash runs outside).

### 2. Malicious / compromised verifier environment

- **Asset**: verifier integrity; secret-free by design but its correctness
  is trusted.
- **Attack surface**: `verifier` crate, `proof::Verifier`,
  `mpcith::MpcithVerifier`.
- **Mitigation**: the verifier holds no secret state and emits only
  accept/reject plus a public `VerificationResult`; it consumes no
  secret inputs. Backend pinning (`UnsupportedBackend`) prevents it from
  being tricked into a weaker hash.
- **Remaining risk**: verifier correctness is *assumed*, not machine-checked
  or formally verified. A buggy verifier could accept invalid artifacts.

### 3. Malicious external input (malformed serialization)

- **Asset**: availability and memory safety of parsers/decoders.
- **Attack surface**: every `decode`/`deserialize` path — `Share::decode`,
  `circuit::deserialize`, `mpcith::decode_{view,proof,repetition,challenge}`,
  `proof::deserialize_proof`/`Statement::decode`, `Amount::decode`,
  `PaymentStatement::decode`.
- **Mitigation**: all decoders are **panic-free** (verified by
  `tests/parser_robustness_tests.rs` against random + curated malformed
  bytes); they reject via `Err`, check version first, check length before
  allocation, and clamp allocation capacity (`.min(1024)`) so a 4-byte
  length field cannot trigger a 4 GB allocation.
- **Remaining risk**: decoders reject *malformed* input but do not
  cryptographically authenticate it; a man-in-the-middle who can modify
  bytes produces parse errors (DoS, not forgery). Integer/boundary
  conversions (e.g., field-element canonicalization) are unit-tested but
  not exhaustively proven.

### 4. Replay attacker

- **Asset**: freshness / single-use of an authorization artifact.
- **Attack surface**: `PaymentStatement` nonce + payment id; verifier-side
  dedup policy.
- **Mitigation**: every statement's canonical encoding includes a fresh
  32-byte `nonce` and a semantic payment id
  (`SHA-256("private-payment-auth/payment/v1" ‖ payment_encoding)`); both
  are public circuit inputs and therefore part of the Fiat–Shamir
  transcript. A proof for one statement verifies under no other statement,
  including re-submissions differing only in nonce.
- **Remaining risk**: duplicate detection is an *application/verifier
  policy* concern, **not** cryptographically enforced. A verifier that does
  not track observed `(payment_id, nonce)` pairs will re-accept the same
  artifact indefinitely.

### 5. Cross-protocol / wrong-statement attacker

- **Asset**: statement/circuit/policy binding.
- **Attack surface**: `proof::Statement`, `mpcith::Statement`,
  `PaymentStatement` field binding.
- **Mitigation**: verification rejects `StatementMismatch`; the FS transcript
  binds the *full* public input vector, the `CircuitId`, the `PolicyId`, and
  the backend. Changing any public field, the circuit, the policy, or the
  backend breaks verification.
- **Remaining risk**: if a verifier deliberately skips the policy-id check,
  it can be convinced to verify against a different policy than intended —
  the *binding* is present but *enforcement* is the verifier's
  responsibility. No signed/committed policy root exists yet.

### 6. Cross-version attacker

- **Asset**: encoding stability / downgrade protection.
- **Attack surface**: `ENCODING_VERSION` / `PROTOCOL_VERSION` checks in all
  decoders.
- **Mitigation**: decoders reject unknown/unsupported versions
  (`UnsupportedVersion`, `UnsupportedProtocolVersion`, `MalformedEncoding`);
  `serialize`/`deserialize` round-trip is tested.
- **Remaining risk**: there is **no forward-compatibility or version
  migration policy**. A newer artifact is simply rejected by an older
  decoder (safe, but no upgrade path is defined).

### 7. Cross-backend attacker

- **Asset**: backend/parameter binding.
- **Attack surface**: `BackendId`, `proof::Verifier::<B>::verify`,
  `mpcith` backend pinning.
- **Mitigation**: `Verifier::<B>` rejects any proof with
  `backend_id ≠ B::ID` via `UnsupportedBackend` before any cryptographic
  work; FS input includes `B::ID` so challenges are backend-specific; SHA-256
  and SHAKE256 produce distinct digests.
- **Remaining risk**: a verifier not pinned (or mis-configured) could accept
  a weaker backend; nothing *auto-negotiates* or *requires* a hybrid
  (SHA-256 + SHAKE256) proof. Backend agility is not, by itself,
  post-quantum security (see Phase 9 section).

### 8. State-confusion attacker

- **Asset**: correctness of stateful / interactive proving APIs.
- **Attack surface**: `MpcithProver` (`commit_phase` /
  `finish_repetition` / `prove_joint_fs`), `proof::Prover` (atomic
  `prove`).
- **Mitigation**: the non-interactive `proof::Prover` exposes only
  `new()` + `prove()` (atomic), removing most ordering hazards. Interactive
  MPCitH methods return typed errors on misuse (e.g., challenging before all
  commitments exist).
- **Remaining risk**: the interactive prover has **no machine-checked state
  machine**; out-of-order calls are documented to error but are not formally
  guaranteed. This is captured honestly in
  [phase-10-audit-report.md](phase-10-audit-report.md) rather than "fixed"
  by changing semantics.

### 9. Resource-exhaustion attacker

- **Asset**: CPU / memory availability of prover and verifier.
- **Attack surface**: circuit size, proof repetition count,
  share count, policy depth, credential count.
- **Mitigation** (all added/verified in Phase 10):
  `circuit::MAX_CIRCUIT_NODES = 1_000_000`,
  `proof::MAX_PROOF_REPETITIONS = 10_000`,
  `mpcith::MAX_REPETITIONS = 10_000`,
  `secret_sharing::MAX_SHARE_COUNT = 1000` (also bounds the O(n²) duplicate
  check in `reconstruct`), `policy::MAX_POLICY_DEPTH = 100`,
  `policy::MAX_CREDENTIAL_COUNT = 1000`. Decoders clamp allocation
  capacity before `with_capacity`. The MPCitH dependency walk is iterative
  (no recursion stack overflow on deep circuits).
- **Remaining risk**: a *valid* but large proof (e.g., `n_reps` just under
  the cap) still costs O(n_reps · circuit_size) to verify; there is no
  global per-request memory ceiling beyond the individual caps. The caps are
  policy choices, not derived from a threat model parameter.

### 10. Secret-extraction / side-channel attacker

- **Asset**: secret shares, witness material, commitment randomness,
  intermediate MPC values.
- **Attack surface**: `SecretBytes`, `CommitmentRandomness`,
  `mpcith::PartyView`, `payment::PrivateWitness`, `mpc::Share` /
  `SharedValue` / `BeaverTriple`, `crypto_core` comparisons.
- **Mitigation**: `SecretBytes` and `CommitmentRandomness` derive
  `Zeroize`+`ZeroizeOnDrop` with redacted `Debug`; digest and commitment
  comparisons use `subtle::ConstantTimeEq` (`Digest::ct_eq`,
  `Commitment::ct_eq`, `verify_commitment`); **no secrets are placed in
  error values**; no global mutable RNG / `SystemTime` / `thread_rng` exists
  in `src` (only `CryptoRngCore` passed in). Phase 10 added `Zeroize`
  (callable) to `Share`/`SharedValue`/`BeaverTriple` and `Zeroize`+`Drop` to
  `PartyView` and `PrivateWitness` (zeroizing credential secrets, amount,
  and bit-decomposition buffers on drop).
- **Remaining risk**: `ZeroizeOnDrop` is used as a marker but **does not
  emit `volatile` writes / `mlock`** — compiler elision of zeroization is
  not formally guaranteed. Field-element arithmetic comparisons in the
  verifier are *not* constant-time (they operate on public reconstruction
  shares, so this is acceptable but undocumented-as-constant-time). There is
  **no `dudect`/valgrind CI verification** of constant-time claims, no
  `mlock`, and secret containers still implement `Clone` (cloning secrets is
  permitted by API). See [clone-ownership-audit.md](clone-ownership-audit.md)
  and [randomness-audit.md](randomness-audit.md).

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

## Cryptographic Backend Abstraction: Assumptions and Limitations (Phase 9)

Phase 9 introduces `CryptoBackend` with `Sha256Backend` (default) and
`Shake256Backend` (SHA-3 XOF). It does **not** replace SHA-256; it makes
the hash/XOF layer pluggable and binds each proof to the backend that
produced it.

### What is provided

- **Non-displacement of SHA-256**: `Sha256Backend::hash` equals the
  historical `Sha256Hash::hash` byte-for-byte, and `commit` keeps the
  legacy framing. Every pre-Phase-9 SHA-256 test vector remains valid; the
  default protocol bytes are unchanged.
- **Backend-bound proofs**: `NonInteractiveProof` carries a `BackendId`;
  `Verifier::<B>::verify` rejects any proof with `backend_id ≠ B::ID`
  via `UnsupportedBackend` before performing any cryptographic work. This
  defeats both cross-backend acceptance and post-hoc relabeling of a
  proof's backend.
- **Backend-bound Fiat–Shamir**: `fs_input` includes `B::ID`, so
  challenges are backend-specific; a proof's challenges cannot be
  recomputed under a different backend.
- **Distinct digests across backends**: for identical input, SHA-256 and
  SHAKE256 produce different digests, which is what makes the binding
  meaningful rather than cosmetic.

### Limitations — explicitly NOT provided

1. **Backend agility is not, by itself, post-quantum security.** Only the
   hash/XOF layer is swapped. The MPC-in-the-Head soundness, field
   arithmetic, and commitment *framing* still rely on the same
   assumptions as before. `Shake256Backend` is a SHA-3 primitive whose
   collision/resistance is believed to resist known quantum attacks, but
   deploying it as a real PQ upgrade requires re-deriving the full
   protocol's concrete security under the QROM — out of scope for this
   phase. See [cryptographic-assumptions.md](cryptographic-assumptions.md).
2. **No hybrid / hedged construction.** There is exactly one backend per
   proof; there is no parallel dual-hash composition. A single backend
   compromise (e.g., a future break of SHA-256) would affect all
   SHA-256 proofs. A production deployment that needs PQ hedging should
   issue *two* proofs (SHA-256 + SHAKE256) and require both, which the
   abstraction now makes straightforward but does not do automatically.
3. **Verifier backend choice is a configuration decision.** A verifier
   pinned to `Sha256Backend` will not accept `Shake256Backend` proofs and
   vice versa. Systems that must accept both must explicitly try each
   configured backend; nothing auto-negotiates.
4. **Shared code paths.** `commit` framing, domain separators, and the FS
   transcript structure are identical across backends; only the underlying
   compression/XOF differs. Backend-specific implementation bugs (e.g., in
   `expand`) affect whichever backend uses them, but a bug in shared logic
   affects all backends.
5. **Repetition count and FS security model unchanged.** Switching backend
   does not change the forgery probability `(1/3)^R` or the ROM/QROM
   assumptions of the Fiat–Shamir transformation.
