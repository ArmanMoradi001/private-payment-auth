# Policy Security (Phase 11)

This document records the security properties and **explicitly documented
limitations** of the `policy` crate (typed AST, normalization, evaluation,
circuit compilation). It supplements the threat model
[../threat-model.md](../threat-model.md) and ADR
[0011](../decisions/0011-policy-ast-and-normalization.md).

## Security goals for the policy layer

1. **Evaluation/circuit agreement.** The reference evaluator and the compiled
   circuit must accept exactly the same witnesses. Phase 11 makes this
   structural: *both* consume the same `normalize` output, so they cannot
   diverge in canonical order. Property tests enforce
   `circuit_never_accepts_what_evaluator_rejects`.
2. **Sound composition.** `And`/`Or`/`Threshold` must compose their children
   soundly. The amount leaf outputs a genuine boolean (Fermat-derived), so
   `Or`/`Threshold` require only the selected branch's amount bound — the
   earlier unsound constant-`1` + global-∧ design is gone.
3. **Tamper-evident policy identity.** `PolicyId` is a domain-separated SHA-256
   of the canonical encoding; replaying or modifying a policy changes the id
   and is rejected by the `payment` binding layer (`StatementMismatch`).
4. **Robust parsing.** `decode`/`validate` never panic on adversarial input
   and reject by `Err` with bounded allocation (fuzzed).

## What is provided

- **Normalization as single source of truth.** Evaluator and compiler both
  normalize; equivalence is not assumed but property-tested.
- **Fermat indicators for exact booleans.** Credential match and amount
  range windows use `x^(p−1) ∈ {0,1}`, leaving the prover no freedom to set
  an indicator to a non-boolean value and satisfy a constraint.
- **Threshold booleanity is a published constraint.** Each `Threshold` emits
  `∏ indicatorᵢ − (1 − 0^k) = 0` as a global output; a forged threshold count
  is rejected by a nonzero constraint output.
- **Bounded policies.** Structural limits (`MAX_POLICY_DEPTH = 100`,
  `MAX_POLICY_NODES = 10000`, `MAX_CREDENTIAL_COUNT = 1000`, arity caps)
  bound circuit size and prover/verifier cost.
- **Complete-witness requirement.** `evaluate` rejects missing credential
  secrets (`WitnessMismatch`), preventing accidental under-specified proofs.

## Explicit limitations (honestly documented, not papered over)

1. **In-circuit credential binding is still a placeholder.** `CredentialId`
   is supplied to the circuit as a *secret-input field element* and checked by
   field equality against the witness commitment. The real `SHA-256`
   commitment runs **outside** the circuit. A malicious prover with custom
   tooling could therefore satisfy a credential leaf without knowing the
   preimage secret. Production requires an arithmetizable hash (Poseidon/
   Rescue-style permutation) inside the circuit. Until then, credential
   *secrecy* against a malicious prover is **not** cryptographically enforced
   at the circuit level — it relies on the relation layer running the real
   hash (which an honest `authorize` does, but a malicious prover can bypass).
2. **Probabilistic / ROM soundness inherited.** The circuit's soundness is
   only as strong as the MPC-in-the-Head proof that evaluates it (forgery
   probability `(1/3)^R` under the Fiat–Shamir ROM/QROM assumptions, which are
   not formally proven in this codebase). The policy layer does not add or
   remove soundness beyond what the proof system provides.
3. **Normalization order is encoding-dependent.** Circuit input ordering
   follows the byte-sorted normalized form. A verifier that forgets to
   normalize would assemble a different public-input vector and must reject
   (`StatementMismatch`). This is enforced by `policy_public_inputs` normalizing,
   but is a regressible invariant (covered by property + payment tests).
4. **No policy revocation / expiry in the AST.** Time locks and revocation are
   not part of `Policy`; if required, they must be added as policy leaves or
   bound via the statement, not assumed.
5. **Constant-time posture is for public structure only.** Policy structure is
   public; the Fermat/exclusion arithmetic is over public circuit values during
   verification. Witness secret handling relies on `SecretBytes` zeroization
   (see the threat model) and is *not* dudect-verified.

## Adversary-relevant notes

- **Malicious prover** (threat-model §1): the policy layer's contribution is
  that the circuit it compiles is *exactly* the evaluator's semantics, so a
  proof that passes verification corresponds to a real policy satisfaction —
  modulo limitation #1 (credential preimage) and the inherited ROM soundness.
- **Malformed serialization** (threat-model §3): `decode` is panic-free and
  bounded; adversarial bytes yield `Err`, never a crash.
- **Cross-protocol / wrong-statement** (threat-model §5): `PolicyId` binding
  means a proof cannot be re-pointed at a different policy without a
  `StatementMismatch`.
