# ADR 0008: Private Payment Authorization (Policy and Payment Layers)

* Status: Accepted (Phase 7)
* Deciders: `policy` / `payment` crate maintainers
* Date: 2026-08

## Context

Phases 1–6 delivered the machinery: hashing and commitments
(`crypto-core`), Shamir sharing, additive MPC (`mpc`), arithmetic
circuits (`circuit`), MPC-in-the-Head (`mpcith`), and non-interactive
Fiat–Shamir proofs (`proof`). What was missing is the *application*
semantic: what a payment authorization actually claims, which data is
public versus private, how policies are expressed, and how a payer
proves — without revealing credentials — that a specific payment is
allowed.

Phase 7 fills that gap with the `policy` crate (policy model +
deterministic circuit compiler) and the `payment` crate (statement,
witness, reference relation, proof integration).

## Decision

### 1. The authorization relation

A payment `(statement, witness)` is authorized under a policy `P`
exactly when:

1. `PolicyId(P) == statement.policy_id` — the payment names its policy;
2. the witness supplies one well-formed secret per declared credential;
3. every credential secret hashes to its committed value:
   `SHA-256(secret) == expected_commitment`;
4. the number of matching credentials meets every threshold `k`, and
   the amount satisfies every cap, combined through the tree's
   `And`/`Or` logic.

This relation exists twice, by design:

- *In the clear*: `payment::AuthorizationRelation::validate` runs it
  before proving (never prove an invalid claim) and serves as the
  executable specification.
- *In arithmetic*: the same semantics compiled to `{+, ×}` gates,
  proven via the generic `proof` stack. The plaintext run must agree
  with the circuit's reference evaluation; disagreement aborts.

Verification is witness-free: the verifier rebuilds the bound circuit,
its public inputs, and the expected output from public data alone.

### 2. Public vs. private data boundaries

| Data | Visibility | Where it lives |
| --- | --- | --- |
| Policy structure, commitments, limits | Public | `Policy`, `CredentialPolicy` |
| `PolicyId`, `CircuitId` | Public | derived digests |
| Payment id, amount, recipient commitment | Public | `PaymentStatement` |
| Credential secrets | **Private** | `PrivateWitness` (zeroizing) |
| Amount as a circuit wire | **Private** input | secret slot |
| Auxiliary inversion witnesses | **Private** | secret slots |
| Proof artifacts | Public | `NonInteractiveProof` |

Binding mechanism: the three public payment fields are appended to the
circuit as extra public inputs multiplied into the root wire. The Fiat–
Shamir derivation hashes the full statement encoding, so proofs are
cryptographically tied to the exact payment they authorize — tampering
with any public field after generation breaks verification.

Privacy boundary: proofs reveal nothing about credential secrets beyond
the policy-satisfaction claim, per the underlying MPCitH zero-knowledge
argument. Note the *statement's* amount is public by construction.

### 3. Policy model and threshold semantics

`Policy` is a small recursive data language:

- `Threshold { k, credentials }` — satisfied when **at least `k` of
  the `n` listed credentials are valid**, i.e., their supplied secrets
  hash to the committed values. Semantics are "at least" (monotone):
  more valid credentials never hurt.
- `AmountAtMost { limit }` — satisfied when the payment amount does not
  exceed `limit` (inclusive), under the window discipline below.
- `And { .. }` / `Or { .. }` — boolean conjunction/disjunction over
  sub-policies, evaluated depth-first in canonical order.

Compilation is fully deterministic (fixed traversal, gate order, and
constants), so equal policies produce identical circuits and identical
`CircuitId`s — a prerequisite for verifier-side reconstruction.

Because the circuit machine has no comparison or hash gates — and the
MPC layers can evaluate only `Add`/`Mul` on shared values — constraints
compile to two gadgets instead of native nodes:

- *Fermat indicator*: `x^(p−1)` equals `1` iff `x ≠ 0`, giving exact
  match booleans (`match_i = 1 − (sᵢ − cᵢ)^(p−1)`) with no prover
  freedom.
- *Inverted exclusion product*: a leaf emits `w = X·aux` where `X` is
  a polynomial vanishing exactly on the violating set (threshold:
  `Π_{t<k}(Σmatch − t)`; amount: `Π over the window above the limit`).
  Then `w ≡ 0` when violated and `w = 1` is reachable via `aux = X⁻¹`
  exactly when satisfied. Combinators compose soundly because each
  child wire is either pinned to `0` or settable to exactly `1`.

### 4. CRITICAL LIMITATION: `AmountAtMost` is not production-safe

The amount constraint uses **raw field arithmetic**. Concretely, it
proves `amount ∉ (limit, AMOUNT_BOUND]` for a compile-time constant
bound — *not* `amount ≤ limit` over the integers.

Consequences an attacker could exploit against a production deployment:

- **Wrap-around**: field elements near `p` behave like huge integers,
  not negative ones; any value outside the excluded window passes.
- **Unbounded escape**: amounts strictly greater than `AMOUNT_BOUND`
  are unconstrained by the window product.

Therefore the current constraint is suitable only for testing and
demonstrating the pipeline. It must NOT gate final financial amounts.
A future phase will introduce a safe fixed-width financial amount
representation — bit-decomposition of the amount inside the circuit
with per-bit booleanity and range checks — so that ordering comparisons
are exact and wrap-around impossible. The public API (`AmountAtMost`,
`PaymentStatement.amount: u64`) is expected to survive that change;
only the compiled gadget changes.

A parallel placeholder applies to credentials: the real SHA-256 check
runs outside the circuit; in-circuit equality compares commitment
digests as field elements. Production requires an arithmetizable hash
permutation (Poseidon/Rescue family) proven inside the circuit.

### 5. Why a full policy DSL is deferred

A richer language (time locks, spending velocity, delegation,
arbitrary predicate composition) would need: a parser and AST with
versioned canonical encoding, type checking over typed inputs, new
circuit gadgets per construct (each requiring fresh soundness analysis
in both evaluators and the MPCitH replay), and cross-implementation
test vectors for every encoding. Phase 7 deliberately ships the four
constructs whose compilation is sound and analyzed, keeping the
encoding stable so later constructs can extend the tag space without
breaking existing `PolicyId`s. The enum-based model already gives
exhaustive pattern matching at every consumer; a DSL would add surface,
not power, until the gadget library matures.

## Consequences

- End-to-end authorization now works: policy → circuit → statement-
  bound proof → witness-free verification, exercised by integration
  tests (satisfied thresholds, partial validity, failures, tampering).
- The documented limitations above are tracked for future phases;
  none of them affect the layered architecture or the public APIs.
- Benchmarks exist for compile/prove/verify to inform the parameter
  study that will replace the provisional repetition count.
