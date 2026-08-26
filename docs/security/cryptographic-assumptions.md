# Cryptographic Assumptions

> **Status: Phase 9.** This document records the concrete hardness and
> modeling assumptions the `private-payment-auth` protocols rely on, with a
> specific focus on what the new `CryptoBackend` abstraction does and does
> *not* change.

## Hash function assumptions

All backends implement the `CryptoBackend` contract (`hash`, `hash_domain`,
`expand`, `commit`). The assumptions differ by backend:

### SHA-256 (`Sha256Backend`, default)

- **Collision resistance** of SHA-256 in the standard model: it is
  infeasible to find `x ≠ y` with `SHA-256(x) = SHA-256(y)`. This underpins
  commitment binding and circuit/statement identity.
- **Preimage resistance** of SHA-256.
- For the Fiat–Shamir transformation, challenges are modeled as random
  oracle outputs. When instantiated with SHA-256, the standard "Fiat–Shamir
  heuristic" assumes the ROM; concretely this is the *correlated-input /
  programmability* of SHA-256 as a random oracle. No quantum resistance is
  claimed: Grover's algorithm gives a quadratic speedup for preimage search.

### SHAKE256 (`Shake256Backend`)

- **Sponge security / XOF indistinguishability** of SHAKE256 (Keccak
  family) in the standard model, with capacity 512 bits.
- SHA-3 primitives are believed to resist known quantum collision/preimage
  attacks better than SHA-2 (no structured quantum attack is known), which
  is why this backend is the "post-quantum-ready" path. **This is a belief
  about the primitive, not a proof that the whole protocol is
  post-quantum-secure** (see below).

## What backend agility changes

- The *only* relocated assumption is "the compression/XOF primitive is
  collision-resistant / random-oracle-like." That assumption moves from
  SHA-2 to SHA-3 when `Shake256Backend` is selected.
- Everything else — field arithmetic, MPC-in-the-Head soundness, commitment
  *structure*, Fiat–Shamir *use* — is unchanged.

## What backend agility does NOT change

1. **Field / circuit layer.** Arithmetic is over the ed25519 scalar field.
   No lattice / code-based / isogeny assumption is introduced. A quantum
   computer breaks the discrete-log-adjacent structure only insofar as the
   field's size permits (ed25519's 252-bit field is *not* quantum-safe).
2. **MPC-in-the-Head soundness.** Soundness error is `(1/3)^R` per the
   3-party corruption model; this is information-theoretic and backend-
   independent.
3. **Protocol transform.** The Fiat–Shamir heuristic is still a heuristic;
   selecting SHAKE256 does not upgrade it to a provable QROM result without
   a dedicated analysis.
4. **Commitment framing / domain separators.** These are identical across
   backends; only the underlying digest differs.

## Concrete security takeaways

- A deployment that needs a *post-quantum* authorization must combine the
  SHAKE256 backend with a PQ-safe field/arithmetic layer (e.g., a lattice-
  or hash-based field), which is **out of scope for Phase 9**.
- Until then, `Shake256Backend` should be read as "hash-layer agility and a
  SHA-3 option," not "the system is now quantum-safe."
- Recommended interim posture for high-assurance settings: issue and require
  **both** a SHA-256 and a SHAKE256 proof for the same statement, so a
  break of either primitive alone does not enable forgery. The abstraction
  makes producing the second proof a one-line configuration change.

## Randomness

- All backends assume a cryptographically secure RNG (`CryptoRngCore`) for
  commitment randomness, challenge seeds, and triple masks. A biased or
  leaked RNG breaks hiding/soundness regardless of backend.
- `expand` for `Shake256Backend` is a deterministic XOF; for
  `Sha256Backend` it is iterative SHA-256. Neither consumes randomness.

## Out of scope

- Formal reductions for the full non-interactive proof under QROM.
- Side-channel resistance beyond constant-time comparison of digests and
  commitments (see the threat model's open questions).
- Verifiable secret sharing / malicious-secure MPC (see earlier sections).
