# Randomness Audit (Phase 10, Prompt 3, Part D)

This audit enumerates every source of randomness and every source of
wall-clock/time in the production `src` trees of all workspace crates, and
assesses whether any secret or nonce is ever derived from a global,
non-injectable, or time-based source.

## Method

Grep for `thread_rng`, `OsRng`, `SystemTime`, `Instant`, `StdRng`,
`ChaCha`, `CryptoRngCore`, `ChallengeSource`, and `rand::` across
`crates/*/src`, separating `#[cfg(test)]` modules from production code.

## Production-code findings (the important part)

**No global mutable RNG, no `thread_rng`, no `OsRng`, no `SystemTime`,
no `Instant`, and no `rand::` global appears anywhere in production
`src`.** Every source of randomness is injected through a typed
parameter:

| Site | Mechanism | Injectable? |
|------|-----------|-------------|
| `crypto_core::random::generate_random_bytes` | `fn<R: CryptoRngCore>(rng: &mut R, …)` | ✅ via `R` |
| `crypto_core::commitment::CommitmentRandomness::generate` | `fn<R: CryptoRngCore>(rng: &mut R)` | ✅ via `R` |
| `mpc::LocalTrustedTripleProvider` | `struct<R: CryptoRngCore>` | ✅ via `R` |
| `mpcith::prover::MpcithProver` | owns `rng: R` and `challenge_source: Box<dyn ChallengeSource>`, both supplied at construction | ✅ |
| `circuit::eval_mpc::evaluate_mpc` / `reveal_output` | `fn<R: CryptoRngCore>` | ✅ via `R` |
| `proof::Prover` | constructed with an `R: CryptoRngCore` | ✅ |

The challenge abstraction is `mpcith::ChallengeSource`, also injected:

- `RandomChallengeSource<R: CryptoRngCore>` wraps a caller-supplied `R`.
- `DeterministicChallengeSource` derives challenges from committed data
  with **no RNG at all** (used for tests and as the local fallback inside
  `MpcithProver::prove`, which swaps it in only for the duration of one
  `prove` call and restores the caller's source afterwards).

`MpcithProver::prove()` does replace `self.challenge_source` with a
`DeterministicChallengeSource` transiently, but this is still *not* a
global source — it is constructed locally and discarded; no static/thread
state is touched.

## Time sources

None. There is no `SystemTime`, `Instant`, `coarsetime`, or similar in
any `src` file. Freshness/replay protection therefore does **not** depend
on wall-clock time; it is provided by caller-supplied statement nonces
(`PaymentStatement.nonce`, `payment_id`) which are absorbed into the
Fiat–Shamir transcript (see the threat model, actor #4).

## Test-only usage (excluded from the production posture)

The following are confined to `#[cfg(test)]` modules and are therefore
out of scope for production-secret derivation, but are listed for
completeness:

- `crypto_core::random` / `commitment` tests: `OsRng` (test helpers only).
- `circuit::eval_mpc` tests: `ChaCha20Rng::seed_from_u64(…)` via
  `MpcSimulator` (test harness only).
- `mpcith::prover` / `verifier` / `transcript` tests:
  `ChaCha20Rng::seed_from_u64(…)` and `DeterministicChallengeSource`
  (test harness only).

## Residual risk (documented, not resolved)

1. **Caller-supplied RNG quality is trusted.** The API cannot stop a
   caller from passing a predictable `CryptoRngCore` (e.g., a seeded
   `ChaCha20Rng` with a guessable seed, or a constant stream). That is a
   caller responsibility and is outside the library's threat model; the
   library never *itself* introduces such a weakness.
2. **No RNG health checking / no `getrandom` enforcement.** Production
   code relies on the injected `CryptoRngCore` to be cryptographically
   secure; there is no in-library check that it is (nor should there be —
   that would require a global).
3. **`OsRng` is reachable only through test paths**; no production entry
   point constructs an OS RNG. If a future API adds a convenience
   `generate()` that defaults to `OsRng`, it must be documented as the
   *only* acceptable default and audited.

## Conclusion

The randomness posture is **clean**: every secret, mask, share, triple,
and commitment-randomness byte in production code flows from an
explicitly injected `CryptoRngCore` or from deterministic Fiat–Shamir
derivation. No global, static, thread-local, or time-based randomness
source exists in `src`.
