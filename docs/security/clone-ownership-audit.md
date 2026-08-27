# Clone & Ownership Audit (Phase 10, Prompt 2, Part C)

This document enumerates every `Clone` implementation on a secret-bearing
type in the workspace, assesses whether cloning widens secret exposure,
records the decision taken, and honestly states residual risk. **No
`Clone` impl was removed during this audit**: removing clone from the
core MPC/`Share`/`BeaverTriple` types would ripple through the public API
and is not justified by a concrete exploit — the real exposure is mitigated
by redacted `Debug` plus `Zeroize`/`ZeroizeOnDrop` where it matters. The
residual risk is documented, not papered over.

## Secret-bearing types and their `Clone` status

| Type | `Clone` | `Zeroize` | `ZeroizeOnDrop` / `Drop` | Decision |
|------|---------|-----------|--------------------------|----------|
| `crypto_core::SecretBytes` | ✅ | ✅ | ✅ (derive) | **Keep.** Each clone owns its own buffer and zeroizes it on drop. |
| `crypto_core::CommitmentRandomness` | ✅ | ✅ | ✅ (derive) | **Keep.** Same as `SecretBytes`; per-copy drop zeroization. |
| `mpc::Share<F>` | ✅ | ✅ (callable) | ❌ no `Drop` | **Keep.** Core MPC type, passed by value everywhere. Clones are *not* auto-zeroized — callers must zeroize sensitive copies. |
| `mpc::SharedValue<F>` | ✅ | ✅ (callable) | ❌ no `Drop` | **Keep.** Same rationale as `Share`. |
| `mpc::BeaverTriple<F>` | ✅ | ✅ (callable) | ❌ no `Drop` | **Keep.** Same rationale as `Share`. |
| `mpcith::PartyView` | ✅ | ✅ (callable) | ✅ (manual `Drop`) | **Keep.** Each clone zeroizes all field-element shares on drop. |
| `payment::PrivateWitness` | ✅ | ✅ (callable) | ✅ (manual `Drop`) | **Keep.** Each clone zeroizes credential secrets + amount + bit buffers on drop. |
| `mpcith::TripleShare` | ✅ | ❌ | ❌ | **Keep but redact.** Holds raw `FieldElement` shares; `Debug` is now redacted (see below). No auto-zeroize. |
| `mpcith::LocalOperation` | ✅ | ❌ | ❌ | **Keep but redact.** Holds raw `FieldElement` shares/masks; `Debug` redacted. No auto-zeroize. |
| `mpcith::Repetition` | ✅ | ❌ | ❌ | **Keep but redact.** `hidden_output_shares` are secret; `Debug` redacted. Needed by Fiat–Shamir joint binding which copies the repetition set. |
| `mpcith::OpenedView` | ✅ | ❌ | ❌ | **Keep but redact.** Contains `PartyView` (redacted) + `SecretBytes` (redacted). No auto-zeroize. |
| `proof::ProofRepetition` | ✅ | ❌ | ❌ | **Keep but redact.** `hidden_output_shares` secret; `Debug` redacted. |
| `proof::NonInteractiveProof` | ✅ | ❌ | ❌ | **Keep.** Aggregates `ProofRepetition`; no new secret exposure beyond the parts. |
| `secret_sharing::Share` | ✅ | ❌ | ❌ | **Keep but redact.** `Debug` redacts `value`. Transient; `reconstruct` returns a zeroizing `SecretBytes`. No auto-zeroize on the struct. |
| `crypto_core::Commitment` / `PublicValue<F>` | ✅ | n/a | n/a | Public values; clone is harmless. |

## Concrete hardening done this phase (secret leak via `Debug`)

Before this audit, the following types **derived `Debug` over raw
`FieldElement` values**, leaking secret shares:
`mpcith::LocalOperation`, `mpcith::TripleShare`, `mpcith::Repetition`,
`proof::ProofRepetition`. These now implement **redacted `Debug`** that
prints only structural/routing information (variant names, node ids,
counts) and never the numeric field values. `PartyView`, `PrivateWitness`,
`OpenedView`, `SecretBytes`, `CommitmentRandomness`, and the `mpc`/`secret-sharing`
share types were already redacted and are unchanged. This is covered by
`tests/secret_lifecycle_tests.rs`.

## Residual risk (documented, not resolved)

1. **Clones of `Share` / `SharedValue` / `BeaverTriple` / `TripleShare` /
   `LocalOperation` / `Repetition` / `OpenedView` / `ProofRepetition` /
   `secret_sharing::Share` are not auto-zeroized on drop.** A clone that
   outlives its use and is dropped normally leaves the secret field
   elements in freed (but not wiped) memory until the allocator reuses it.
   Mitigations: redacted `Debug` prevents accidental logging; these values
   are typically short-lived within a single prove/verify call; `PartyView`
   and `PrivateWitness` *do* zeroize on drop because they are the
   long-lived containers that aggregate the others.
2. **No `mlock` / no volatile writes.** `Zeroize` implementations issue
   `write_volatile`-style clears in the `zeroize` crate, but the OS may
   still page secret memory; locking is not used.
3. **`Clone` on `SecretBytes`/`CommitmentRandomness` is intentional and
   safe** — each copy zeroizes independently on drop — but callers that
   clone-and-forget a secret and *never* drop the original still hold a
   live copy; that is caller responsibility, not a library defect.
4. **No `dudect`/valgrind CI** verifies the constant-time claims
   (see `constant_time_tests.rs` for behavioral coverage only).

## Recommendation (future, out of audit scope)

- Add `Drop`-based zeroization to the generic MPC types (`Share`,
  `SharedValue`, `BeaverTriple`) so clones auto-wipe. This is blocked only
  by the usual Rust restriction that a `Drop` impl cannot add a bound the
  struct lacks; it requires a concrete wrapper or a careful trait-bound
  change and is a follow-up, not an audit fix.
- Consider wrapping long-lived aggregates (`Repetition`, `ProofRepetition`,
  `OpenedView`) in a zeroizing container if they are ever persisted beyond
  a single verification call.
