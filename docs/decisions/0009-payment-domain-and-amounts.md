# ADR 0009: Payment Domain and Safe Amount Binding

* Status: Accepted (Phase 8)
* Deciders: `payment` crate maintainers
* Date: 2026-08

## Context

Phase 7 shipped the authorization pipeline but left two deliberate
gaps: amounts were constrained by an unsound window-exclusion product
(`docs/decisions/0008` §4), and there was no explicit payment domain —
statements carried a bare `u64`, no protocol/circuit binding, and no
freshness material. Phase 8 closes the amount hole and introduces the
payment domain.

## Decision

### 1. Payment model and amount semantics

- **`Amount { value: u64, unit: AmountUnit }`** — money is an exact
  count of integer units (currently `Cents`). `u64::MAX` is the
  maximum representable amount. Canonical encoding:
  `version(u8) ‖ value(u64 BE) ‖ unit(u8)`.
- **No silent casting.** There is no conversion from field elements to
  `Amount`. Field values live modulo `p ≈ 2^252`; anything that did
  not originate as a `u64` must be rejected, not reduced. The circuit
  layer proves the *field-side* value is small enough to correspond to
  a `u64` (see below); the plaintext side never converts.
- **`Payment`** — payer-side record: format version, raw payment id,
  typed amount, recipient commitment, and a fresh 32-byte nonce.
  Semantic identity:
  `SHA-256("private-payment-auth/payment/v1" ‖ canonical_encoding)`.
- **Bound `PaymentStatement`** — fixed-width canonical binding of
  semantic payment id, amount, recipient commitment, policy id,
  circuit id, protocol version, and nonce. Decoding is strict:
  truncation, trailing bytes, unknown versions, unknown units are all
  errors.

### 2. Dual bit-decomposition range check

To prove `amount ≤ limit` soundly in the `{+, ×}` circuit language,
the witness supplies:

- the 64 little-endian binary digits of the amount `v`
  (`SecretSlot::AmountBit(i)`), and
- the 64 little-endian binary digits of `d = limit − v`
  (`SecretSlot::DifferenceBit(i)`).

The gadget publishes four outputs that honest executions pin to
exactly zero:

1. `Σᵢ bᵢ·(1 − bᵢ)` over the amount digits (booleanity);
2. `Σᵢ bᵢ·2ⁱ − v` (reconstruction of the claimed amount);
3. booleanity sum over the difference digits;
4. `Σⱼ dⱼ·2ʲ − d` (reconstruction of the difference).

Why this prevents wrap-around: accepting proofs satisfy `v = Σ bᵢ2ⁱ ≤
2^64 − 1` and `d = Σ dⱼ2ʲ ≤ 2^64 − 1` *as integers*, so `v + d = limit`
holds without modular reduction, forcing `0 ≤ v ≤ limit < 2^64`. When
`v > limit`, `limit − v (mod p) = p − (v − limit) > 2^64 − 1`; no
64-digit assignment reconstructs it, output (4) cannot vanish, and the
proof fails. The phase 7 window product instead excluded only a finite
window above the limit and silently accepted everything outside it —
including wrapped values; it has been removed entirely
(`AMOUNT_BOUND` no longer exists).

Cost: ~700 gates per amount leaf (~5 gates per digit × 128 digits plus
sums), replacing the O(limit) window product. Property tests enforce
`reference_range_check(amount, limit) == circuit acceptance` over
randomized pairs.

### 3. Replay model (`payment_id` + nonce)

Every statement embeds a fresh 32-byte `nonce` alongside its semantic
payment id, and both flow into the bound circuit's public inputs —
hence into the Fiat–Shamir transcript. Consequences:

- A proof verifies under exactly one statement encoding; any mutation
  (id, amount, recipient, nonce, policy, circuit, version) breaks
  verification. This is enforced adversarially in tests.
- Replaying the same artifact against the same statement is detectable
  by verifiers tracking observed `(payment_id, nonce)` pairs;
  freshness generation (choosing nonces once) belongs to the payer
  SDK layer.

### 4. Public/private boundary

| Data | Visibility |
| --- | --- |
| Policy structure, commitments, limits | Public |
| Payment id, amount, recipient commitment, nonce | Public (statement) |
| Circuit id, protocol version | Public (statement) |
| Credential secrets, binary digit witnesses, aux inversion witnesses | Private (witness) |

Digit witnesses are private even though they are fully determined by
public values: proving knowledge of a consistent decomposition is the
point, revealing them would leak nothing but is unnecessary.

### 5. Phase 7 amount implementation: removed/replaced

The window-exclusion gadget, the compile-time `AMOUNT_BOUND`
constant, and the "amount caps are global assertions" caveat attached
to them were **removed**. The compiler now emits the four published
zero-constraints per `AmountAtMost` leaf plus a neutral combinator
wire; `CompiledPolicy::range_check_outputs` tells consumers how many
leading outputs must be zero (the trailing root output must equal the
statement-binding product). The ADR 0008 §4 limitation stands as
documentation of the replaced design only.

## Consequences

- Amounts are now bound safely end-to-end: boundary amounts (0, 1,
  limit−1, limit) verify; `limit+1`, `u64::MAX`, and forged digit
  witnesses fail at generation or verification.
- Statement tampering across all seven public fields breaks
  verification (tested exhaustively).
- Proof sizes/grow times increase modestly with the extra digit
  witnesses; benchmarks track both pipelines during transition.
