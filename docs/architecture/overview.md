# Architecture Overview

> **Status: Phase 0 — Repository Foundation.** No cryptographic
> implementation has started. This document describes the *intended*
> architecture only.

## Purpose

This project provides cryptographic payment authorization built on
secure multi-party computation (MPC) principles: a payment is authorized
by producing a proof that a set of parties jointly evaluated the
authorization policy over secret inputs, without revealing those inputs.

## Layered Design

The system is organized in strict layers. Dependencies may only point
downward; see [dependency-boundaries.md](dependency-boundaries.md) for
the enforced rules.

```
            +-----+
            | sdk |                 public entry point
            +-----+
       -------|-------------------
        +---------+  +-------+     application layer
        | payment |  | sdk   |
        +---------+  +-------+
             |          |
        +---------+ +--------+    authorization layer
        | policy  | | verifier|
        +---------+ +--------+
             |
        +---------+              proof layer
        | proof   |
        +---------+
             |
        +---------+              protocol layer
        | mpcith  |
        +---------+
             |
        +---------+              MPC layer
        | mpc     |
        +---------+
             |
   +---------------+ +--------+
   | secret-sharing| | crypto-core | primitives layer
   +---------------+ +--------+
```

## Crates

| Crate             | Intended responsibility |
| ----------------- | ----------------------- |
| `crypto-core`     | Foundational traits and implementations: hashing, commitments, canonical encoding, secret handling, randomness, field arithmetic, Fiat–Shamir transcripts. Depends on nothing internal. |
| `secret-sharing`  | Shamir-style secret sharing and reconstruction of keys and protocol inputs, built on `crypto-core`. |
| `mpc`             | The MPC protocol layer: distributed evaluation of the authorization computation over shared secrets. |
| `mpcith`          | MPC-in-the-Head constructions that turn `mpc` protocol executions into zero-knowledge proof components. |
| `policy`          | Authorization policy definition and evaluation: spending limits, multi-party approval rules, time locks, and their commitments. |
| `proof`           | The abstract zero-knowledge proof interface built on `mpcith`, including Fiat–Shamir transformation and serialization of proofs. |
| `payment`         | End-to-end payment authorization orchestration: composes proofs and policies into authorization flows. Deliberately insulated from the MPC layers. |
| `verifier`        | Standalone verification of authorization artifacts, independent of the proving side. |
| `sdk`             | The single stable public entry point for external consumers, re-exporting curated APIs from the crates above. |

## `crypto-core` Abstractions (Phase 1)

Implemented abstractions and their contracts:

- **`Digest`** — fixed-size (32-byte) typed hash output. Hex-formatted in
  `Debug`/`Display`; equality is constant-time (`subtle::ConstantTimeEq`)
  behind both an explicit `ct_eq` and the standard `PartialEq`, so
  ordinary `==` never leaks through timing.
- **`SecretBytes`** — owned secret container wrapping a `Vec<u8>` with
  `Zeroize` + `ZeroizeOnDrop`; its `Debug` output is always
  `SecretBytes([REDACTED])`, preventing accidental secret leakage into
  logs. Mutable access exists solely for filling fresh randomness.
- **`HashFunction`** — algorithm-agnostic trait (`hash`, `hash_domain`);
  `Sha256Hash` is the first implementation. `hash_domain` canonically
  length-frames the domain, making cross-domain collisions impossible.
- **`CanonicalEncode`** — injective canonical encoding: variable-length
  data is framed with a 4-byte big-endian length; fixed-size values
  (`Digest`) are written raw. Implemented for `&[u8]` and `SecretBytes`.
- **Commitments** — `commit::<H>(message, &randomness)` computes
  `H(canonical(randomness) ‖ len_be32(message) ‖ message)`; `open` is
  constant-time. Randomness is exactly 32 bytes and zeroizing.

All operations are `#![forbid(unsafe_code)]` and error via a single
`CryptoCoreError`.

## Key Invariants

1. Only `crypto-core` may contain raw cryptographic primitives.
2. `payment` and `verifier` depend on the *abstract* `proof` interface,
   never on `mpc` or `mpcith` directly.
3. All code is `#![forbid(unsafe_code)]`.
4. Every crate documents its future responsibility via crate-level docs.
