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
| `crypto-core`     | Foundational traits and implementations: hashing, commitments, field arithmetic, symmetric primitives, Fiat–Shamir transcripts. Depends on nothing internal. |
| `secret-sharing`  | Shamir-style secret sharing and reconstruction of keys and protocol inputs, built on `crypto-core`. |
| `mpc`             | The MPC protocol layer: distributed evaluation of the authorization computation over shared secrets. |
| `mpcith`          | MPC-in-the-Head constructions that turn `mpc` protocol executions into zero-knowledge proof components. |
| `policy`          | Authorization policy definition and evaluation: spending limits, multi-party approval rules, time locks, and their commitments. |
| `proof`           | The abstract zero-knowledge proof interface built on `mpcith`, including Fiat–Shamir transformation and serialization of proofs. |
| `payment`         | End-to-end payment authorization orchestration: composes proofs and policies into authorization flows. Deliberately insulated from the MPC layers. |
| `verifier`        | Standalone verification of authorization artifacts, independent of the proving side. |
| `sdk`             | The single stable public entry point for external consumers, re-exporting curated APIs from the crates above. |

## Key Invariants

1. Only `crypto-core` may contain raw cryptographic primitives.
2. `payment` and `verifier` depend on the *abstract* `proof` interface,
   never on `mpc` or `mpcith` directly.
3. All code is `#![forbid(unsafe_code)]`.
4. Every crate documents its future responsibility via crate-level docs.
