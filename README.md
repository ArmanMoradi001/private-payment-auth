# MPC Payment

A cryptographic payment authorization project.

**Status: Phase 0 — Repository Foundation**

This repository currently contains only workspace scaffolding and CI
configuration. **NO cryptographic implementation has started yet.**

## Purpose

This project will provide cryptographic payment authorization built on
secure multi-party computation principles.

## Philosophy

Security-first: correctness, constant-time operations, and audited
dependencies take priority over performance and features. Every change is
gated by format checks, strict lints, tests in debug and release modes,
dependency auditing, and license/policy enforcement via `cargo deny`.

## Layout

- `crates/*` — workspace members (none yet)
- `.github/workflows/ci.yml` — CI pipeline
- `deny.toml`, `clippy.toml`, `rustfmt.toml` — lint/licensing policy
- `rust-toolchain.toml` — pinned stable toolchain with `rustfmt` and `clippy`
