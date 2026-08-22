# Dependency Boundaries

This document defines the allowed dependency directions between workspace
crates. These rules are enforced by review and (in the future) by an
automated CI check.

## Allowed Dependencies

```
sdk            -> payment, proof, policy, verifier
payment        -> proof, policy, crypto-core
verifier       -> proof, policy, crypto-core
policy         -> crypto-core
proof          -> mpcith, crypto-core
mpcith         -> mpc, secret-sharing, crypto-core
mpc            -> secret-sharing, crypto-core
secret-sharing -> crypto-core
crypto-core    -> (nothing)
```

Layering, bottom to top:

```
crypto-core <- secret-sharing <- mpc <- mpcith <- proof <- payment / verifier / policy <- sdk
```

## Forbidden Dependencies

| Crate            | Must NOT depend on                                 | Rationale |
| ---------------- | -------------------------------------------------- | --------- |
| `payment`        | `mpc`, `mpcith`, `secret-sharing`                  | The application layer must only see the abstract proof interface; leaking MPC internals would couple business logic to protocol details. |
| `verifier`       | `mpc`, `mpcith`, `secret-sharing`, `payment`        | Verification must be independent of the proving stack; it must never depend on the orchestration crate. |
| `proof`          | `mpc`, `secret-sharing`, `policy`, `payment`        | Proofs are built on the MPC-in-the-Head abstraction only. |
| `mpcith`         | `proof`, `payment`, `policy`                        | Protocol constructions stay below the proof interface. |
| `mpc`            | `mpcith`, `proof`, or anything above                | The MPC layer is unaware of how its execution becomes a proof. |
| `secret-sharing` | anything except `crypto-core`                       | Pure utility layer. |
| `crypto-core`    | any internal crate                                  | It is the foundation. |
| `sdk`            | `mpc`, `mpcith`, `secret-sharing`, `crypto-core`    | External consumers reach internals only through the public crates. |

## Enforcement

- Cycles are impossible: Cargo rejects cyclic dependencies between crates.
- The table above is enforced by review today.
- A future CI lint (`cargo-deny` bans rules or a dedicated script) will
  check this list mechanically.

Any new dependency must be added here first, with rationale, before it is
wired into a `Cargo.toml`.
