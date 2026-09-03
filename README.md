# Private Payment Auth

Privacy-preserving payment authorization built in Rust using secure computation and zero-knowledge proofs.

The project explores a simple cryptographic primitive with a practical goal:

> Prove that a payment satisfies an authorization policy without revealing the private credentials and authorization data used to satisfy it.

The current architecture combines additive secret sharing, MPC, MPC-in-the-Head (MPCitH), Fiat–Shamir, typed authorization policies, and a verifier-oriented SDK.

## Why this project exists

Traditional payment authorization exposes the evidence of authorization.

For example, a system may require several signatures, reveal which parties approved a transaction, or expose internal spending rules.

Private Payment Auth takes a different approach.

The prover holds the private witness and produces a proof that the authorization relation is satisfied. The verifier receives only the public statement and proof.

Conceptually:

```text
Private credentials + private witness
                |
                v
        Authorization policy
                |
                v
       Arithmetic computation
                |
                v
             MPC
                |
                v
       MPC-in-the-Head
                |
                v
          Fiat–Shamir
                |
                v
          Proof artifact
                |
                v
            Verifier
```

The verifier does not need the witness, secret shares, or commitment randomness.

## Cryptographic foundation

The implementation is deliberately layered.

```text
crypto-core
    |
    v
secret-sharing
    |
    v
mpc
    |
    v
circuit
    |
    v
mpcith
    |
    v
proof
    |
    v
policy
    |
    v
payment
    |
    v
sdk
```

### `crypto-core`

The cryptographic foundation.

Provides:

- typed digests
- hashing and domain separation
- hash-based commitments
- canonical encoding
- secure randomness interfaces
- zeroizing secret containers
- pluggable cryptographic backends

The current backends include SHA-256 and SHAKE256.

### `secret-sharing`

Secret sharing primitives over the project field.

The current implementation includes Shamir secret sharing with strict validation and explicit share encoding.

### `mpc`

Arithmetic MPC based on additive secret sharing and Beaver triples.

The layer supports private inputs, public values, addition, multiplication, and explicit reveal operations.

### `circuit`

A deterministic arithmetic DAG.

The circuit representation is intentionally small:

- secret inputs
- public inputs
- constants
- addition
- multiplication

Circuits have canonical encodings and deterministic identities.

### `mpcith`

The proof engine built from simulated MPC executions.

The current construction uses three virtual parties. Their views are committed before the challenge, and only the challenged openings are revealed.

### `proof`

The non-interactive proof layer.

Fiat–Shamir derives challenges from a domain-separated transcript that includes the statement, circuit identity, protocol version, cryptographic backend, repetition identifier, and commitments.

### `policy`

The authorization model.

Policies currently express:

- amount limits
- credential ownership
- threshold authorization
- conjunction
- disjunction

Policies are typed, validated, normalized, canonically encoded, and compiled deterministically into arithmetic circuits.

### `payment`

The payment domain.

Payment statements bind security-relevant payment data to the authorization proof, including payment identity, amount, recipient commitment, policy identity, circuit identity, protocol version, and nonce.

### `sdk`

The application-facing interface.

The SDK is the preferred public entry point for:

- authorization
- verification
- artifact serialization
- artifact deserialization
- authorization identity

The SDK orchestrates the underlying layers without reimplementing cryptographic verification.

## Privacy model

The central privacy boundary is simple:

### Prover

The prover possesses:

- credential secrets
- private witness data
- secret shares
- MPC randomness

These values are consumed locally during proof generation.

### Verifier

The verifier receives:

- payment
- policy
- public statement
- authorization artifact

The verifier does not receive:

- credential secrets
- witness values
- secret shares
- commitment randomness
- the hidden MPC party view

The authorization artifact is designed to be self-contained and secret-free.

## Authorization flow

At a high level:

```text
Payment
   +
Policy
   +
Private Witness
        |
        v
    SDK::authorize
        |
        v
Policy normalization
        |
        v
Circuit compilation
        |
        v
Authorization relation
        |
        v
MPC execution
        |
        v
MPC-in-the-Head
        |
        v
Fiat–Shamir
        |
        v
Authorization artifact
```

Verification follows the opposite direction without any secret input:

```text
Payment
   +
Policy
   +
Authorization
        |
        v
    SDK::verify
        |
        v
Binding checks
        |
        v
Circuit / policy verification
        |
        v
Proof verification
        |
        v
      Valid
```

## Example authorization policy

A policy can express a rule such as:

```text
AND(
    Threshold(2, [credential_1, credential_2, credential_3]),
    AmountAtMost(100)
)
```

The prover can demonstrate that two valid credentials satisfy the policy and that the payment amount is within the configured limit without revealing which private credentials were used.

## Engineering principles

This project treats cryptographic software as security-critical infrastructure.

The implementation follows a few core principles:

- keep cryptographic primitives isolated from application logic
- prefer mature cryptographic implementations over handwritten primitives
- make security-sensitive objects strongly typed
- use canonical encodings for cryptographic statements
- make protocol identities explicit and domain-separated
- keep the verifier small and deterministic
- maintain independent reference evaluators
- test adversarially, not only for the happy path
- fuzz untrusted parsing boundaries
- document security assumptions and limitations explicitly

The repository also enforces:

- `#![forbid(unsafe_code)]`
- strict Clippy checks
- debug and release testing
- dependency and license checks
- property-based testing
- fuzzing
- deterministic test vectors
- Criterion benchmarks

## Post-quantum direction

The architecture is designed to support a future post-quantum MPCitH profile.

The project currently provides backend agility at the hash/XOF layer through SHA-256 and SHAKE256.

This does **not** mean that the complete protocol is post-quantum secure.

The current field, MPC construction, Fiat–Shamir assumptions, and other protocol components remain part of the security model. A genuine post-quantum profile requires a complete analysis of those components and their composition.

## Current status

The project is in active development.

The cryptographic foundation, secret sharing, MPC runtime, arithmetic circuits, MPC-in-the-Head proof system, Fiat–Shamir layer, authorization policy model, payment domain, and SDK have been implemented and hardened through extensive testing.

The codebase should currently be understood as:

**production-oriented cryptographic engineering, not an independently audited production payment system.**

External security review and formal analysis remain necessary before handling real funds or high-assurance deployments.

## Repository layout

```text
crates/
├── crypto-core/       Cryptographic primitives and backends
├── secret-sharing/    Secret sharing
├── mpc/               Arithmetic MPC
├── circuit/           Arithmetic circuits
├── mpcith/            MPC-in-the-Head
├── proof/             Non-interactive proofs
├── policy/            Authorization policies
├── payment/           Payment domain
├── verifier/          Standalone verification
└── sdk/               Public application API

tests/                 Integration, property, and adversarial tests
fuzz/                  Fuzz targets
benches/               Benchmarks
docs/
├── architecture/      System architecture
├── security/          Threat model and security notes
└── decisions/         Architecture decision records
```

## Security limitations

The project intentionally documents its current limitations.

Examples include:

- the current credential commitment relation is not yet an arithmetization-friendly hash construction for fully in-circuit credential hashing
- the MPCitH soundness parameters are provisional
- Fiat–Shamir security is not accompanied by a formal QROM proof in this codebase
- the verifier has not been machine-checked
- replay and duplicate suppression remain application-level concerns
- cryptographic memory protection does not currently provide guarantees such as `mlock`
- the complete system has not undergone an independent external audit

These limitations are part of the project's current security model and should not be ignored when evaluating deployment suitability.

## Development

The repository is organized as a Cargo workspace.

Run the core verification suite with:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
cargo test --workspace --release
cargo audit
cargo deny check
cargo doc --workspace --no-deps
cargo bench --no-run
```

## License

Dual-licensed under:

- MIT
- Apache-2.0

See [`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE).
