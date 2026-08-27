# Fuzzing Infrastructure (Phase 10, Prompt 4, Part A)

## Status

A `cargo-fuzz` harness is set up under [`../../fuzz`](../../fuzz). **It requires a
nightly toolchain and `cargo-fuzz`** to build and run:

```sh
rustup toolchain install nightly
cargo +nightly install cargo-fuzz
cargo +nightly fuzz run decode_share        # and the other targets
```

The fuzz crate is intentionally **not** a member of the default workspace (the
root `Cargo.toml` lists only `crates/*`), so `cargo build`, `cargo test`, and
`cargo test --workspace` never try to compile it and never require nightly.

## Targets

Each target feeds adversarial `&[u8]` into a decoder/parser and asserts the
call returns `Ok`/`Err` **without panicking**. Panics are the bugs we hunt.

| Target | Entry point | What it covers |
|--------|-------------|----------------|
| `decode_share` | `secret_sharing::Share::<Fr>::decode` | share parser |
| `decode_circuit` | `circuit::deserialize::<Fr>` | circuit parser |
| `decode_mpcith_proof` | `mpcith::decode_proof` | MPCitH proof parser |
| `decode_proof` | `proof::deserialize_proof` + `proof::Statement::decode` | proof + statement parsers |
| `decode_payment` | `payment::Amount::decode` + `payment::PaymentStatement::decode` | payment parsers |
| `policy_range_check` | `payment::range_check::reference_range_check` | range-check numeric boundary (policy crate has no decoder) |

The `policy_range_check` target exists because the `policy` crate exposes no
deserializer; instead it fuzzes the numeric range-check boundary that the
policy crate's compilation emits, ensuring it never panics on hostile input.

## Corpus

`fuzz/corpus/<target>/seed` contains a placeholder seed so the directories are
tracked in git. For effective coverage, replace these with **valid** encodings
(e.g. serialize a real `Share`, `Circuit`, `MpcithProof`, `NonInteractiveProof`,
`Amount`, `PaymentStatement`) before a long fuzzing run; `cargo fuzz run` will
then mutate from valid structures and populate the corpus automatically.

## Scope and limitations

- **Goal:** crash/panic discovery in the parser and boundary layers. Fuzzing
  proves *robustness against malformed bytes*, not cryptographic soundness.
- Decoders are the only fuzzed surface here. Higher-level properties
  (prover/verifier consistency, Fiat–Shamir binding, MPC reconstruct,
  commitment open) are covered by `tests/property_tests_expanded.rs` and the
  Prompt-3 regression suites, which run on stable.
- The harness asserts "no panic", not "rejects invalid input". Rejecting
  invalid input is already enforced by explicit error returns validated in the
  regression suites; fuzzing complements that by catching the cases those
  suites do not enumerate.
- `libfuzzer-sys` links libFuzzer, which is only available on nightly with the
  appropriate sanitizer; this is why the targets are not compiled by the
  default (stable) build.
