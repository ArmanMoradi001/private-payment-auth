#!/usr/bin/env python3
"""Generates Fiat-Shamir challenge test vectors for the proof crate.

This script INDEPENDENTLY implements the challenge derivation rule
documented for `private-payment-auth/mpcith/fs/v1`:

    digest = SHA-256( len_be32(domain) || domain || message )
    hidden_party = digest[0] % 3

    message = version(u8=1)
           || statement_encoding
           || repetition_id(u32 BE)
           || commitments(3 x 32B)

    statement_encoding =
              version(u8=1)
           || circuit_id(32B)
           || n_public_inputs(u32 BE) || values(32B BE each)
           || n_expected_outputs(u32 BE) || values(32B BE each)

Field elements are encoded as fixed-width big-endian bytes of their
integer value (ed25519 scalar field, width 32).

Run from anywhere: writes fiat_shamir_vectors.json next to this file.
"""

import hashlib
import json
import os

DOMAIN = b"private-payment-auth/mpcith/fs/v1"


def be32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def encode_statement(circuit_id: bytes, public_inputs: list, expected_outputs: list) -> bytes:
    out = bytearray()
    out.append(1)  # statement version
    out += circuit_id
    out += be32(len(public_inputs))
    for v in public_inputs:
        out += v.to_bytes(32, "big")
    out += be32(len(expected_outputs))
    for v in expected_outputs:
        out += v.to_bytes(32, "big")
    return bytes(out)


def derive_challenge(
    circuit_id: bytes,
    public_inputs: list,
    expected_outputs: list,
    commitments: list,
    repetition_id: int,
) -> dict:
    stmt = encode_statement(circuit_id, public_inputs, expected_outputs)
    msg = bytearray()
    msg.append(1)  # protocol version
    msg += stmt
    msg += be32(repetition_id)
    for c in commitments:
        assert len(c) == 32
        msg += c
    framed = be32(len(DOMAIN)) + DOMAIN + bytes(msg)
    digest = hashlib.sha256(framed).digest()
    return {
        "digest": digest.hex(),
        "hidden_party": digest[0] % 3,
    }


def main():
    cases = []

    # Case 1: the canonical end-to-end fixture ((x+2)*p + x, x=7, p=5 -> 52).
    # Circuit id below must equal the Rust fixture's compute_id(); the
    # Rust vector test recomputes it, so here we simply use a fixed id
    # that the Rust side derives independently as well.
    c1_commitments = [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
    ]
    r1 = derive_challenge(
        circuit_id=bytes(range(32)),
        public_inputs=[5],
        expected_outputs=[52],
        commitments=[bytes.fromhex(h) for h in c1_commitments],
        repetition_id=0,
    )
    cases.append({
        "label": "canonical_fixture",
        "version": 1,
        "repetition_id": 0,
        "circuit_id": bytes(range(32)).hex(),
        "public_inputs": ["0000000000000000000000000000000000000000000000000000000000000005"],
        "expected_outputs": ["0000000000000000000000000000000000000000000000000000000000000034"],
        "commitments": c1_commitments,
        "expected_digest": r1["digest"],
        "expected_hidden_party": r1["hidden_party"],
    })

    # Case 2: different repetition id must change the challenge.
    r2 = derive_challenge(
        circuit_id=bytes(range(32)),
        public_inputs=[5],
        expected_outputs=[52],
        commitments=[bytes.fromhex(h) for h in c1_commitments],
        repetition_id=1,
    )
    cases.append({
        "label": "different_repetition_id",
        "version": 1,
        "repetition_id": 1,
        "circuit_id": bytes(range(32)).hex(),
        "public_inputs": ["0000000000000000000000000000000000000000000000000000000000000005"],
        "expected_outputs": ["0000000000000000000000000000000000000000000000000000000000000034"],
        "commitments": c1_commitments,
        "expected_digest": r2["digest"],
        "expected_hidden_party": r2["hidden_party"],
    })

    # Case 3: multiple inputs/outputs and different commitments.
    c3 = [
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ]
    r3 = derive_challenge(
        circuit_id=bytes([0xAB] * 32),
        public_inputs=[11, 22],
        expected_outputs=[1],
        commitments=[bytes.fromhex(h) for h in c3],
        repetition_id=42,
    )
    cases.append({
        "label": "multi_value_statement",
        "version": 1,
        "repetition_id": 42,
        "circuit_id": bytes([0xAB] * 32).hex(),
        "public_inputs": [
            "000000000000000000000000000000000000000000000000000000000000000b",
            "0000000000000000000000000000000000000000000000000000000000000016",
        ],
        "expected_outputs": ["0000000000000000000000000000000000000000000000000000000000000001"],
        "commitments": c3,
        "expected_digest": r3["digest"],
        "expected_hidden_party": r3["hidden_party"],
    })

    doc = {"domain": DOMAIN.decode(), "cases": cases}
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "fiat_shamir_vectors.json")
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print(f"wrote {len(cases)} vectors to {out_path}")


if __name__ == "__main__":
    main()
