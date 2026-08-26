#!/usr/bin/env python3
"""Generates Fiat-Shamir challenge test vectors for the proof crate.

This script INDEPENDENTLY implements the challenge derivation rule used by
``FiatShamirChallengeGenerator<Sha256Backend>`` for
``private-payment-auth/mpcith/fs/v1``:

    message = DOMAIN_FS
            || BACKEND_ID                       # Sha256Backend::ID
            || PROTOCOL_VERSION (u8 = 2)
            || statement_encoding
            || n_reps (u32 BE)
            || ( repetition_id (u32 BE) || commitments (3 x 32B) ) * n_reps
            || selector_repetition_id (u32 BE)

    digest[r]        = SHA-256( len_be32(DOMAIN_FS) || DOMAIN_FS || message )
    hidden_party[r]  = u64( SHA256( len_be32(DOMAIN_FS) || DOMAIN_FS
                                   || 0u32 || message )[0:8] ) % 3

The hidden party uses the backend's ``expand`` (iterative SHA-256 for
SHA-256), reading the first 8 bytes of the 64-byte expansion as a big-endian
``u64`` and reducing modulo 3.

Challenges are derived JOINTLY: each repetition's digest absorbs the full
committed transcript plus its own repetition id as the selector.

    statement_encoding =
              STATEMENT_VERSION (u8 = 1)
           || circuit_id (32B)
           || n_public_inputs (u32 BE) || values (32B BE each)
           || n_expected_outputs (u32 BE) || values (32B BE each)

Field elements are encoded as fixed-width big-endian bytes of their integer
value (ed25519 scalar field, width 32).

Run from anywhere: writes fiat_shamir_vectors.json next to this file.
"""

import hashlib
import json
import os

# Mirror crypto-core::backend::DOMAIN_FS / Sha256Backend::ID exactly.
DOMAIN = b"private-payment-auth/fs/v2"  # hash domain bytes
DOMAIN_LABEL = "private-payment-auth/mpcith/fs/v1"  # JSON metadata label
BACKEND_ID = b"sha256-v1\0\0\0\0\0\0\0"  # 16 bytes
PROTOCOL_VERSION = 2
STATEMENT_VERSION = 1


def be32(value: int) -> bytes:
    return value.to_bytes(4, "big")


def encode_statement(circuit_id: bytes, public_inputs: list, expected_outputs: list) -> bytes:
    out = bytearray()
    out.append(STATEMENT_VERSION)
    out += circuit_id
    out += be32(len(public_inputs))
    for v in public_inputs:
        out += v.to_bytes(32, "big")
    out += be32(len(expected_outputs))
    for v in expected_outputs:
        out += v.to_bytes(32, "big")
    return bytes(out)


def fs_input(stmt: bytes, sessions: list, selector_id: int) -> bytes:
    msg = bytearray()
    msg += DOMAIN
    msg += BACKEND_ID
    msg.append(PROTOCOL_VERSION)
    msg += stmt
    msg += be32(len(sessions))
    for rep_id, commitments in sessions:
        assert len(commitments) == 3
        msg += be32(rep_id)
        for c in commitments:
            assert len(c) == 32
            msg += c
    msg += be32(selector_id)
    return bytes(msg)


def fs_digest(stmt: bytes, sessions: list, selector_id: int) -> str:
    message = fs_input(stmt, sessions, selector_id)
    framed = be32(len(DOMAIN)) + DOMAIN + be32(len(message)) + message
    return hashlib.sha256(framed).digest().hex()


def hidden_party(stmt: bytes, sessions: list, selector_id: int) -> int:
    message = fs_input(stmt, sessions, selector_id)
    framed = be32(len(DOMAIN)) + DOMAIN + (0).to_bytes(4, "big") + message
    digest = hashlib.sha256(framed).digest()
    return int.from_bytes(digest[:8], "big") % 3


def derive_challenges(circuit_id, public_inputs, expected_outputs, sessions) -> dict:
    """`sessions` is a list of `(repetition_id, commitments)` tuples."""
    stmt = encode_statement(circuit_id, public_inputs, expected_outputs)
    digests = [fs_digest(stmt, sessions, rep_id) for rep_id, _ in sessions]
    parties = [hidden_party(stmt, sessions, rep_id) for rep_id, _ in sessions]
    return {"digests": digests, "hidden_parties": parties}


def case(label, circuit_id, public_inputs, expected_outputs, sessions):
    r = derive_challenges(circuit_id, public_inputs, expected_outputs, sessions)
    return {
        "label": label,
        "version": 1,
        "circuit_id": circuit_id.hex(),
        "public_inputs": [f"{v:064x}" for v in public_inputs],
        "expected_outputs": [f"{v:064x}" for v in expected_outputs],
        "sessions": [
            {"repetition_id": rep_id, "commitments": [c.hex() for c in cms]}
            for rep_id, cms in sessions
        ],
        "expected_digests": r["digests"],
        "expected_hidden_parties": r["hidden_parties"],
    }


def main():
    c1 = [
        bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111"),
        bytes.fromhex("2222222222222222222222222222222222222222222222222222222222222222"),
        bytes.fromhex("3333333333333333333333333333333333333333333333333333333333333333"),
    ]
    c1b = [
        bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        bytes.fromhex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        bytes.fromhex("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"),
    ]
    c3 = [
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ]
    c3 = [bytes.fromhex(h) for h in c3]
    cid1 = bytes(range(32))

    cases = [
        # Case 1: two repetitions sharing one statement.
        case(
            "canonical_fixture_two_reps",
            cid1,
            [5],
            [52],
            [(0, c1), (1, c1b)],
        ),
        # Case 2: a commitment in the *other* repetition must still change
        # every digest (joint binding).
        case(
            "joint_binding",
            cid1,
            [5],
            [52],
            [(0, c1b), (1, c1)],
        ),
        # Case 3: multiple inputs/outputs, three repetitions, ids != 0..n.
        case(
            "multi_value_statement_three_reps",
            bytes([0xAB] * 32),
            [11, 22],
            [1],
            [
                (7, c3),
                (8, c1),
                (9, c1b),
            ],
        ),
    ]

    doc = {"domain": DOMAIN_LABEL, "cases": cases}
    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "fiat_shamir_vectors.json")
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")
    print(f"wrote {len(cases)} vectors to {out_path}")


if __name__ == "__main__":
    main()
