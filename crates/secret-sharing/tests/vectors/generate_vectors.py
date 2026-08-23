#!/usr/bin/env python3
"""Generate deterministic Shamir test vectors for the secret-sharing crate.

The prime field matches the Rust implementation (ark_ed25519::Fr scalar
field): p = 2^252 + 27742317777372353535851937790883648493.

Shares are generated with fixed polynomial coefficients so the output is
reproducible. Values are serialized as 32-byte big-endian hex, matching the
canonical encoding used by the crate.
"""

import json
import os

P = 2**252 + 27742317777372353535851937790883648493

CASES = [
    # (secret_hex, coefficients_hex[0] is ignored; constant term is the secret)
    {
        "secret_hex": "deadbeef",
        "threshold": 3,
        "share_count": 5,
        "coefficients_hex": ["01", "02"],
    },
    {
        "secret_hex": "00" * 31 + "ff",
        "threshold": 2,
        "share_count": 4,
        "coefficients_hex": [
            "0a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223242526272829",
        ],
    },
    {
        "secret_hex": "01",
        "threshold": 5,
        "share_count": 10,
        "coefficients_hex": [
            "07",
            "0f" * 32,
            "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
            "0fedcba9876543210fedcba9876543210fedcba9876543210fedcba987654321",
        ],
    },
]


def to_int(hex_str: str) -> int:
    value = int.from_bytes(bytes.fromhex(hex_str), "big")
    assert value < P, f"value {hex_str} not below modulus"
    return value


def to_hex(value: int) -> str:
    return value.to_bytes(32, "big").hex()


def evaluate(coefficients, x: int) -> int:
    result = 0
    for coeff in reversed(coefficients):
        result = (result * x + coeff) % P
    return result


def lagrange_at_zero(points) -> int:
    total = 0
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, (xj, _) in enumerate(points):
            if i == j:
                continue
            num = (num * xj) % P
            den = (den * (xj - xi)) % P
        total = (total + yi * num * pow(den, P - 2, P)) % P
    return total


def encode_share(threshold, share_count, index, value) -> str:
    return (
        bytes([1])
        + threshold.to_bytes(4, "big")
        + share_count.to_bytes(4, "big")
        + index.to_bytes(4, "big")
        + value.to_bytes(32, "big")
    ).hex()


def main() -> None:
    out_cases = []
    for case in CASES:
        threshold = case["threshold"]
        share_count = case["share_count"]
        secret_int = to_int(case["secret_hex"])
        coefficients = [secret_int] + [to_int(c) for c in case["coefficients_hex"]]
        assert len(coefficients) == threshold
        # Canonical form: minimal big-endian bytes, at least one byte.
        canonical_hex = secret_int.to_bytes(
            max(1, (secret_int.bit_length() + 7) // 8), "big"
        ).hex()

        shares = []
        encoded = []
        for index in range(1, share_count + 1):
            value = evaluate(coefficients, index)
            shares.append({"index": index, "value_hex": to_hex(value)})
            encoded.append(encode_share(threshold, share_count, index, value))

        # Deterministic subsets of size t that must reconstruct the secret,
        # plus a too-small subset that must fail.
        subsets = [
            list(range(1, threshold + 1)),
            list(range(share_count - threshold + 1, share_count + 1)),
        ]
        if threshold >= 2:
            step = max(share_count // share_count, 1)
            mixed = sorted(
                set([i * step + 1 for i in range(threshold)]) & set(range(1, share_count + 1))
            )
            while len(mixed) < threshold:
                for candidate in range(1, share_count + 1):
                    if candidate not in mixed:
                        mixed.append(candidate)
                        break
                mixed = sorted(set(mixed))
            if len(mixed) == threshold:
                subsets.append(mixed)

        insufficient = list(range(1, threshold)) or [1]

        out_cases.append(
            {
                "name": f"{threshold}-of-{share_count}",
                "secret_hex": to_hex(secret_int),
                "canonical_secret_hex": canonical_hex,
                "threshold": threshold,
                "share_count": share_count,
                "shares": shares,
                "encoded_shares_hex": encoded,
                "reconstruct_subsets": subsets,
                "insufficient_subset_indices": insufficient,
            }
        )

    document = {
        "field_modulus_hex": to_hex(P),
        "field_element_size_bytes": 32,
        "version": 1,
        "cases": out_cases,
    }

    out_path = os.path.join(os.path.dirname(__file__), "shamir_vectors.json")
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2)
        handle.write("\n")

    print(f"wrote {len(out_cases)} cases to {out_path}")

    # Self-check with pure Python reconstruction.
    for case in out_cases:
        points = [(s["index"], int(s["value_hex"], 16)) for s in case["shares"][: case["threshold"]]]
        recovered = lagrange_at_zero(points)
        assert recovered == int(case["secret_hex"], 16), "python self-check failed"
    print("python self-check passed")


if __name__ == "__main__":
    main()
