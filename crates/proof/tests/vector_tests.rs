//! Cross-implementation vectors: the Rust Fiat–Shamir derivation must
//! reproduce challenges computed by the independent Python script
//! (`generate_fs_vectors.py` in this directory).

use circuit::CircuitId;
use crypto_core::Digest;
use mpc::PublicValue;
use mpcith::{FieldElement, ViewCommitment};
use proof::{ChallengeGenerator as _, FiatShamirChallengeGenerator, FsSession};

type Fr = FieldElement;

fn fr_from_be_hex(hex: &str) -> Fr {
    let bytes = hex_to_bytes(hex);
    use ark_ff::{BigInteger, PrimeField};
    let bits: Vec<bool> = bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> (7 - i)) & 1 == 1))
        .collect();
    Fr::from_bigint(<Fr as PrimeField>::BigInt::from_bits_be(&bits))
        .expect("vector value is a canonical field element")
}

fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0);
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[derive(serde::Deserialize)]
struct VectorFile {
    domain: String,
    cases: Vec<VectorCase>,
}

#[derive(serde::Deserialize)]
struct VectorCase {
    label: String,
    #[allow(dead_code)]
    version: u8,
    circuit_id: String,
    public_inputs: Vec<String>,
    expected_outputs: Vec<String>,
    sessions: Vec<SessionCase>,
    expected_digests: Vec<String>,
    expected_hidden_parties: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct SessionCase {
    repetition_id: u32,
    commitments: Vec<String>,
}

#[test]
fn rust_fs_matches_python_vectors() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/fiat_shamir_vectors.json"
    );
    let raw = std::fs::read_to_string(path).expect("vectors exist");
    let doc: VectorFile = serde_json::from_str(&raw).expect("valid JSON");

    assert_eq!(
        doc.domain, "private-payment-auth/mpcith/fs/v1",
        "domain drift between implementations"
    );

    let generator = FiatShamirChallengeGenerator::<crypto_core::Sha256Backend>::default();
    for case in &doc.cases {
        let statement = proof::Statement {
            circuit_id: CircuitId::from_digest(Digest::from(
                <[u8; 32]>::try_from(hex_to_bytes(&case.circuit_id).as_slice())
                    .expect("32-byte id"),
            )),
            public_inputs: case
                .public_inputs
                .iter()
                .map(|h| PublicValue::new(fr_from_be_hex(h)))
                .collect(),
            expected_outputs: case
                .expected_outputs
                .iter()
                .map(|h| PublicValue::new(fr_from_be_hex(h)))
                .collect(),
        };
        let commitment_sets: Vec<Vec<ViewCommitment>> = case
            .sessions
            .iter()
            .map(|s| {
                s.commitments
                    .iter()
                    .map(|h| {
                        let arr: [u8; 32] = <[u8; 32]>::try_from(hex_to_bytes(h).as_slice())
                            .expect("32-byte commitment");
                        ViewCommitment::from_digest(Digest::from(arr))
                    })
                    .collect()
            })
            .collect();
        let sessions: Vec<FsSession<'_>> = case
            .sessions
            .iter()
            .zip(&commitment_sets)
            .map(|(s, cms)| FsSession::new(mpcith::RepetitionId::new(s.repetition_id), cms))
            .collect();

        // Every selector's full digest must match the Python script's
        // independent computation (stronger than party equality).
        for (r, _) in case.sessions.iter().enumerate() {
            let digest = generator
                .fs_digest(&statement, &sessions, r)
                .unwrap_or_else(|e| panic!("case {} failed: {e}", case.label));
            let actual_hex: String = digest
                .as_bytes()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(
                actual_hex, case.expected_digests[r],
                "case {} session {}: digest mismatch",
                case.label, r
            );
        }

        // The trait-level derivation agrees with the raw digests.
        let challenges = generator
            .derive_all(&statement, &sessions)
            .unwrap_or_else(|e| panic!("case {} derive_all failed: {e}", case.label));
        let parties: Vec<u8> = challenges.iter().map(|c| c.hidden_party.get()).collect();
        assert_eq!(parties, case.expected_hidden_parties);
        println!("case {} ok", case.label);
    }
}
