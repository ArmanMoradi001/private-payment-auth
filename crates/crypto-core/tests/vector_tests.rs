//! Known-answer tests against externally generated vectors.

use crypto_core::{commit, CommitmentRandomness, HashFunction, Sha256Backend, Sha256Hash};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    sha256: Vec<ShaVector>,
    hash_domain: Vec<DomainVector>,
    commitment: Vec<CommitVector>,
}

#[derive(Deserialize)]
struct ShaVector {
    input_hex: String,
    output_hex: String,
}

#[derive(Deserialize)]
struct DomainVector {
    domain_hex: String,
    data_hex: String,
    output_hex: String,
}

#[derive(Deserialize)]
struct CommitVector {
    message_hex: String,
    randomness_hex: String,
    commitment_hex: String,
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn vectors() -> Vectors {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/crypto_vectors.json"
    );
    let raw = std::fs::read_to_string(path).expect("vector file");
    serde_json::from_str(&raw).expect("valid vector JSON")
}

#[test]
fn sha256_vectors() {
    for v in vectors().sha256 {
        let input = unhex(&v.input_hex);
        let expected = unhex(&v.output_hex);
        assert_eq!(Sha256Hash::hash(&input).as_ref(), &expected);
    }
}

#[test]
fn hash_domain_vectors() {
    for v in vectors().hash_domain {
        let domain = unhex(&v.domain_hex);
        let data = unhex(&v.data_hex);
        let expected = unhex(&v.output_hex);
        assert_eq!(Sha256Hash::hash_domain(&domain, &data).as_ref(), &expected);
    }
}

#[test]
fn commitment_vectors() {
    for v in vectors().commitment {
        let message = unhex(&v.message_hex);
        let randomness =
            CommitmentRandomness::new(unhex(&v.randomness_hex).into()).expect("32-byte randomness");
        let expected = unhex(&v.commitment_hex);
        let c = commit::<Sha256Backend>(&message, &randomness);
        assert_eq!(c.as_bytes(), &expected[..]);
        assert!(crypto_core::open::<Sha256Backend>(
            &c,
            &message,
            &randomness
        ));
    }
}
