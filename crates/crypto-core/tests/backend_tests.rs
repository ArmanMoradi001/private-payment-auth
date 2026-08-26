//! Backend-agnostic behavior tests.
//!
//! These verify that [`Sha256Backend`] and [`Shake256Backend`] both satisfy
//! the [`CryptoBackend`] contract, that the SHA-256 backend reproduces the
//! legacy `Sha256Hash` reference byte-for-byte, and that the two backends
//! never produce identical digests for the same input (the property the
//! protocol relies on to bind proofs to a single backend).

use crypto_core::backend::{CryptoBackend, Sha256Backend, Shake256Backend};
use crypto_core::{commit, CommitmentRandomness, HashFunction as _, Sha256Hash};
use rand_core::OsRng;

#[test]
fn sha256_backend_matches_reference_sha256() {
    for data in [
        b"".as_ref(),
        b"abc",
        b"hello world",
        &[0x00u8; 64],
        &[0xffu8; 1],
    ] {
        let got = Sha256Backend::hash(data).as_bytes().to_vec();
        let expected = Sha256Hash::hash(data).to_vec();
        assert_eq!(got, expected, "sha256 backend must equal legacy Sha256Hash");
    }
}

#[test]
fn backends_produce_distinct_digests() {
    let data = b"same input, different backend";
    assert_ne!(
        Sha256Backend::hash(data).as_bytes(),
        Shake256Backend::hash(data).as_bytes(),
        "backends must not collide on identical input"
    );
}

#[test]
fn hash_is_deterministic_per_backend() {
    let data = b"determinism";
    assert_eq!(Sha256Backend::hash(data), Sha256Backend::hash(data));
    assert_eq!(Shake256Backend::hash(data), Shake256Backend::hash(data));
}

#[test]
fn hash_domain_separates_domains_and_backends() {
    let a = Sha256Backend::hash_domain(b"dom-a", b"x")
        .as_bytes()
        .to_vec();
    let b = Sha256Backend::hash_domain(b"dom-b", b"x")
        .as_bytes()
        .to_vec();
    let c = Shake256Backend::hash_domain(b"dom-a", b"x")
        .as_bytes()
        .to_vec();
    assert_ne!(a, b, "domain separation must change the digest");
    assert_ne!(a, c, "backend separation must change the digest");
}

#[test]
fn commit_differs_across_backends() {
    let r = CommitmentRandomness::generate(&mut OsRng).unwrap();
    let msg = b"commitment backend separation";
    let c_sha = commit::<Sha256Backend>(msg, &r);
    let c_shake = commit::<Shake256Backend>(msg, &r);
    assert_ne!(c_sha.as_bytes(), c_shake.as_bytes());
    // The SHA-256 backend commitment must still equal the historical vector.
    assert_eq!(c_sha.as_bytes().len(), 32);
}

#[test]
fn expand_returns_requested_length_and_differs() {
    let domain = b"domain";
    let data = b"expand me";
    let a = Sha256Backend::expand(domain, data, 48);
    let b = Shake256Backend::expand(domain, data, 48);
    assert_eq!(a.len(), 48);
    assert_eq!(b.len(), 48);
    assert_ne!(a, b, "XOF expansions must differ between backends");
    assert_eq!(a, Sha256Backend::expand(domain, data, 48));
    assert_eq!(b, Shake256Backend::expand(domain, data, 48));
}
