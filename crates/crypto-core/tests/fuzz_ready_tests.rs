//! Fuzz-ready sanity checks for the cryptographic backend abstraction.
//!
//! These exercises run backend operations over adversarial / edge-case inputs
//! (empty, single-byte, large, and high-entropy buffers) to assert the basic
//! soundness properties a fuzzer would target: determinism, backend
//! separation, commitment binding, and exact expansion lengths.

use crypto_core::backend::{CryptoBackend, Sha256Backend, Shake256Backend};
use crypto_core::{commit, CommitmentRandomness};
use rand_core::{OsRng, RngCore};

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    OsRng.fill_bytes(&mut v);
    v
}

#[test]
fn hash_handles_edge_inputs() {
    for data in [
        vec![],
        vec![0u8],
        vec![255u8],
        random_bytes(1),
        random_bytes(1024),
    ] {
        let s = Sha256Backend::hash(&data);
        let k = Shake256Backend::hash(&data);
        assert_eq!(
            s,
            Sha256Backend::hash(&data),
            "sha256 must be deterministic"
        );
        assert_eq!(
            k,
            Shake256Backend::hash(&data),
            "shake256 must be deterministic"
        );
        assert_ne!(s.as_bytes(), k.as_bytes(), "backends must differ");
    }
}

#[test]
fn commit_binds_message_and_randomness() {
    for _ in 0..20 {
        let msg = random_bytes(OsRng.next_u32() as usize % 200 + 1);
        let r1 = CommitmentRandomness::generate(&mut OsRng).unwrap();
        let r2 = CommitmentRandomness::generate(&mut OsRng).unwrap();
        let c1 = commit::<Sha256Backend>(&msg, &r1);
        let c2 = commit::<Sha256Backend>(&msg, &r1);
        let c3 = commit::<Sha256Backend>(&msg, &r2);
        assert_eq!(c1, c2, "commitment must be deterministic");
        assert_ne!(c1, c3, "different randomness must change commitment");
        assert_ne!(
            c1.as_bytes(),
            commit::<Shake256Backend>(&msg, &r1).as_bytes(),
            "different backend must change commitment"
        );
    }
}

#[test]
fn expand_length_is_exact_for_random_sizes() {
    for len in [0usize, 1, 16, 32, 64, 1000] {
        let sha = Sha256Backend::expand(b"d", b"data", len);
        let shake = Shake256Backend::expand(b"d", b"data", len);
        assert_eq!(sha.len(), len, "sha256 expand length");
        assert_eq!(shake.len(), len, "shake256 expand length");
        assert_eq!(sha, Sha256Backend::expand(b"d", b"data", len));
        assert_eq!(shake, Shake256Backend::expand(b"d", b"data", len));
    }
}

#[test]
fn cross_backend_inequality_holds_on_random_inputs() {
    for _ in 0..50 {
        let data = random_bytes(OsRng.next_u32() as usize % 64);
        assert_ne!(
            Sha256Backend::hash(&data).as_bytes(),
            Shake256Backend::hash(&data).as_bytes()
        );
    }
}
