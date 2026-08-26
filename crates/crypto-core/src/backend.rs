//! Cryptographic backend abstraction.
//!
//! This module introduces a [`CryptoBackend`] trait that abstracts the
//! concrete hash/XOF primitive consumed by the protocol. Two backends are
//! provided initially:
//!
//! * [`Sha256Backend`] — SHA-256, the workspace default.
//! * [`Shake256Backend`] — SHAKE256 (a SHA-3 XOF), used for the
//!   post-quantum-ready *path* while remaining protocol-compatible
//!   (32-byte fixed digests).
//!
//! **Critically**, this abstraction does *not* replace SHA-256 globally.
//! SHA-256 remains the default backend; the trait only adds the ability
//! to select an alternative (e.g. SHAKE256) without touching call sites
//! that take a generic `B: CryptoBackend`. All existing SHA-256 test
//! vectors remain byte-for-byte identical.
//!
//! The abstraction is bound into proofs and Fiat–Shamir derivations via a
//! [`BackendId`] so that a proof produced under one backend can never be
//! accepted under another (see the proof crate).

use core::fmt;
use core::marker::PhantomData;

use digest::ExtendableOutput;
use digest::XofReader;
use sha2::Digest as _;
use sha2::Sha256;
use sha3::Shake256;
use subtle::ConstantTimeEq;

use crate::encoding::CanonicalEncode;
use crate::error::CryptoCoreError;

/// Domain separator for plain hashing.
pub const DOMAIN_HASH: &[u8] = b"private-payment-auth/hash/v2";
/// Domain separator for commitments.
pub const DOMAIN_COMMIT: &[u8] = b"private-payment-auth/commit/v2";
/// Domain separator for Fiat–Shamir challenge derivation.
pub const DOMAIN_FS: &[u8] = b"private-payment-auth/fs/v2";
/// Domain separator for circuit identity hashing.
pub const DOMAIN_CIRCUIT: &[u8] = b"private-payment-auth/circuit/v2";
/// Domain separator for policy hashing.
pub const DOMAIN_POLICY: &[u8] = b"private-payment-auth/policy/v2";
/// Domain separator for payment hashing.
pub const DOMAIN_PAYMENT: &[u8] = b"private-payment-auth/payment/v2";

/// Byte length of a canonical [`BackendId`] encoding.
pub const BACKEND_ID_LEN: usize = 16;

/// Canonical, fixed-width identifier of a cryptographic backend.
///
/// Stored as a 16-byte big-endian-padded ASCII tag (e.g. `b"sha256-v1\0\0\0\0\0"`)
/// so that two backends can be compared and serialized unambiguously and
/// with zero ambiguity about padding.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BackendId([u8; BACKEND_ID_LEN]);

impl BackendId {
    /// Constructs a backend id from a fixed 16-byte array.
    pub const fn new(bytes: [u8; BACKEND_ID_LEN]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw 16-byte identifier.
    pub fn as_bytes(&self) -> &[u8; BACKEND_ID_LEN] {
        &self.0
    }

    /// Returns the raw 16-byte identifier.
    pub fn to_array(&self) -> [u8; BACKEND_ID_LEN] {
        self.0
    }
}

impl CanonicalEncode for BackendId {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
}

impl fmt::Debug for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BackendId({})", hex(&self.0))
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex(&self.0))
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A generic fixed-length digest parameterized by its [`CryptoBackend`].
///
/// The byte length always equals `B::DIGEST_LEN`. Equality is
/// constant-time, the value is redacted in `Debug`, and the encoding is
/// the bare fixed-width byte string.
pub struct GenericDigest<B: CryptoBackend> {
    bytes: Vec<u8>,
    _marker: PhantomData<B>,
}

impl<B: CryptoBackend> GenericDigest<B> {
    /// Wraps raw bytes, asserting they match `B::DIGEST_LEN`.
    pub fn new(bytes: Vec<u8>) -> Self {
        assert_eq!(
            bytes.len(),
            B::DIGEST_LEN,
            "GenericDigest length must equal B::DIGEST_LEN"
        );
        Self {
            bytes,
            _marker: PhantomData,
        }
    }

    /// Parses a digest from a slice, rejecting wrong lengths.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoCoreError> {
        if bytes.len() != B::DIGEST_LEN {
            return Err(CryptoCoreError::InvalidLength);
        }
        Ok(Self {
            bytes: bytes.to_vec(),
            _marker: PhantomData,
        })
    }

    /// Borrows the digest bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Constant-time equality.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }

    /// Consumes the wrapper, returning the inner bytes.
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the digest as a fixed `[u8; 32]` when the backend uses the
    /// conventional 32-byte digest length. Panics otherwise.
    pub fn to_array_32(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes);
        out
    }
}

impl<B: CryptoBackend> Clone for GenericDigest<B> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            _marker: PhantomData,
        }
    }
}

impl<B: CryptoBackend> PartialEq for GenericDigest<B> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other)
    }
}

impl<B: CryptoBackend> Eq for GenericDigest<B> {}

impl<B: CryptoBackend> fmt::Debug for GenericDigest<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GenericDigest<{}>(REDACTED)", B::ID)
    }
}

impl<B: CryptoBackend> CanonicalEncode for GenericDigest<B> {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.bytes);
    }
}

/// A cryptographic backend: the set of primitives the protocol consumes.
///
/// Implementors are zero-sized markers (stateless), and all operations
/// are static methods over byte slices. Backends are selected by type
/// parameter at compile time, which keeps the hot path allocation-free
/// and lets the compiler monomorphize each instance.
pub trait CryptoBackend: Clone + Send + Sync + 'static {
    /// Unique identifier for this backend (e.g. `"sha256-v1"`).
    const ID: BackendId;

    /// Fixed digest length in bytes.
    const DIGEST_LEN: usize;

    /// Hash a byte slice to a fixed-length digest.
    fn hash(data: &[u8]) -> GenericDigest<Self>;

    /// Domain-separated hash: `H(domain || len(data) || data)`.
    fn hash_domain(domain: &[u8], data: &[u8]) -> GenericDigest<Self>;

    /// Expand output to a variable length (XOF-like). For SHA-256 this is
    /// implemented by iterative hashing; for SHAKE256 it is a native XOF.
    fn expand(domain: &[u8], data: &[u8], out_len: usize) -> Vec<u8>;

    /// Commitment: `H(domain || randomness || len(msg) || msg)`.
    fn commit(domain: &[u8], msg: &[u8], randomness: &[u8]) -> GenericDigest<Self>;
}

/// Frames `domain || len(data) || data` for domain-separated hashing.
fn frame(domain: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(domain.len() + 4 + data.len());
    domain.encode(&mut out);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

/// SHA-256 backend (the workspace default).
///
/// `Sha256Backend::hash(data)` produces exactly the same bytes as
/// `Sha256Hash::hash(data)` for identical inputs, preserving every
/// existing SHA-256 test vector.
#[derive(Clone, Copy, Debug, Default)]
pub struct Sha256Backend;

impl CryptoBackend for Sha256Backend {
    const ID: BackendId = BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0");
    const DIGEST_LEN: usize = 32;

    fn hash(data: &[u8]) -> GenericDigest<Self> {
        GenericDigest::new(sha256(data).to_vec())
    }

    fn hash_domain(domain: &[u8], data: &[u8]) -> GenericDigest<Self> {
        GenericDigest::new(sha256(&frame(domain, data)).to_vec())
    }

    fn expand(domain: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
        // Iterative hashing: out = H(domain || counter || data) concatenated.
        let mut out = Vec::with_capacity(out_len);
        let mut counter: u32 = 0;
        while out.len() < out_len {
            let mut input = Vec::with_capacity(domain.len() + 4 + data.len());
            domain.encode(&mut input);
            input.extend_from_slice(&counter.to_be_bytes());
            input.extend_from_slice(data);
            out.extend_from_slice(&sha256(&input));
            counter = counter.wrapping_add(1);
        }
        out.truncate(out_len);
        out
    }

    fn commit(domain: &[u8], msg: &[u8], randomness: &[u8]) -> GenericDigest<Self> {
        GenericDigest::new(sha256(&commit_frame(domain, msg, randomness)).to_vec())
    }
}

fn commit_frame(domain: &[u8], msg: &[u8], randomness: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        domain.len() + 4 + randomness.len() + 4 + msg.len(),
    );
    domain.encode(&mut out);
    randomness.encode(&mut out);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// SHAKE256 backend (a SHA-3 XOF).
///
/// Produces 32-byte fixed digests (matching SHA-256's length for protocol
/// compatibility) but uses the native variable-length XOF for `expand`,
/// which is its key advantage. **This does not by itself establish
/// post-quantum security for the whole MPCitH construction** — it only
/// makes the hash layer post-quantum-ready.
#[derive(Clone, Copy, Debug, Default)]
pub struct Shake256Backend;

impl CryptoBackend for Shake256Backend {
    const ID: BackendId = BackendId::new(*b"shake256-v1\0\0\0\0\0");
    const DIGEST_LEN: usize = 32;

    fn hash(data: &[u8]) -> GenericDigest<Self> {
        GenericDigest::new(shake256(&frame(DOMAIN_HASH, data), 32))
    }

    fn hash_domain(domain: &[u8], data: &[u8]) -> GenericDigest<Self> {
        GenericDigest::new(shake256(&frame(domain, data), 32))
    }

    fn expand(domain: &[u8], data: &[u8], out_len: usize) -> Vec<u8> {
        // Native XOF: SHAKE256(domain || len(data) || data, out_len).
        shake256(&frame(domain, data), out_len)
    }

    fn commit(domain: &[u8], msg: &[u8], randomness: &[u8]) -> GenericDigest<Self> {
        GenericDigest::new(shake256(&commit_frame(domain, msg, randomness), 32))
    }
}

fn sha256(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hasher.finalize().into()
}

fn shake256(input: &[u8], out_len: usize) -> Vec<u8> {
    let mut hasher = Shake256::default();
    digest::Update::update(&mut hasher, input);
    let mut reader = hasher.finalize_xof();
    let mut buf = vec![0u8; out_len];
    reader.read(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::HashFunction;

    #[test]
    fn sha256_backend_matches_legacy_sha256hash() {
        // The new backend must produce identical bytes to the legacy
        // Sha256Hash for the same inputs (no global SHA-256 change).
        let input = b"private-payment-auth test input";
        let legacy = crate::hash::Sha256Hash::hash(input);
        let backend = Sha256Backend::hash(input);
        assert_eq!(backend.as_bytes(), &legacy[..]);
    }

    #[test]
    fn sha256_backend_id_is_well_formed() {
        const SHA256_ID: [u8; 16] = *b"sha256-v1\0\0\0\0\0\0\0";
        const SHAKE_ID: [u8; 16] = *b"shake256-v1\0\0\0\0\0";
        assert_eq!(Sha256Backend::ID.as_bytes(), &SHA256_ID);
        assert_eq!(Shake256Backend::ID.as_bytes(), &SHAKE_ID);
    }

    #[test]
    fn backend_ids_differ() {
        assert_ne!(Sha256Backend::ID, Shake256Backend::ID);
    }

    #[test]
    fn sha256_and_shake256_outputs_differ() {
        let data = b"same input, different backend";
        let a = Sha256Backend::hash(data);
        let b = Shake256Backend::hash(data);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn domain_separation_holds() {
        let d1 = Sha256Backend::hash_domain(b"domain-a", b"x");
        let d2 = Sha256Backend::hash_domain(b"domain-b", b"x");
        let d3 = Sha256Backend::hash_domain(b"domain-a", b"y");
        assert_ne!(d1.as_bytes(), d2.as_bytes());
        assert_ne!(d1.as_bytes(), d3.as_bytes());
    }

    #[test]
    fn sha256_expand_is_deterministic_and_sized() {
        let out = Sha256Backend::expand(DOMAIN_FS, b"seed", 64);
        assert_eq!(out.len(), 64);
        assert_eq!(out, Sha256Backend::expand(DOMAIN_FS, b"seed", 64));
    }

    #[test]
    fn shake256_expand_is_native_xof() {
        let out = Shake256Backend::expand(DOMAIN_FS, b"seed", 100);
        assert_eq!(out.len(), 100);
        assert_eq!(out, Shake256Backend::expand(DOMAIN_FS, b"seed", 100));
    }

    #[test]
    fn commitments_are_deterministic() {
        let msg = b"message";
        let r = b"randomness-bytes-are-32-bytes-lo";
        let c1 = Sha256Backend::commit(DOMAIN_COMMIT, msg, r);
        let c2 = Sha256Backend::commit(DOMAIN_COMMIT, msg, r);
        assert_eq!(c1, c2);
        assert_ne!(
            Sha256Backend::commit(DOMAIN_COMMIT, b"other", r),
            c1
        );
    }

    #[test]
    fn digest_equality_is_constant_time_semantics() {
        let a = Sha256Backend::hash(b"a");
        let b = Sha256Backend::hash(b"a");
        assert!(a.ct_eq(&b));
        assert_eq!(a, b);
        let c = Sha256Backend::hash(b"c");
        assert!(!a.ct_eq(&c));
        assert_ne!(a, c);
    }
}
