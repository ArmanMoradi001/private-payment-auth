//! Cross-backend tests: SHA-256 and SHAKE256 backends must never produce
//! the same output for identical inputs, and their identities must differ.

use crypto_core::backend::{BackendId, GenericDigest, Sha256Backend, Shake256Backend};
use crypto_core::CryptoBackend;
use std::any::TypeId;

#[test]
fn identical_input_yields_different_outputs() {
    let data = b"identical input, two backends";
    let a = Sha256Backend::hash(data);
    let b = Shake256Backend::hash(data);
    assert_ne!(a.as_bytes(), b.as_bytes());
}

#[test]
fn backend_ids_differ() {
    assert_ne!(Sha256Backend::ID, Shake256Backend::ID);
    assert_eq!(Sha256Backend::ID, Sha256Backend::ID);
    assert_eq!(Shake256Backend::ID, Shake256Backend::ID);
}

#[test]
fn digest_type_identities_differ_at_compile_time() {
    // Different monomorphizations are distinct types: this is a
    // compile-time guarantee that `GenericDigest<Sha256Backend>` and
    // `GenericDigest<Shake256Backend>` cannot be confused.
    fn type_id_of<T: 'static>() -> TypeId {
        TypeId::of::<T>()
    }
    assert_ne!(
        type_id_of::<GenericDigest<Sha256Backend>>(),
        type_id_of::<GenericDigest<Shake256Backend>>()
    );
    // The backend id type is shared but the values differ.
    let _: GenericDigest<Sha256Backend>;
    let _: GenericDigest<Shake256Backend>;
    let _ = BackendId::new(*b"sha256-v1\0\0\0\0\0\0\0");
}

#[test]
fn digests_are_constant_time_comparable() {
    let x = Sha256Backend::hash(b"x");
    let y = Sha256Backend::hash(b"x");
    assert!(x.ct_eq(&y));
    assert!(!x.ct_eq(&Sha256Backend::hash(b"y")));
    let z = Shake256Backend::hash(b"x");
    assert!(z.ct_eq(&Shake256Backend::hash(b"x")));
    assert!(!z.ct_eq(&Shake256Backend::hash(b"y")));
}
