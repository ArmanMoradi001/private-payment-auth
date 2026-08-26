//! Protocol configuration.
//!
//! A [`ProtocolConfig`] pins the cryptographic [`CryptoBackend`] used by a
//! prover/verifier pair and the engineering parameters (e.g. repetition
//! count). It is immutable after construction: there are no public
//! setters, so a config cannot be silently mutated mid-protocol.

use core::marker::PhantomData;

use crypto_core::backend::{CryptoBackend, Sha256Backend};

/// Configuration for a proof session.
pub struct ProtocolConfig<B: CryptoBackend = Sha256Backend> {
    backend: PhantomData<B>,
    repetitions: u32,
}

impl<B: CryptoBackend> ProtocolConfig<B> {
    /// Constructs a config with an explicit repetition count.
    pub fn new(repetitions: u32) -> Self {
        Self {
            backend: PhantomData,
            repetitions,
        }
    }

    /// The repetition count (number of MPCitH repetitions).
    pub fn repetitions(&self) -> u32 {
        self.repetitions
    }

    /// Marker so downstream code can recover the backend type.
    pub fn backend_id(&self) -> crypto_core::BackendId {
        B::ID
    }
}

impl<B: CryptoBackend> Default for ProtocolConfig<B> {
    fn default() -> Self {
        // Engineering parameter, NOT a production-safe security bound.
        Self::new(12)
    }
}
