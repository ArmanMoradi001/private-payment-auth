//! SDK-level configuration.
//!
//! [`SdkConfig`] is the small bag of knobs every SDK workflow reads:
//! the protocol version stamp, the chosen cryptographic backend, the
//! Fiat–Shamir repetition count, and whether to self-verify generated
//! authorizations before returning them to the caller.
//!
//! `SdkConfig` is constructed once and then frozen: every field is
//! private and exposed only through getters, so a workflow cannot
//! silently downgrade `repetitions` or flip `self_verify` mid-run.

use crypto_core::BackendId;
use crypto_core::CryptoBackend;
use crypto_core::Sha256Backend;

/// Default protocol version expected of incoming authorizations and
/// stamped into newly produced ones.
pub const DEFAULT_PROTOCOL_VERSION: u8 = 1;

/// Default Fiat–Shamir repetition count.
///
/// Matches the workspace-wide proof default; controls the
/// soundness/size tradeoff. Higher = better soundness, larger proof.
pub const DEFAULT_REPETITIONS: u32 = 12;

/// Immutable SDK configuration.
///
/// Construction is via [`SdkConfig::new`] (or [`SdkConfig::default`]).
/// After construction, every field is exposed only through getters and
/// cannot be mutated by the SDK caller.
#[derive(Clone, Copy, Debug)]
pub struct SdkConfig {
    protocol_version: u8,
    backend_id: BackendId,
    repetitions: u32,
    self_verify: bool,
}

impl SdkConfig {
    /// Builds an SDK configuration.
    pub fn new(
        protocol_version: u8,
        backend_id: BackendId,
        repetitions: u32,
        self_verify: bool,
    ) -> Self {
        Self {
            protocol_version,
            backend_id,
            repetitions,
            self_verify,
        }
    }

    /// Protocol version expected of incoming/stamped into outgoing
    /// authorizations.
    pub fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    /// The cryptographic backend selected for this SDK run.
    pub fn backend_id(&self) -> BackendId {
        self.backend_id
    }

    /// The Fiat–Shamir repetition count to use.
    pub fn repetitions(&self) -> u32 {
        self.repetitions
    }

    /// Whether to self-verify generated authorizations before
    /// returning them to the caller.
    pub fn self_verify(&self) -> bool {
        self.self_verify
    }
}

impl Default for SdkConfig {
    fn default() -> Self {
        Self::new(
            DEFAULT_PROTOCOL_VERSION,
            Sha256Backend::ID,
            DEFAULT_REPETITIONS,
            true,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sensible() {
        let cfg = SdkConfig::default();
        assert_eq!(cfg.protocol_version(), DEFAULT_PROTOCOL_VERSION);
        assert_eq!(cfg.protocol_version(), 1);
        assert_eq!(cfg.backend_id(), Sha256Backend::ID);
        assert_eq!(cfg.repetitions(), DEFAULT_REPETITIONS);
        assert_eq!(cfg.repetitions(), 12);
        assert!(cfg.self_verify());
    }

    #[test]
    fn config_is_immutable_after_construction() {
        let cfg = SdkConfig::new(2, Sha256Backend::ID, 8, false);
        assert_eq!(cfg.protocol_version(), 2);
        assert_eq!(cfg.repetitions(), 8);
        assert!(!cfg.self_verify());
    }

    #[test]
    fn config_is_clone_copy() {
        let cfg = SdkConfig::default();
        let copy = cfg;
        assert_eq!(cfg.protocol_version(), copy.protocol_version());
        assert_eq!(cfg.repetitions(), copy.repetitions());
        assert_eq!(cfg.self_verify(), copy.self_verify());
        assert_eq!(cfg.backend_id(), copy.backend_id());
    }
}
