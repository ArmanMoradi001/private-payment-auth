//! Core authorization artifact types.
//!
//! An [`Authorization`] is the immutable, self-contained artifact the
//! SDK produces and consumes. It bundles the version stamps and
//! identifiers needed to bind an authorization to a specific protocol,
//! cryptographic backend, payment, policy, and circuit, together with
//! the non-interactive proof that attests policy satisfaction.
//!
//! Construction is public (the SDK layers that build authorizations
//! need it), but every field is private and exposed only through
//! getters, so downstream code cannot mutate an authorization in place.

use core::fmt;

use crypto_core::BackendId;
use crypto_core::Digest;
use proof::NonInteractiveProof;

/// Domain separator binding authorization ids to this application and
/// authorization model version.
pub const AUTHORIZATION_ID_DOMAIN: &[u8] = b"private-payment-auth/authorization/v1";

/// Current authorization artifact encoding version.
///
/// Bumped whenever the on-the-wire layout of [`Authorization`] changes
/// in an incompatible way. Decoders/validators reject mismatches.
pub const AUTHORIZATION_VERSION: u8 = 1;

/// Complete authorization artifact: an immutable bundle of metadata
/// identifying the protocol/binding context together with the
/// non-interactive proof of policy satisfaction.
///
/// `Authorization` is public-by-construction but immutable afterwards:
/// every field is private and accessed only via getters. The contained
/// [`NonInteractiveProof`] carries no secrets (its secret inputs are
/// absorbed into MPCitH view commitments), so [`Debug`] may freely
/// format it; we still redact the proof's hidden material for defense
/// in depth and consistency with the proof crate's own redacting
/// implementation.
pub struct Authorization {
    version: u8,
    protocol_version: u8,
    backend_id: BackendId,
    payment_id: [u8; 32],
    policy_id: Digest,
    circuit_id: Digest,
    proof: NonInteractiveProof,
}

impl Clone for Authorization {
    fn clone(&self) -> Self {
        Self {
            version: self.version,
            protocol_version: self.protocol_version,
            backend_id: self.backend_id,
            payment_id: self.payment_id,
            policy_id: self.policy_id,
            circuit_id: self.circuit_id,
            proof: self.proof.clone(),
        }
    }
}

impl Authorization {
    /// Assembles an authorization artifact from its parts.
    ///
    /// This is the only way to construct an [`Authorization`]. Once
    /// constructed, every field is immutable: only getters are exposed.
    pub fn new(
        version: u8,
        protocol_version: u8,
        backend_id: BackendId,
        payment_id: [u8; 32],
        policy_id: Digest,
        circuit_id: Digest,
        proof: NonInteractiveProof,
    ) -> Self {
        Self {
            version,
            protocol_version,
            backend_id,
            payment_id,
            policy_id,
            circuit_id,
            proof,
        }
    }

    /// Artifact format version.
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Protocol version this authorization was produced under.
    pub fn protocol_version(&self) -> u8 {
        self.protocol_version
    }

    /// Cryptographic backend the proof was produced with.
    pub fn backend_id(&self) -> BackendId {
        self.backend_id
    }

    /// Raw 32-byte payment identifier bound by this authorization.
    pub fn payment_id(&self) -> &[u8; 32] {
        &self.payment_id
    }

    /// Semantic id of the policy satisfied by this authorization.
    pub fn policy_id(&self) -> Digest {
        self.policy_id
    }

    /// Semantic id of the circuit evaluated by the contained proof.
    pub fn circuit_id(&self) -> Digest {
        self.circuit_id
    }

    /// The non-interactive proof attesting policy satisfaction.
    pub fn proof(&self) -> &NonInteractiveProof {
        &self.proof
    }
}

impl fmt::Debug for Authorization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // An Authorization contains no secrets (the proof redacts its
        // own hidden material), but we still wrap the proof in a
        // redacting Debug for consistency with the proof crate.
        f.debug_struct("Authorization")
            .field("version", &self.version)
            .field("protocol_version", &self.protocol_version)
            .field("backend_id", &self.backend_id)
            .field("payment_id", &format_args!("{:02x?}", self.payment_id))
            .field("policy_id", &self.policy_id)
            .field("circuit_id", &self.circuit_id)
            .field(
                "proof",
                &format_args!("<redacted: {} repetitions>", self.proof.repetitions().len()),
            )
            .finish()
    }
}
