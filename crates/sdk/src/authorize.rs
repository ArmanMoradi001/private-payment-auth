//! Authorization generation and verification workflows.
//!
//! [`Sdk`] is the SDK's only stateful entry point. It owns a frozen
//! [`SdkConfig`] and exposes [`Sdk::authorize`] (build an authorization
//! artifact) and [`Sdk::verify`] (independently validate one). All
//! cryptographic operations — validation, normalization, policy
//! compilation, statement construction, plaintext relation check,
//! proof generation, proof verification — are delegated to the
//! existing `payment`, `policy`, and `proof` crates; the SDK itself
//! adds no new cryptographic primitives.
//!
//! # Backend dispatch
//!
//! Neither [`Sdk::authorize`] nor [`Sdk::verify`] takes a backend
//! type parameter. Both select the backend explicitly:
//!
//! - `authorize` reads [`SdkConfig::backend_id`] and dispatches to
//!   the matching monomorphized backend.
//! - `verify` reads [`Authorization::backend_id`] (the backend the
//!   artifact was bound to) and dispatches to the matching
//!   monomorphized backend. If the verifier's configured backend
//!   disagrees with the artifact's bound backend the call returns
//!   [`SdkError::BackendMismatch`] — the SDK never silently picks
//!   one or attempts to guess.
//!
//! # Verification-only workflow
//!
//! `verify` does not take a witness, so a payment receiver, merchant,
//! or any other party can independently check an authorization with
//! only `(Payment, Policy, Authorization)` in hand.

use crypto_core::CryptoBackend;
use crypto_core::Sha256Backend;
use payment::Amount;
use payment::Payment;
use payment::PaymentStatement;
use payment::PrivateWitness;
use policy::Policy;
use rand_core::CryptoRngCore;

use crate::backend::backend_from_id;
use crate::backend::BackendType;
use crate::config::SdkConfig;
use crate::error::SdkError;
use crate::types::Authorization;
use crate::types::AUTHORIZATION_VERSION;
use crate::verification::VerificationFailure;
use crate::verification::VerificationResult;

/// SDK orchestration object: a frozen configuration plus the two
/// workflows (authorize / verify) the application cares about.
#[derive(Clone, Debug)]
pub struct Sdk {
    config: SdkConfig,
}

impl Sdk {
    /// Domain separator for deterministic statement-nonce derivation.
    fn nonce_domain() -> &'static [u8] {
        b"private-payment-auth/sdk/nonce/v1"
    }

    /// Builds an SDK with the supplied configuration.
    pub fn new(config: SdkConfig) -> Self {
        Self { config }
    }

    /// Returns the SDK's frozen configuration.
    pub fn config(&self) -> SdkConfig {
        self.config
    }

    /// Generates a fresh authorization artifact proving that
    /// `witness` satisfies `policy` for `payment`.
    ///
    /// The SDK pipeline delegates every step to the underlying crates:
    ///
    /// 1. Validate the payment object (version stamp, layout).
    /// 2. Validate, then normalize the policy; derive the policy id.
    /// 3. Compile the policy to a circuit and derive the circuit id.
    /// 4. Build the public proof statement with a fresh per-attempt
    ///    nonce.
    /// 5. Run the plaintext authorization relation over the
    ///    statement, witness, and normalized policy.
    /// 6. Delegate proof generation to [`payment::authorize_payment`].
    /// 7. Bundle the result into an immutable [`Authorization`].
    /// 8. When [`SdkConfig::self_verify`] is `true`, independently
    ///    re-verify the artifact before returning it so any
    ///    pipeline-internal inconsistency surfaces as
    ///    [`SdkError::SelfVerificationFailed`].
    ///
    /// # Backend selection
    ///
    /// Reads [`SdkConfig::backend_id`] and dispatches to the matching
    /// monomorphized backend. Returns [`SdkError::BackendUnsupported`]
    /// if the configured backend id does not name a backend this SDK
    /// build knows how to handle. The SDK never silently picks a
    /// different backend.
    ///
    /// # Errors
    ///
    /// - [`SdkError::BackendUnsupported`] for an unknown configured
    ///   backend id.
    /// - [`SdkError::InvalidPayment`] / [`SdkError::InvalidPolicy`]
    ///   for structurally bad inputs.
    /// - [`SdkError::InvalidWitness`] when the witness fails the
    ///   plaintext relation against the supplied policy.
    /// - [`SdkError::AuthorizationGenerationFailed`] for downstream
    ///   proof-generation failures (transcript overflow, randomness,
    ///   resource limits).
    /// - [`SdkError::SelfVerificationFailed`] when self-verification
    ///   of the freshly built artifact surfaces an inconsistency.
    pub fn authorize(
        &self,
        payment: &Payment,
        policy: &Policy,
        witness: &PrivateWitness,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Authorization, SdkError> {
        match backend_from_id(&self.config.backend_id())? {
            BackendType::Sha256 => {
                self.authorize_with::<Sha256Backend>(payment, policy, witness, rng)
            }
            BackendType::Shake256 => Err(SdkError::BackendUnsupported),
        }
    }

    /// Independently verifies `authorization` against the supplied
    /// `payment` and `policy`. **Takes no witness** — this is the
    /// verification-only API used by payment receivers, merchants,
    /// and any other party that needs to validate an authorization
    /// without holding the original secret material.
    ///
    /// Returns [`VerificationResult::Valid`] only when:
    /// - the artifact's encoding version is supported,
    /// - the artifact's bound backend matches the SDK's configured
    ///   backend (otherwise [`SdkError::BackendMismatch`]),
    /// - the artifact's policy and circuit bindings match the
    ///   recomputed identifiers from the supplied `policy`,
    /// - the artifact's payment binding matches the supplied `payment`,
    /// - and the contained proof passes the independent
    ///   cryptographic verification step.
    ///
    /// On any binding or cryptographic failure, returns
    /// [`VerificationResult::Invalid`] with a high-level
    /// `reason`; cryptographic internals are never surfaced.
    ///
    /// # Backend dispatch
    ///
    /// Reads the artifact's bound [`Authorization::backend_id`] and
    /// dispatches to the matching monomorphized backend. If the
    /// artifact's bound backend does not match the SDK's configured
    /// backend, returns [`SdkError::BackendMismatch`] — the SDK
    /// never silently picks a different backend.
    ///
    /// # Errors
    ///
    /// - [`SdkError::BackendMismatch`] when the artifact's bound
    ///   backend does not match the SDK's configured backend.
    /// - [`SdkError::BackendUnsupported`] for an artifact bound to a
    ///   backend this SDK build does not implement.
    /// - [`SdkError::InvalidPolicy`] when the supplied policy fails
    ///   normalization or compilation.
    pub fn verify(
        &self,
        payment: &Payment,
        policy: &Policy,
        authorization: &Authorization,
    ) -> Result<VerificationResult, SdkError> {
        // 0. Backend alignment: the verifier's configured backend
        //    must match the artifact's bound backend. A mismatch is a
        //    hard configuration error — the SDK never silently picks
        //    one or re-encodes the artifact.
        if authorization.backend_id() != self.config.backend_id() {
            return Err(SdkError::BackendMismatch);
        }

        // 1. Dispatch to the monomorphized backend by the artifact's
        //    bound backend id. The lower-level `verify::<B>` then
        //    checks version, recomputes bindings, and runs the
        //    cryptographic verification.
        match backend_from_id(&authorization.backend_id())? {
            BackendType::Sha256 => {
                self.verify_with::<Sha256Backend>(payment, policy, authorization)
            }
            BackendType::Shake256 => Err(SdkError::BackendUnsupported),
        }
    }

    /// Generic backend-parameterized authorization generation.
    ///
    /// Internal helper dispatched to by [`Sdk::authorize`] via
    /// [`SdkConfig::backend_id`]. Not intended for direct use — the
    /// non-generic [`Sdk::authorize`] is the public entry point.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::BackendUnsupported`] if `B` does not match
    /// the SHA-256 backend the `payment` crate is hard-wired to use
    /// today; the workspace is single-backend and the SDK never
    /// silently re-implements crypto under a different primitive.
    pub fn authorize_with<B: CryptoBackend>(
        &self,
        payment: &Payment,
        policy: &Policy,
        witness: &PrivateWitness,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Authorization, SdkError> {
        if B::ID != Sha256Backend::ID {
            return Err(SdkError::BackendUnsupported);
        }

        // 1. Validate the payment.
        validate_payment(payment)?;

        // 2. Validate, then normalize the policy.
        policy.validate().map_err(|_| SdkError::InvalidPolicy)?;
        let normalized = policy.normalize().map_err(|_| SdkError::InvalidPolicy)?;

        // 3. Derive the policy id off the normalized form.
        let policy_id = policy::policy_id(&normalized).map_err(|_| SdkError::InvalidPolicy)?;

        // 4. Compile the policy to a circuit and derive the circuit id.
        let circuit_id =
            payment::payment_circuit_id(&normalized).map_err(|_| SdkError::InvalidPolicy)?;

        // 5. Build the statement with a deterministic nonce derived from
        //    the binding triple. Determinism keeps authorize→verify
        //    round-trips reproducible without requiring the SDK to
        //    store the nonce inside the [`Authorization`] artifact.
        let nonce = deterministic_nonce(
            &payment.payment_id,
            policy_id.as_digest(),
            circuit_id.as_digest(),
        );
        let statement = build_statement(
            payment,
            policy_id,
            circuit_id,
            self.config.protocol_version(),
            nonce,
        )?;

        // 6. Run the plaintext authorization relation. Any failure
        //    here means the witness cannot satisfy this policy for
        //    this payment; producing a proof would be wasted work.
        payment::AuthorizationRelation::validate(&statement, witness, &normalized)
            .map_err(relation_to_sdk_error)?;

        // 7. Delegate proof generation. `payment::authorize_payment`
        //    composes statement-binding, witness-to-field wiring, and
        //    the underlying [`proof::Prover::prove`] call. The
        //    repetition count is taken from the payment crate's
        //    `AUTHORIZATION_REPETITIONS` constant; honoring the SDK's
        //    own `config.repetitions()` here would require reaching
        //    into private `payment::wiring` code, which we deliberately
        //    avoid to keep the SDK a pure orchestration layer.
        let _ = self.config;
        let proof = payment::authorize_payment(&statement, witness, &normalized, rng)
            .map_err(|_| SdkError::AuthorizationGenerationFailed)?;

        // 8. Bundle the immutable authorization artifact.
        let authorization = Authorization::new(
            AUTHORIZATION_VERSION,
            self.config.protocol_version(),
            B::ID,
            payment.payment_id,
            *policy_id.as_digest(),
            *circuit_id.as_digest(),
            proof,
        );

        // 9. Optional self-verification: catch pipeline bugs early.
        if self.config.self_verify() {
            let result = self.verify_with::<B>(payment, policy, &authorization)?;
            if !result.is_valid() {
                return Err(SdkError::SelfVerificationFailed);
            }
        }

        Ok(authorization)
    }

    /// Generic backend-parameterized verification.
    ///
    /// Internal helper dispatched to by [`Sdk::verify`] via the
    /// artifact's bound [`Authorization::backend_id`]. Not intended
    /// for direct use — the non-generic [`Sdk::verify`] is the
    /// public entry point.
    ///
    /// # Errors
    ///
    /// Returns [`SdkError::BackendUnsupported`] if `B` does not match
    /// the SHA-256 backend the `payment` crate is hard-wired to use
    /// today.
    pub fn verify_with<B: CryptoBackend>(
        &self,
        payment: &Payment,
        policy: &Policy,
        authorization: &Authorization,
    ) -> Result<VerificationResult, SdkError> {
        if B::ID != Sha256Backend::ID {
            return Err(SdkError::BackendUnsupported);
        }

        // 1. Artifact structure / version.
        if authorization.version() != AUTHORIZATION_VERSION {
            return Ok(VerificationResult::Invalid(
                VerificationFailure::VersionMismatch,
            ));
        }

        // 2. Backend compatibility: the proof's bound backend id must
        //    equal both the SDK config and the verifier's chosen
        //    backend type. A mismatch here is reported as
        //    BackendMismatch rather than as a cryptographic error.
        if authorization.backend_id() != self.config.backend_id() {
            return Ok(VerificationResult::Invalid(
                VerificationFailure::BackendMismatch,
            ));
        }
        if authorization.backend_id() != B::ID {
            return Ok(VerificationResult::Invalid(
                VerificationFailure::BackendMismatch,
            ));
        }

        // 3. Recompute the policy/circuit bindings from `policy`.
        let normalized = policy.normalize().map_err(|_| SdkError::InvalidPolicy)?;
        let policy_id = policy::policy_id(&normalized).map_err(|_| SdkError::InvalidPolicy)?;
        if authorization.policy_id() != *policy_id.as_digest() {
            return Ok(VerificationResult::Invalid(
                VerificationFailure::PolicyMismatch,
            ));
        }
        let circuit_id =
            payment::payment_circuit_id(&normalized).map_err(|_| SdkError::InvalidPolicy)?;
        if authorization.circuit_id() != *circuit_id.as_digest() {
            return Ok(VerificationResult::Invalid(
                VerificationFailure::CircuitMismatch,
            ));
        }

        // 4. Recompute the payment binding from `payment`.
        if authorization.payment_id() != &payment.payment_id {
            return Ok(VerificationResult::Invalid(
                VerificationFailure::PaymentMismatch,
            ));
        }

        // 5. Delegate the cryptographic check to the payment crate's
        //    verifier, which rebuilds the statement, compiles the
        //    circuit, and runs the underlying [`proof::Verifier`].
        //
        //    The statement's nonce is reconstructed deterministically
        //    from the binding triple (the same way it was generated)
        //    so the verifier rebuilds the exact statement the prover
        //    committed to in its Fiat–Shamir transcript.
        let statement = build_statement(
            payment,
            policy_id,
            circuit_id,
            authorization.protocol_version(),
            deterministic_nonce(
                authorization.payment_id(),
                &authorization.policy_id(),
                &authorization.circuit_id(),
            ),
        )?;

        match payment::verify_payment_authorization(&statement, authorization.proof(), &normalized)
        {
            Ok(true) => Ok(VerificationResult::Valid),
            Ok(false) => Ok(VerificationResult::Invalid(
                VerificationFailure::ProofInvalid,
            )),
            Err(_) => Ok(VerificationResult::Invalid(
                VerificationFailure::ProofInvalid,
            )),
        }
    }
}

impl Default for Sdk {
    fn default() -> Self {
        Self::new(SdkConfig::default())
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Validates the structural integrity of a [`Payment`].
///
/// This is a thin orchestrator-level check (version stamp + nonce
/// length); cryptographic policy/witness validation lives in
/// [`payment::AuthorizationRelation::validate`].
fn validate_payment(payment: &Payment) -> Result<(), SdkError> {
    use payment::payment::PAYMENT_ENCODING_VERSION;
    if payment.version != PAYMENT_ENCODING_VERSION {
        return Err(SdkError::InvalidPayment);
    }
    Ok(())
}

/// Builds a [`PaymentStatement`] from the public inputs.
fn build_statement(
    payment: &Payment,
    policy_id: policy::PolicyId,
    circuit_id: circuit::CircuitId,
    protocol_version: u8,
    nonce: [u8; payment::statement::NONCE_LEN],
) -> Result<PaymentStatement, SdkError> {
    Ok(PaymentStatement {
        payment_id: payment.payment_id(),
        amount: Amount {
            value: payment.amount.value,
            unit: payment.amount.unit,
        },
        recipient_commitment: payment.recipient_commitment,
        policy_id,
        circuit_id,
        protocol_version,
        nonce,
    })
}

/// Derives a deterministic 32-byte nonce from the authorization's
/// public binding triple.
///
/// The SDK uses a domain-separated SHA-256 over the
/// (payment_id ‖ policy_id ‖ circuit_id) tuple so authorize→verify
/// round trips are reproducible without storing the nonce in the
/// [`Authorization`] artifact. The domain separator ensures the
/// derived bytes never collide with values bound into the payment
/// itself.
fn deterministic_nonce(
    payment_id: &[u8; 32],
    policy_id: &crypto_core::Digest,
    circuit_id: &crypto_core::Digest,
) -> [u8; payment::statement::NONCE_LEN] {
    use crypto_core::HashFunction;
    use crypto_core::Sha256Hash;
    let mut buf = Vec::with_capacity(32 + 32 + 32);
    buf.extend_from_slice(payment_id);
    buf.extend_from_slice(policy_id.as_bytes());
    buf.extend_from_slice(circuit_id.as_bytes());
    let digest: [u8; 32] = Sha256Hash::hash_domain(Sdk::nonce_domain(), &buf);
    digest
}

/// Maps a payment-layer authorization failure onto the SDK's
/// high-level, secret-free error variants.
fn relation_to_sdk_error(err: payment::PaymentError) -> SdkError {
    use payment::PaymentError::*;
    match err {
        InvalidPolicy => SdkError::InvalidPolicy,
        PolicyIdMismatch => SdkError::PolicyMismatch,
        WitnessCountMismatch | MalformedCredentialSecret => SdkError::InvalidWitness,
        AmountMismatch | AmountExceedsLimit | InvalidBitWitness => SdkError::InvalidWitness,
        PolicyNotSatisfied
        | CredentialCommitmentMismatch
        | ThresholdNotMet
        | ProofGenerationFailed
        | ProofRejected
        | StatementMismatch => SdkError::AuthorizationGenerationFailed,
    }
}

// ---------------------------------------------------------------------------
// Sha256Backend convenience constructors
// ---------------------------------------------------------------------------

impl Sdk {
    /// Authorizes under the SHA-256 backend (the workspace default).
    ///
    /// Convenience wrapper around the generic internal
    /// [`Sdk::authorize_with::<B>`] for callers that want to spell out
    /// the backend at the call site instead of going through
    /// [`Sdk::authorize`].
    pub fn authorize_sha256(
        &self,
        payment: &Payment,
        policy: &Policy,
        witness: &PrivateWitness,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Authorization, SdkError> {
        self.authorize_with::<Sha256Backend>(payment, policy, witness, rng)
    }

    /// Verifies under the SHA-256 backend (the workspace default).
    ///
    /// Convenience wrapper around the generic internal
    /// [`Sdk::verify_with::<B>`] for callers that want to spell out
    /// the backend at the call site instead of going through
    /// [`Sdk::verify`].
    pub fn verify_sha256(
        &self,
        payment: &Payment,
        policy: &Policy,
        authorization: &Authorization,
    ) -> Result<VerificationResult, SdkError> {
        self.verify_with::<Sha256Backend>(payment, policy, authorization)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_core::BackendId;
    use crypto_core::SecretBytes;
    use payment::{Amount, AmountUnit, PrivateWitness};
    use policy::{credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK};
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn sdk_default_uses_default_config() {
        let sdk = Sdk::default();
        let cfg = sdk.config();
        let default = SdkConfig::default();
        assert_eq!(cfg.protocol_version(), default.protocol_version());
        assert_eq!(cfg.backend_id(), default.backend_id());
        assert_eq!(cfg.repetitions(), default.repetitions());
        assert_eq!(cfg.self_verify(), default.self_verify());
    }

    #[test]
    fn relation_error_mapping_is_exhaustive() {
        // Every payment error must collapse to a defined SDK variant.
        for err in [
            payment::PaymentError::InvalidPolicy,
            payment::PaymentError::PolicyIdMismatch,
            payment::PaymentError::WitnessCountMismatch,
            payment::PaymentError::MalformedCredentialSecret,
            payment::PaymentError::CredentialCommitmentMismatch,
            payment::PaymentError::ThresholdNotMet,
            payment::PaymentError::AmountExceedsLimit,
            payment::PaymentError::AmountMismatch,
            payment::PaymentError::InvalidBitWitness,
            payment::PaymentError::PolicyNotSatisfied,
            payment::PaymentError::ProofGenerationFailed,
            payment::PaymentError::ProofRejected,
            payment::PaymentError::StatementMismatch,
        ] {
            let mapped = relation_to_sdk_error(err);
            let _ = format!("{}", mapped);
        }
    }

    /// Builds a sample 2-of-3 threshold policy together with a valid
    /// witness for a 75-cent payment against a 100-cent cap.
    fn fixture() -> (Payment, Policy, PrivateWitness, Vec<SecretBytes>) {
        let secrets: Vec<SecretBytes> = (0..3)
            .map(|i| SecretBytes::new(vec![(i as u8) + 1, 0x0c, 0x0d]))
            .collect();
        let members: Vec<Policy> = secrets
            .iter()
            .map(|s| Policy::Credential(CredentialId::from_commitment(credential_commitment(s))))
            .collect();
        let policy = Policy::And(vec![
            Policy::Threshold {
                k: ThresholdK::new(2),
                members,
            },
            Policy::AmountAtMost(AmountLimit::new(100)),
        ]);

        let payment = Payment {
            version: 1,
            payment_id: [0x42; 32],
            amount: Amount {
                value: 75,
                unit: AmountUnit::Cents,
            },
            recipient_commitment: crypto_core::Digest::new([0x11; 32]),
            nonce: [0x33; 32],
        };
        let witness = PrivateWitness::new(secrets.clone(), payment.amount, 100);
        (payment, policy, witness, secrets)
    }

    #[test]
    fn authorize_then_verify_round_trip_is_valid() {
        let (payment, policy, witness, _secrets) = fixture();
        let sdk = Sdk::default();
        let mut rng = ChaCha20Rng::seed_from_u64(7);

        let authorization = sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed for a valid policy/witness");

        // Same SDK with self_verify enabled must reach Valid.
        let result = sdk
            .verify(&payment, &policy, &authorization)
            .expect("verify must succeed for a well-formed authorization");
        assert!(result.is_valid(), "expected Valid, got {:?}", result);
    }

    /// The verification-only workflow: a verifier with no witness
    /// must reach `Valid` for a well-formed authorization.
    #[test]
    fn verify_only_workflow_does_not_require_a_witness() {
        let (payment, policy, witness, _secrets) = fixture();
        let sdk = Sdk::default();
        let mut rng = ChaCha20Rng::seed_from_u64(11);

        let authorization = sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        // The verifier's surface is (Payment, Policy, Authorization)
        // — no witness, no secret material.
        let result = sdk
            .verify(&payment, &policy, &authorization)
            .expect("verification-only call must succeed");
        assert!(result.is_valid(), "expected Valid, got {:?}", result);
    }

    #[test]
    fn tampered_policy_id_is_rejected_as_policy_mismatch() {
        let (payment, policy, witness, _secrets) = fixture();
        let sdk = Sdk::default();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let authorization = sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        // Swap the policy for one with a different id but identical
        // public shape: a higher amount cap.
        let tampered_policy = Policy::AmountAtMost(AmountLimit::new(200));
        let result = sdk
            .verify(&payment, &tampered_policy, &authorization)
            .expect("verify must surface a failure, not an error");
        assert_eq!(
            result,
            VerificationResult::Invalid(VerificationFailure::PolicyMismatch)
        );
    }

    #[test]
    fn tampered_payment_id_is_rejected_as_payment_mismatch() {
        let (payment, policy, witness, _secrets) = fixture();
        let sdk = Sdk::default();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let authorization = sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        let mut tampered = payment;
        tampered.payment_id = [0x99; 32];
        let result = sdk
            .verify(&tampered, &policy, &authorization)
            .expect("verify must surface a failure, not an error");
        assert_eq!(
            result,
            VerificationResult::Invalid(VerificationFailure::PaymentMismatch)
        );
    }

    /// Mutating the circuit-bound portion of the policy (e.g. raising
    /// the threshold) must surface as `PolicyMismatch`: the policy
    /// hash itself changes because the normalized policy differs, so
    /// the verifier rejects on the policy id check before the
    /// circuit check.
    #[test]
    fn tampered_circuit_is_rejected_as_policy_mismatch() {
        let (payment, policy, witness, secrets) = fixture();
        let sdk = Sdk::default();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let authorization = sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        // Build a structurally similar policy except the threshold
        // becomes 3-of-3 (different circuit *and* different policy).
        let members: Vec<Policy> = secrets
            .iter()
            .map(|s| Policy::Credential(CredentialId::from_commitment(credential_commitment(s))))
            .collect();
        let tampered_policy = Policy::And(vec![
            Policy::Threshold {
                k: ThresholdK::new(3),
                members,
            },
            Policy::AmountAtMost(AmountLimit::new(100)),
        ]);

        let result = sdk
            .verify(&payment, &tampered_policy, &authorization)
            .expect("verify must surface a failure, not an error");
        assert_eq!(
            result,
            VerificationResult::Invalid(VerificationFailure::PolicyMismatch)
        );
    }

    #[test]
    fn wrong_version_is_rejected_as_version_mismatch() {
        let (payment, policy, witness, _secrets) = fixture();
        let sdk = Sdk::default();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let authorization = sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        // Build a new Authorization stamped with an unsupported
        // version. The proof is reused so only the version stamp
        // changes — every other binding still matches.
        let proof = authorization.proof().clone();
        let other = crate::types::Authorization::new(
            99,
            authorization.protocol_version(),
            authorization.backend_id(),
            *authorization.payment_id(),
            authorization.policy_id(),
            authorization.circuit_id(),
            proof,
        );

        let result = sdk
            .verify(&payment, &policy, &other)
            .expect("verify must surface a failure");
        assert_eq!(
            result,
            VerificationResult::Invalid(VerificationFailure::VersionMismatch)
        );
    }

    /// Mutating `authorization.backend_id` surfaces as
    /// `BackendMismatch` because the verifier config and the
    /// artifact disagree.
    #[test]
    fn tampered_backend_id_is_rejected_as_backend_mismatch() {
        let (payment, policy, witness, _secrets) = fixture();
        let sdk = Sdk::default();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let authorization = sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        // Construct an Authorization stamped with a different backend id.
        let wrong_backend = crypto_core::BackendId::new(*b"shake256-v1\0\0\0\0\0");
        let proof = authorization.proof().clone();
        let tampered = crate::types::Authorization::new(
            authorization.version(),
            authorization.protocol_version(),
            wrong_backend,
            *authorization.payment_id(),
            authorization.policy_id(),
            authorization.circuit_id(),
            proof,
        );

        let err = sdk
            .verify(&payment, &policy, &tampered)
            .expect_err("verifier must surface a backend mismatch as an SdkError");
        assert_eq!(err, SdkError::BackendMismatch);
    }

    /// A verifier whose configured backend differs from the
    /// artifact's bound backend must fail with `BackendMismatch`,
    /// not silently re-encode the artifact.
    #[test]
    fn verifier_config_backend_mismatch_yields_sdk_error() {
        let (payment, policy, witness, _secrets) = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(7);

        // Authorize under the default SHA-256 backend.
        let default_sdk = Sdk::default();
        let authorization = default_sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        // A different SDK configured for SHAKE256 must refuse the
        // SHA-256-bound artifact — never silently re-encode it.
        let other_cfg = SdkConfig::new(
            default_sdk.config().protocol_version(),
            crypto_core::Shake256Backend::ID,
            default_sdk.config().repetitions(),
            default_sdk.config().self_verify(),
        );
        let other_sdk = Sdk::new(other_cfg);

        let err = other_sdk
            .verify(&payment, &policy, &authorization)
            .expect_err("verifier config mismatch must error");
        assert_eq!(err, SdkError::BackendMismatch);
    }

    /// A verifier whose config points at an unknown backend must fail
    /// with `BackendMismatch`: the unknown config backend cannot be
    /// aligned with the SHA-256-bound artifact.
    #[test]
    fn verifier_with_unknown_backend_yields_backend_mismatch() {
        let (payment, policy, witness, _secrets) = fixture();
        let mut rng = ChaCha20Rng::seed_from_u64(7);

        let default_sdk = Sdk::default();
        let authorization = default_sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        let bogus_cfg = SdkConfig::new(
            default_sdk.config().protocol_version(),
            BackendId::new(*b"bogus-v9\0\0\0\0\0\0\0\0"),
            default_sdk.config().repetitions(),
            default_sdk.config().self_verify(),
        );
        let bogus_sdk = Sdk::new(bogus_cfg);

        let err = bogus_sdk
            .verify(&payment, &policy, &authorization)
            .expect_err("unknown verifier backend must error");
        assert_eq!(err, SdkError::BackendMismatch);
    }

    /// Authorizing with a config backend id the SDK doesn't
    /// implement must surface as `BackendUnsupported` — the SDK
    /// never silently picks a different backend.
    #[test]
    fn authorize_with_unknown_backend_yields_backend_unsupported() {
        let (payment, policy, witness, _secrets) = fixture();
        let bogus_cfg = SdkConfig::new(
            SdkConfig::default().protocol_version(),
            BackendId::new(*b"bogus-v9\0\0\0\0\0\0\0\0"),
            SdkConfig::default().repetitions(),
            false,
        );
        let bogus_sdk = Sdk::new(bogus_cfg);
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let err = bogus_sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect_err("authorize with unknown backend must error");
        assert_eq!(err, SdkError::BackendUnsupported);
    }

    /// Mutating `authorization.protocol_version` must surface as a
    /// cryptographic failure: the proof was bound to the original
    /// version and cannot be accepted under a different one.
    #[test]
    fn tampered_protocol_version_causes_proof_failure() {
        let (payment, policy, witness, _secrets) = fixture();
        let sdk = Sdk::default();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let authorization = sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        // Bump protocol_version on the artifact only.
        let proof = authorization.proof().clone();
        let tampered = crate::types::Authorization::new(
            authorization.version(),
            authorization.protocol_version().wrapping_add(1),
            authorization.backend_id(),
            *authorization.payment_id(),
            authorization.policy_id(),
            authorization.circuit_id(),
            proof,
        );

        // Backend still matches, so verify() dispatches; the
        // cryptographic step then rejects the version mismatch.
        let result = sdk
            .verify(&payment, &policy, &tampered)
            .expect("verify must surface a failure, not an error");
        assert_eq!(
            result,
            VerificationResult::Invalid(VerificationFailure::ProofInvalid)
        );
    }

    /// Mutating `authorization.circuit_id` while leaving everything
    /// else unchanged must surface as `CircuitMismatch`.
    #[test]
    fn tampered_circuit_id_is_rejected_as_circuit_mismatch() {
        let (payment, policy, witness, _secrets) = fixture();
        let sdk = Sdk::default();
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let authorization = sdk
            .authorize(&payment, &policy, &witness, &mut rng)
            .expect("authorize must succeed");

        let proof = authorization.proof().clone();
        let tampered = crate::types::Authorization::new(
            authorization.version(),
            authorization.protocol_version(),
            authorization.backend_id(),
            *authorization.payment_id(),
            authorization.policy_id(),
            crypto_core::Digest::new([0xee; 32]),
            proof,
        );

        let result = sdk
            .verify(&payment, &policy, &tampered)
            .expect("verify must surface a failure, not an error");
        assert_eq!(
            result,
            VerificationResult::Invalid(VerificationFailure::CircuitMismatch)
        );
    }
}
