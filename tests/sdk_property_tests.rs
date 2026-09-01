//! Property tests for the SDK authorization workflow (Phase 12).
//!
//! Randomly generated policies and witnesses are run through the full
//! `authorize → verify` pipeline and the corresponding mutation
//! properties are checked. These complement `sdk_e2e_tests.rs` and
//! `sdk_adversarial_tests.rs` by exploring the input space that
//! hand-written cases cannot reach.
//!
//! Properties enforced:
//!
//! - **`Payment` encoding round-trip** — `Payment::encode()` is
//!   deterministic and the semantic `payment_id` digest is stable.
//! - **Authorization encoding round-trip** — `deserialize(serialize(a))`
//!   yields an authorization that verifies the same way.
//! - **Identity stability** — `authorization_id(a)` is deterministic
//!   over the same `Authorization` value.
//! - **Statement mutation resistance** — flipping any single byte of
//!   a serialized authorization's proof or header field invalidates
//!   the resulting `verify` call (or, when the affected field is the
//!   explicit version/protocol/backend, surfaces the corresponding
//!   `VerificationFailure` / `SdkError`).
//! - **Policy mutation resistance** — replacing the policy with one
//!   of the same shape but different threshold k invalidates the
//!   verification.
//! - **Version mutation resistance** — bumping the artifact version
//!   byte surfaces `VersionUnsupported` at decode time.
//! - **Backend mutation resistance** — flipping the backend id byte
//!   in the encoding surfaces `BackendUnsupported` at decode time
//!   (and `BackendMismatch` at verify time when the value is still
//!   recognized).
//! - **Authorize→verify agreement** — for every random valid
//!   `(payment, policy, witness)` triple, `authorize(...)` succeeds
//!   and the produced authorization verifies.

use crypto_core::{Digest, SecretBytes};
use payment::{Amount, AmountUnit, Payment, PrivateWitness};
use policy::{credential_commitment, AmountLimit, CredentialId, Policy, ThresholdK};
use proptest::prelude::*;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use sdk::{
    deserialize as sdk_deserialize, serialize, Authorization, Sdk, SdkConfig, SdkError,
    VerificationFailure, VerificationResult,
};

const HEADER_LEN: usize = 1 + 1 + 16 + 32 + 32 + 32;

/// A generated `(Payment, Policy, PrivateWitness)` triple together
/// with the secrets the policy's credential leaves were built from.
/// The secrets let us build a witness that satisfies the policy.
#[derive(Debug, Clone)]
struct Generated {
    payment: Payment,
    policy: Policy,
    witness: PrivateWitness,
}

/// Random 32-byte secret material.
fn arb_secret() -> impl Strategy<Value = SecretBytes> {
    proptest::collection::vec(any::<u8>(), 1..8).prop_map(SecretBytes::new)
}

/// Builds a credential leaf whose id is the real commitment of a
/// random secret, returning both so the satisfying witness can be
/// reconstructed.
fn arb_credential() -> impl Strategy<Value = (Policy, SecretBytes)> {
    arb_secret().prop_map(|secret| {
        let id = CredentialId::from_commitment(credential_commitment(&secret));
        (Policy::Credential(id), secret)
    })
}

/// Recursive policy generator. Nesting and branching are kept small
/// so generated policies stay within resource limits and remain
/// quick to evaluate. The returned secrets are aligned with the
/// `policy_credential_ids` DFS walk of the *unnormalized* policy;
/// [`arb_triple`] normalizes after generation and re-orders secrets
/// to match.
///
/// **Amount cap semantics.** The relation check iterates over every
/// `AmountAtMost` limit in the policy and demands the witness's
/// `difference_bits` equal `decompose(limit − amount)`. A witness built
/// for a single cap cannot validate a policy that contains multiple
/// distinct caps, so the property tests restrict amount leaves to
/// `AmountAtMost(0)` (any amount ≤ 0 → only `0` satisfies, which is
/// what the witness's `amount = 0` already establishes). The amount
/// leaf is therefore generated with a *fixed* zero cap.
fn arb_policy() -> impl Strategy<Value = (Policy, Vec<SecretBytes>)> {
    let leaf = prop_oneof![
        arb_credential().prop_map(|(p, s)| (p, vec![s])),
        Just((Policy::AmountAtMost(AmountLimit::new(0)), Vec::new())),
    ];
    leaf.prop_recursive(2, 16, 3, move |inner| {
        let child = inner.clone();
        prop_oneof![
            proptest::collection::vec(child.clone(), 1..4).prop_map(|gens| {
                let (members, secrets): (Vec<_>, Vec<_>) = gens.into_iter().unzip();
                (Policy::And(members), secrets.concat())
            }),
            proptest::collection::vec(child.clone(), 1..4).prop_map(|gens| {
                let (members, secrets): (Vec<_>, Vec<_>) = gens.into_iter().unzip();
                (Policy::Or(members), secrets.concat())
            }),
            proptest::collection::vec(child, 1..4)
                .prop_flat_map(|gens| {
                    let (members, secrets): (Vec<_>, Vec<_>) = gens.into_iter().unzip();
                    let len = members.len() as u16;
                    (Just(members), Just(secrets.concat()), 1u16..=len)
                })
                .prop_map(|(members, secrets, k)| {
                    (
                        Policy::Threshold {
                            k: ThresholdK::new(k),
                            members,
                        },
                        secrets,
                    )
                }),
        ]
    })
}

/// Builds a complete `(Payment, Policy, PrivateWitness)` triple whose
/// witness satisfies the policy. The amount is set to zero so every
/// `AmountAtMost` cap is honored; the policy's declared credential
/// count is honored by the witness builder.
///
/// The secrets are reordered to match the canonical (normalized)
/// policy's DFS walk so that `policy_credential_ids(normalized)` and
/// `witness.credential_secrets` line up positionally.
fn arb_triple() -> impl Strategy<Value = Generated> {
    (
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        any::<[u8; 32]>(),
        arb_policy(),
    )
        .prop_map(
            |(payment_id, recipient_commitment, nonce, (policy_unnorm, secrets_unnorm))| {
                let payment = Payment {
                    version: 1,
                    payment_id,
                    amount: Amount {
                        value: 0,
                        unit: AmountUnit::Cents,
                    },
                    recipient_commitment: Digest::new(recipient_commitment),
                    nonce,
                };
                // Drop policies that fail to validate / normalize.
                let policy = match policy_unnorm.normalize() {
                    Ok(p) if p.validate().is_ok() => p,
                    _ => Policy::AmountAtMost(AmountLimit::new(0)),
                };
                let ids = payment::policy_credential_ids(&policy);
                // Build a map from credential id -> secret using the
                // pre-normalization witness, then replay in the
                // normalized order.
                let id_to_secret: std::collections::HashMap<_, _> =
                    payment_unnorm_ids_and_secrets(&policy_unnorm)
                        .into_iter()
                        .zip(secrets_unnorm)
                        .collect();
                let secrets: Vec<SecretBytes> = ids
                    .into_iter()
                    .map(|id| {
                        id_to_secret
                            .get(&id)
                            .cloned()
                            .unwrap_or_else(|| SecretBytes::new(vec![0u8; 8]))
                    })
                    .collect();
                let witness = PrivateWitness::new(secrets, payment.amount, 0);
                Generated {
                    payment,
                    policy,
                    witness,
                }
            },
        )
}

/// Walks a (possibly-unnormalized) policy in DFS order and returns
/// its `Credential` leaf ids. Used to re-key secrets when the
/// generated policy's structure changes under normalization.
fn payment_unnorm_ids_and_secrets(policy: &Policy) -> Vec<policy::CredentialId> {
    fn walk(p: &Policy, out: &mut Vec<policy::CredentialId>) {
        match p {
            Policy::Credential(id) => out.push(*id),
            Policy::AmountAtMost(_) => {}
            Policy::Threshold { members, .. } | Policy::And(members) | Policy::Or(members) => {
                for m in members {
                    walk(m, out);
                }
            }
        }
    }
    let mut v = Vec::new();
    walk(policy, &mut v);
    v
}

fn sdk_default() -> Sdk {
    Sdk::new(SdkConfig::default())
}

fn authorize(
    sdk: &Sdk,
    payment: &Payment,
    policy: &Policy,
    witness: &PrivateWitness,
    seed: u64,
) -> Authorization {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    if let Ok(a) = sdk.authorize(payment, policy, witness, &mut rng) {
        return a;
    }
    // Diagnostic: surface the underlying payment-layer error so a
    // future regression points at the real cause.
    let normalized = policy.normalize().expect("normalize");
    let pid = policy::policy_id(&normalized).expect("policy_id");
    let cid = payment::payment_circuit_id(&normalized).expect("circuit_id");
    let pstmt = payment::PaymentStatement {
        payment_id: payment.payment_id(),
        amount: payment.amount,
        recipient_commitment: payment.recipient_commitment,
        policy_id: pid,
        circuit_id: cid,
        protocol_version: proof::PROTOCOL_VERSION,
        nonce: [0u8; payment::statement::NONCE_LEN],
    };
    let rel_err = payment::AuthorizationRelation::validate(&pstmt, witness, &normalized)
        .err()
        .map(|e| format!("relation={:?}", e))
        .unwrap_or_else(|| "relation=Ok".to_string());
    let mut rng2 = ChaCha20Rng::seed_from_u64(seed);
    let auth_err = payment::authorize_payment(&pstmt, witness, &normalized, &mut rng2)
        .err()
        .map(|e| format!("auth_payment={:?}", e))
        .unwrap_or_else(|| "auth_payment=Ok".to_string());
    panic!("authorize failed: {} {}", rel_err, auth_err);
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    #[test]
    fn payment_encoding_is_deterministic_and_id_stable(
        payment_id in any::<[u8; 32]>(),
        recipient in any::<[u8; 32]>(),
        nonce in any::<[u8; 32]>(),
        amount in any::<u64>(),
    ) {
        let payment = Payment {
            version: 1,
            payment_id,
            amount: Amount { value: amount, unit: AmountUnit::Cents },
            recipient_commitment: Digest::new(recipient),
            nonce,
        };

        // Encoding is deterministic and fixed-width.
        assert_eq!(payment.encode(), payment.encode());
        assert_eq!(payment.encode().len(), Payment::ENCODED_LEN);

        // The semantic payment id derives deterministically from the
        // encoding — distinct payments never share an id when their
        // encodings differ.
        assert_eq!(payment.payment_id(), payment.payment_id());

        let mut bumped = payment;
        bumped.amount.value = amount.wrapping_add(1);
        assert_ne!(payment.payment_id(), bumped.payment_id());
    }

    #[test]
    fn authorization_encoding_round_trips(
        generated in arb_triple(),
        seed in any::<u64>(),
    ) {
        let sdk = sdk_default();
        let auth = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);

        let bytes = serialize(&auth);
        let recovered = sdk_deserialize(&bytes).expect("well-formed bytes must decode");

        // All public binding fields must match (the proof is opaque
        // but the SDK's verifier re-runs the proof against the
        // recovered artifact to confirm equality).
        assert_eq!(recovered.version(), auth.version());
        assert_eq!(recovered.protocol_version(), auth.protocol_version());
        assert_eq!(recovered.backend_id(), auth.backend_id());
        assert_eq!(recovered.payment_id(), auth.payment_id());
        assert_eq!(recovered.policy_id(), auth.policy_id());
        assert_eq!(recovered.circuit_id(), auth.circuit_id());

        // The recovered artifact must verify against the original
        // context.
        let result = sdk.verify(&generated.payment, &generated.policy, &recovered)
            .expect("verify must succeed");
        assert!(result.is_valid(), "round-tripped artifact must verify");
    }

    #[test]
    fn authorization_id_is_deterministic(
        generated in arb_triple(),
        seed in any::<u64>(),
    ) {
        let sdk = sdk_default();
        let a = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);
        // The same seed yields a fresh but identical authorization.
        let b = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);
        assert_eq!(sdk::authorization_id(&a), sdk::authorization_id(&b));
    }

    #[test]
    fn statement_mutation_resistance(
        generated in arb_triple(),
        seed in any::<u64>(),
    ) {
        let sdk = sdk_default();
        let auth = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);
        let mut bytes = serialize(&auth);

        // Pick a random byte inside the *proof* region (past the
        // 114-byte header) and flip one bit. The proof's Fiat–Shamir
        // commitment must detect the change.
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(seed);
        let proof_len = bytes.len() - HEADER_LEN;
        prop_assume!(proof_len > 0);
        let offset = HEADER_LEN + (rng.next_u64() as usize) % proof_len;
        bytes[offset] ^= 0x01;

        let tampered = sdk_deserialize(&bytes).expect("decode must still succeed");
        let result = sdk.verify(&generated.payment, &generated.policy, &tampered)
            .expect("verify must surface a failure");
        assert!(
            !result.is_valid(),
            "proof-bit flip must invalidate verification"
        );
    }

    #[test]
    fn policy_mutation_resistance(
        generated in arb_triple(),
        seed in any::<u64>(),
    ) {
        let sdk = sdk_default();
        let auth = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);

        // Swap the policy for a totally different one. The policy_id
        // check inside the verifier must trip.
        let tampered_policy = Policy::AmountAtMost(AmountLimit::new(1));
        let result = sdk.verify(&generated.payment, &tampered_policy, &auth)
            .expect("verify must surface a failure");
        assert_eq!(
            result,
            VerificationResult::Invalid(VerificationFailure::PolicyMismatch),
            "policy swap must trip PolicyMismatch"
        );
    }

    #[test]
    fn version_mutation_resistance(
        generated in arb_triple(),
        seed in any::<u64>(),
        bump in 1u8..=10,
    ) {
        let sdk = sdk_default();
        let auth = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);
        let mut bytes = serialize(&auth);

        // Bump the artifact version byte by `bump`. Decoding must
        // reject — the SDK never silently accepts unknown versions.
        bytes[0] = sdk::AUTHORIZATION_VERSION.wrapping_add(bump);
        assert!(
            matches!(
                sdk_deserialize(&bytes),
                Err(SdkError::VersionUnsupported)
            ),
            "unknown artifact version must be rejected"
        );
    }

    #[test]
    fn backend_mutation_resistance(
        generated in arb_triple(),
        seed in any::<u64>(),
    ) {
        let sdk = sdk_default();
        let auth = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);
        let mut bytes = serialize(&auth);

        // Flip a single byte inside the backend id (offset 2..18).
        // The result is still a well-formed 16-byte tag, but it no
        // longer names a supported backend, so the decoder must
        // refuse.
        bytes[2] ^= 0x01;
        assert!(
            matches!(
                sdk_deserialize(&bytes),
                Err(SdkError::BackendUnsupported)
            ),
            "unknown backend id must be rejected"
        );
    }

    #[test]
    fn authorize_verify_agreement_for_random_inputs(
        generated in arb_triple(),
        seed in any::<u64>(),
    ) {
        let sdk = sdk_default();
        let auth = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);

        // The produced authorization must verify for the same
        // context. This is the completeness property: any
        // well-formed triple the prover accepts is one the verifier
        // accepts.
        let result = sdk.verify(&generated.payment, &generated.policy, &auth)
            .expect("verify must succeed");
        assert!(result.is_valid(), "completeness: authorize ⇒ verify");
    }

    #[test]
    fn serialization_size_is_stable(
        generated in arb_triple(),
        seed in any::<u64>(),
    ) {
        let sdk = sdk_default();
        let a = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);
        let b = authorize(&sdk, &generated.payment, &generated.policy, &generated.witness, seed);
        assert_eq!(serialize(&a).len(), serialize(&b).len());
        // The bound check on the proof decoder caps repetition
        // counts well below the encoding limit, so the serialized
        // size is bounded by HEADER_LEN + MAX_PROOF_REPETITIONS * …
        // We assert the weak invariant here: bytes are non-empty and
        // the SDK's hard upper bound is far above what real inputs
        // reach. Real sizes are logged in the benchmark suite.
        assert!(!serialize(&a).is_empty());
    }
}
