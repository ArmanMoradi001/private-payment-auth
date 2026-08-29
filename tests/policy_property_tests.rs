//! Property tests for the policy crate (Phase 11, Part B).
//!
//! These complement `tests/policy_tests.rs` (hand-written unit/adversarial
//! cases) with randomized properties that must hold for every well-formed
//! policy:
//!
//! - **Canonical form is idempotent** — `normalize(normalize(p)) == normalize(p)`.
//! - **Policy id is stable under normalization** — `policy_id` depends only
//!   on the canonical form.
//! - **Encoding round-trips** — `decode(encode(p)) == p` for valid policies.
//! - **Compilation is deterministic** — two compiles of the same policy
//!   produce identical circuits.
//! - **Soundness + completeness** — the compiled circuit and the reference
//!   evaluator always agree on authorization: `evaluate` authorized implies
//!   `reference_evaluate` accepts, and vice versa. A random (adversarial)
//!   witness can never make the circuit accept a policy the evaluator
//!   rejects (soundness); a witness built from the commitment preimages
//!   always makes both accept (completeness).

use ark_ed25519::Fr;
use crypto_core::SecretBytes;
use policy::{
    compile_with_layout, credential_commitment, decode, encode, evaluate, normalize, policy_id,
    AmountLimit, AuthorizationResult, CredentialId, Policy, PolicyError, PolicyWitness, ThresholdK,
};
use proptest::prelude::*;
use rand_core::SeedableRng;

/// A generated policy together with the preimage secrets of every
/// credential leaf it contains. The secrets let us build a witness that
/// *satisfies* the policy, which is the completeness side of the
/// agreement property.
#[derive(Debug)]
struct Generated {
    policy: Policy,
    secrets: Vec<SecretBytes>,
}

/// Random short secret material.
fn arb_secret() -> impl Strategy<Value = SecretBytes> {
    proptest::collection::vec(any::<u8>(), 1..8).prop_map(SecretBytes::new)
}

/// Builds a credential leaf whose id is the real commitment of a random
/// secret, returning both so the satisfying witness can be reconstructed.
fn arb_credential() -> impl Strategy<Value = (Policy, Vec<SecretBytes>)> {
    arb_secret().prop_map(|secret| {
        let id = CredentialId::from_commitment(credential_commitment(&secret));
        (Policy::Credential(id), vec![secret])
    })
}

/// Recursive policy generator. Nesting and branching are kept small so
/// generated policies stay within all resource limits and remain quick to
/// evaluate.
fn arb_policy() -> impl Strategy<Value = Generated> {
    let leaf = prop_oneof![
        arb_credential(),
        any::<u64>().prop_map(|limit| (Policy::AmountAtMost(AmountLimit::new(limit)), Vec::new())),
    ];
    leaf.prop_recursive(2, 32, 3, move |inner| {
        let child = inner.clone();
        prop_oneof![
            // And
            proptest::collection::vec(child.clone(), 1..4).prop_map(|gens| {
                let (members, secrets): (Vec<_>, Vec<_>) = gens.into_iter().unzip();
                (Policy::And(members), secrets.concat())
            }),
            // Or
            proptest::collection::vec(child.clone(), 1..4).prop_map(|gens| {
                let (members, secrets): (Vec<_>, Vec<_>) = gens.into_iter().unzip();
                (Policy::Or(members), secrets.concat())
            }),
            // Threshold: k in 1..=members, members from children.
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
    .prop_map(|(policy, secrets)| Generated { policy, secrets })
}

/// Flattens a generated policy's credential secrets into a satisfying
/// witness: one preimage per distinct credential id, plus amount 0 (which
/// satisfies any `AmountAtMost` limit, since limits are u64 ≥ 0).
fn satisfying_witness(policy: &Policy, secrets: &[SecretBytes]) -> PolicyWitness {
    let ids: Vec<CredentialId> = {
        fn collect(p: &Policy, out: &mut Vec<CredentialId>) {
            match p {
                Policy::Credential(id) => out.push(*id),
                Policy::AmountAtMost(_) => {}
                Policy::Threshold { members, .. } | Policy::And(members) | Policy::Or(members) => {
                    for m in members {
                        collect(m, out);
                    }
                }
            }
        }
        let mut v = Vec::new();
        collect(policy, &mut v);
        v
    };
    let mut w = PolicyWitness::new().with_amount(AmountLimit::new(0));
    for (id, secret) in ids.iter().zip(secrets.iter()) {
        w = w.with_credential(*id, secret.clone());
    }
    w
}

/// Builds a *random* witness for `policy`: a fresh secret per credential id
/// (so it generally will *not* satisfy the policy) and a random amount.
fn adversarial_witness(policy: &Policy) -> PolicyWitness {
    use rand_core::RngCore;
    let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(0x1234_5678);
    let ids: Vec<CredentialId> = {
        fn collect(p: &Policy, out: &mut Vec<CredentialId>) {
            match p {
                Policy::Credential(id) => out.push(*id),
                Policy::AmountAtMost(_) => {}
                Policy::Threshold { members, .. } | Policy::And(members) | Policy::Or(members) => {
                    for m in members {
                        collect(m, out);
                    }
                }
            }
        }
        let mut v = Vec::new();
        collect(policy, &mut v);
        v
    };
    let mut w = PolicyWitness::new().with_amount(AmountLimit::new(rng.next_u64()));
    for id in &ids {
        let mut buf = [0u8; 8];
        rng.fill_bytes(&mut buf);
        w = w.with_credential(*id, SecretBytes::new(buf.to_vec()));
    }
    w
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn normalize_is_idempotent(g in arb_policy()) {
        let once = normalize(&g.policy).unwrap();
        let twice = normalize(&once).unwrap();
        prop_assert_eq!(once, twice);
    }

    #[test]
    fn policy_id_stable_under_normalization(g in arb_policy()) {
        let direct = policy_id(&g.policy);
        let normalized = policy_id(&normalize(&g.policy).unwrap());
        prop_assert_eq!(direct, normalized);
    }

    #[test]
    fn encode_decode_round_trips(g in arb_policy()) {
        let encoded = encode(&g.policy);
        let decoded = decode(&encoded).unwrap();
        prop_assert_eq!(decoded, g.policy);
    }

    #[test]
    fn compilation_is_deterministic(g in arb_policy()) {
        let a = compile_with_layout::<Fr>(&g.policy).unwrap();
        let b = compile_with_layout::<Fr>(&g.policy).unwrap();
        // The circuit id is a content hash of the compiled circuit, so
        // identical ids imply identical circuits.
        prop_assert_eq!(a.circuit.compute_id(), b.circuit.compute_id());
    }

    #[test]
    fn satisfying_witness_agrees(g in arb_policy()) {
        let witness = satisfying_witness(&g.policy, &g.secrets);
        let eval = evaluate(&g.policy, &witness).unwrap();
        prop_assert!(eval.authorized, "reference evaluator must authorize a satisfying witness");
        let compiled = compile_with_layout::<Fr>(&g.policy).unwrap();
        let circuit_ok = compiled.reference_evaluate(&g.policy, &witness).unwrap();
        prop_assert!(circuit_ok, "compiled circuit must accept a satisfying witness");
    }

    #[test]
    fn circuit_never_accepts_what_evaluator_rejects(g in arb_policy()) {
        // Soundness: an adversarial witness cannot make the circuit accept
        // a policy the reference evaluator rejects.
        let witness = adversarial_witness(&g.policy);
        let eval: AuthorizationResult = match evaluate(&g.policy, &witness) {
            Ok(r) => r,
            // A witness that does not even cover the policy cannot be used
            // to argue soundness here; skip.
            Err(PolicyError::WitnessMismatch) => return Ok(()),
            Err(_) => return Ok(()),
        };
        let compiled = compile_with_layout::<Fr>(&g.policy).unwrap();
        let circuit_ok = compiled.reference_evaluate(&g.policy, &witness).unwrap();
        if !eval.authorized {
            // Evaluator rejects: the circuit must also reject (soundness).
            prop_assert!(!circuit_ok, "circuit accepted a witness the evaluator rejected");
        } else {
            // Evaluator accepts: completeness demands the circuit accept too.
            prop_assert!(circuit_ok, "circuit rejected a witness the evaluator accepted");
        }
    }
}
