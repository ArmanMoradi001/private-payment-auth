//! Unit and adversarial tests for the policy crate (Phase 11).
//!
//! Covers all five node types, threshold edge cases, empty collections,
//! duplicate handling, normalization, deep nesting, resource-limit
//! rejections, malformed encodings, policy-id stability, and
//! policy/circuit agreement.

use ark_ed25519::Fr;
use crypto_core::SecretBytes;
use policy::{
    credential_commitment, decode, encode, evaluate, normalize, policy_id, validate, AmountLimit,
    AuthorizationResult, CredentialId, Policy, PolicyError, PolicyWitness, ThresholdK,
};

/// Builds a `(CredentialId, secret)` pair from a fresh secret.
fn cred(secret: &[u8]) -> (CredentialId, SecretBytes) {
    let secret = SecretBytes::new(secret.to_vec());
    let id = CredentialId::from_commitment(credential_commitment(&secret));
    (id, secret)
}

fn leaf((id, _): &(CredentialId, SecretBytes)) -> Policy {
    Policy::Credential(*id)
}

#[test]
fn credential_leaf_evaluates() {
    let (id, secret) = cred(b"alice");
    let policy = Policy::Credential(id);
    let witness = PolicyWitness::new().with_credential(id, secret.clone());
    let result = evaluate(&policy, &witness).unwrap();
    assert!(result.authorized);

    // Wrong secret fails.
    let other = SecretBytes::new(b"bob".to_vec());
    let bad = PolicyWitness::new().with_credential(id, other);
    assert!(!evaluate(&policy, &bad).unwrap().authorized);
}

#[test]
fn amount_leaf_evaluates() {
    let policy = Policy::AmountAtMost(AmountLimit::new(100));
    assert!(
        evaluate(
            &policy,
            &PolicyWitness::new().with_amount(AmountLimit::new(50))
        )
        .unwrap()
        .authorized
    );
    assert!(
        !evaluate(
            &policy,
            &PolicyWitness::new().with_amount(AmountLimit::new(101))
        )
        .unwrap()
        .authorized
    );
}

#[test]
fn threshold_variants() {
    let creds: Vec<(CredentialId, SecretBytes)> = (0..3).map(|i| cred(&[i; 4])).collect();
    let members: Vec<Policy> = creds.iter().map(leaf).collect();

    // 1-of-1
    let p = Policy::Threshold {
        k: ThresholdK::new(1),
        members: vec![members[0].clone()],
    };
    let w = PolicyWitness::new().with_credential(creds[0].0, creds[0].1.clone());
    assert!(evaluate(&p, &w).unwrap().authorized);

    // 2-of-3 with all three credentials present and correct -> authorized.
    let p = Policy::Threshold {
        k: ThresholdK::new(2),
        members: members.clone(),
    };
    let w = PolicyWitness::new()
        .with_credential(creds[0].0, creds[0].1.clone())
        .with_credential(creds[1].0, creds[1].1.clone())
        .with_credential(creds[2].0, creds[2].1.clone());
    let r = evaluate(&p, &w).unwrap();
    assert!(r.authorized);

    // Two valid, one present-but-wrong -> count is 2, which meets the
    // 2-of-3 threshold, so authorized.
    let wrong = SecretBytes::new(vec![9u8; 4]);
    let w_bad = w.clone().with_credential(creds[2].0, wrong.clone());
    let r = evaluate(&p, &w_bad).unwrap();
    assert!(r.authorized);

    // Only one valid for 2-of-3 -> fails.
    let w1 = PolicyWitness::new()
        .with_credential(creds[0].0, creds[0].1.clone())
        .with_credential(creds[1].0, wrong.clone())
        .with_credential(creds[2].0, wrong.clone());
    assert!(!evaluate(&p, &w1).unwrap().authorized);

    // n-of-n requires all.
    let p = Policy::Threshold {
        k: ThresholdK::new(3),
        members: members.clone(),
    };
    assert!(evaluate(&p, &w).unwrap().authorized);

    // invalid k = 0 rejected.
    assert_eq!(
        validate(&Policy::Threshold {
            k: ThresholdK::new(0),
            members: members.clone()
        }),
        Err(PolicyError::InvalidThreshold)
    );
    // empty member set rejected.
    assert_eq!(
        validate(&Policy::Threshold {
            k: ThresholdK::new(1),
            members: vec![]
        }),
        Err(PolicyError::EmptyPolicy)
    );
}

#[test]
fn empty_combinators_rejected() {
    assert_eq!(
        validate(&Policy::And(vec![])),
        Err(PolicyError::EmptyPolicy)
    );
    assert_eq!(validate(&Policy::Or(vec![])), Err(PolicyError::EmptyPolicy));
    assert_eq!(
        validate(&Policy::Threshold {
            k: ThresholdK::new(0),
            members: vec![]
        }),
        Err(PolicyError::InvalidThreshold)
    );
}

#[test]
fn duplicate_credentials_in_threshold_rejected() {
    let (id, secret) = cred(b"dup");
    let p = Policy::Threshold {
        k: ThresholdK::new(1),
        members: vec![Policy::Credential(id), Policy::Credential(id)],
    };
    assert_eq!(validate(&p), Err(PolicyError::DuplicateCredential));
    // But the witness can still carry two identical secrets; the policy
    // itself is rejected at validation time.
    let _ = secret;
}

#[test]
fn duplicate_subtrees_in_and_or_normalize() {
    let (id, secret) = cred(b"x");
    let a = Policy::Credential(id);
    let p = Policy::And(vec![a.clone(), a.clone()]);
    let n = normalize(&p).unwrap();
    // And([A, A]) normalizes to A.
    assert_eq!(n, a);
    let w = PolicyWitness::new().with_credential(id, secret);
    assert!(evaluate(&n, &w).unwrap().authorized);
}

#[test]
fn normalization_sorts_children() {
    let c1 = Policy::Credential(cred(b"1").0);
    let c2 = Policy::Credential(cred(b"2").0);
    let a = Policy::And(vec![c2.clone(), c1.clone()]);
    let b = Policy::And(vec![c1.clone(), c2.clone()]);
    assert_eq!(normalize(&a).unwrap(), normalize(&b).unwrap());
}

#[test]
fn deeply_nested_within_limit() {
    let mut policy = Policy::AmountAtMost(AmountLimit::new(1));
    for _ in 0..policy::MAX_POLICY_DEPTH {
        policy = Policy::And(vec![policy]);
    }
    assert!(validate(&policy).is_ok());
}

#[test]
fn depth_plus_one_rejected() {
    let mut policy = Policy::AmountAtMost(AmountLimit::new(1));
    for _ in 0..(policy::MAX_POLICY_DEPTH + 1) {
        policy = Policy::And(vec![policy]);
    }
    assert_eq!(validate(&policy), Err(PolicyError::MaxDepthExceeded));
}

#[test]
fn max_nodes_plus_one_rejected() {
    // Build a balanced binary `And` tree with `leaves` leaves and
    // `leaves - 1` internal nodes (each `And` has two children, so the
    // per-combinator child limit is never hit). A tree with 6001 leaves
    // has 12001 nodes, exceeding MAX_POLICY_NODES (10000).
    let leaves = policy::MAX_POLICY_NODES / 2 + 1;
    let mut stack: Vec<Policy> = (0..leaves)
        .map(|i| Policy::AmountAtMost(AmountLimit::new(i as u64)))
        .collect();
    while stack.len() > 1 {
        let a = stack.remove(0);
        let b = stack.remove(0);
        stack.push(Policy::And(vec![a, b]));
    }
    let p = stack.into_iter().next().unwrap();
    assert!(matches!(validate(&p), Err(PolicyError::MaxNodesExceeded)));
}

#[test]
fn malformed_encodings_rejected() {
    // Truncated.
    let good = encode(&Policy::AmountAtMost(AmountLimit::new(5)));
    assert!(decode(&good).is_ok());
    assert_eq!(
        decode(&good[..good.len() - 1]),
        Err(PolicyError::MalformedEncoding)
    );
    // Trailing bytes.
    let mut trailing = good.clone();
    trailing.push(0);
    assert_eq!(decode(&trailing), Err(PolicyError::TrailingBytes));
    // Unknown version.
    let mut unknown = vec![0xffu8];
    unknown.extend_from_slice(&good[1..]);
    assert_eq!(decode(&unknown), Err(PolicyError::UnknownVersion));
    // Unknown tag.
    assert_eq!(decode(&[1u8, 99u8]), Err(PolicyError::MalformedEncoding));
}

#[test]
fn mutated_policy_id_fails() {
    let (id, _secret) = cred(b"m");
    let policy = Policy::And(vec![
        Policy::Credential(id),
        Policy::AmountAtMost(AmountLimit::new(10)),
    ]);
    let pid = policy_id(&policy).unwrap();
    // Tweak the encoding and re-decode: ids must differ.
    let mut enc = encode(&policy);
    // Flip a bit in the amount limit field.
    if let Some(last) = enc.last_mut() {
        *last ^= 0x01;
    }
    let mutated = decode(&enc).unwrap();
    assert_ne!(policy_id(&mutated).unwrap(), pid);
}

#[test]
fn policy_id_stable_under_normalization() {
    let c1 = Policy::Credential(cred(b"a").0);
    let c2 = Policy::Credential(cred(b"b").0);
    let raw = Policy::Or(vec![
        Policy::And(vec![c1.clone(), c2.clone()]),
        Policy::AmountAtMost(AmountLimit::new(7)),
    ]);
    assert_eq!(
        policy_id(&raw).unwrap(),
        policy_id(&normalize(&raw).unwrap()).unwrap()
    );
}

#[test]
fn compile_and_evaluate_agree() {
    let creds: Vec<(CredentialId, SecretBytes)> = (0..3).map(|i| cred(&[i; 4])).collect();
    let policy = Policy::And(vec![
        Policy::Threshold {
            k: ThresholdK::new(2),
            members: creds.iter().map(leaf).collect(),
        },
        Policy::AmountAtMost(AmountLimit::new(100)),
    ]);

    let mut witness = PolicyWitness::new().with_amount(AmountLimit::new(50));
    for (id, secret) in &creds {
        witness = witness.clone().with_credential(*id, secret.clone());
    }

    let result: AuthorizationResult = evaluate(&policy, &witness).unwrap();
    assert!(result.authorized);

    let compiled = policy::compile_with_layout::<Fr>(&policy).unwrap();
    assert!(compiled.reference_evaluate(&policy, &witness).unwrap());

    // A witness missing a credential is a mismatch (does not even cover
    // the policy), so both the evaluator and the circuit reject it.
    let mut bad = PolicyWitness::new().with_amount(AmountLimit::new(50));
    bad = bad.with_credential(creds[0].0, creds[0].1.clone());
    assert!(evaluate(&policy, &bad).is_err());
    assert!(compiled.reference_evaluate(&policy, &bad).is_err());
}

#[test]
fn policy_circuit_mismatch_detected() {
    // An over-limit amount makes the evaluator disagree with a circuit
    // that would otherwise accept the credential structure.
    let (id, secret) = cred(b"z");
    let policy = Policy::And(vec![
        Policy::Credential(id),
        Policy::AmountAtMost(AmountLimit::new(10)),
    ]);
    let witness = PolicyWitness::new()
        .with_credential(id, secret)
        .with_amount(AmountLimit::new(50));
    assert!(!evaluate(&policy, &witness).unwrap().authorized);
    let compiled = policy::compile_with_layout::<Fr>(&policy).unwrap();
    assert!(!compiled.reference_evaluate(&policy, &witness).unwrap());
}
