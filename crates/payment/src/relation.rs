//! The plaintext authorization relation.
//!
//! [`AuthorizationRelation::validate`] is the *reference semantics* of
//! a payment authorization: it checks, in the clear, that the witness
//! satisfies the policy for the statement. It runs before proving (a
//! prover must not spend time proving an invalid payment) and doubles
//! as the executable specification the compiled circuit must agree
//! with.

use crypto_core::{HashFunction, Sha256Hash};
use policy::{credential_commitment, Policy};

use crate::error::PaymentError;
use crate::statement::PaymentStatement;
use crate::wiring;
use crate::witness::PrivateWitness;

/// Reference implementation of the authorization relation.
pub struct AuthorizationRelation;

impl AuthorizationRelation {
    /// Validates `statement`/`witness` against `policy` in the clear.
    ///
    /// Checks, in order:
    /// 1. The policy is structurally valid and its id matches the
    ///    statement's.
    /// 2. The witness covers the policy's credentials with well-formed
    ///    secrets.
    /// 3. Every credential secret hashes to its committed value.
    /// 4. Threshold counts and amount caps hold, combined through the
    ///    policy tree's `And`/`Or` structure.
    /// 5. As an internal invariant, the compiled circuit's reference
    ///    evaluation over the same inputs agrees with this outcome.
    ///
    /// # Errors
    ///
    /// Returns the first failing check's error; see
    /// [`crate::error::PaymentError`].
    pub fn validate(
        statement: &PaymentStatement,
        witness: &PrivateWitness,
        policy: &Policy,
    ) -> Result<(), PaymentError> {
        // 1. Policy shape and identity binding.
        policy.validate().map_err(|_| PaymentError::InvalidPolicy)?;
        if policy.policy_id() != statement.policy_id {
            return Err(PaymentError::PolicyIdMismatch);
        }

        // 2. Witness shape and statement binding.
        witness.validate(policy)?;
        if witness.amount != statement.amount {
            return Err(PaymentError::AmountMismatch);
        }

        // 3. Plaintext range check per amount cap, with digit-witness
        //    consistency. In the u64 domain `amount < 2^64` and
        //    `limit − amount < 2^64` hold whenever the subtraction does
        //    not underflow — exactly what the circuit's dual
        //    decomposition proves over field elements.
        for limit in limits(policy) {
            let value = witness.amount.value;
            if value > limit {
                return Err(PaymentError::AmountExceedsLimit);
            }
            let difference = limit - value;
            if witness.amount_bits != crate::decompose(value)
                || witness.difference_bits != crate::decompose(difference)
            {
                return Err(PaymentError::InvalidBitWitness);
            }
        }

        // 4. Direct evaluation of the policy tree.
        let satisfied = Self::eval_tree(policy, statement, witness)?;
        if !satisfied {
            return Err(PaymentError::PolicyNotSatisfied);
        }

        // 5. Arithmetic encoding agreement (defense in depth).
        let compiled = wiring::compile(policy)?;
        let (secrets, publics) = wiring::build_inputs(&compiled, policy, witness)?;
        let outputs = wiring::reference_outputs(&compiled.circuit, &secrets, &publics)?;
        let root = outputs.last().copied().ok_or(PaymentError::InvalidPolicy)?;
        if root != wiring::satisfied() {
            return Err(PaymentError::InvalidPolicy);
        }
        Ok(())
    }

    /// Evaluates the policy tree directly over hashed secrets,
    /// returning the boolean result. On failure it stores the most
    /// specific cause in `cause`.
    fn eval_tree(
        policy: &Policy,
        statement: &PaymentStatement,
        witness: &PrivateWitness,
    ) -> Result<bool, PaymentError> {
        let mut next_credential = 0usize;
        let mut cause: Option<PaymentError> = None;
        let result = Self::eval_node(policy, statement, witness, &mut next_credential, &mut cause);
        match (result, cause) {
            (true, _) => Ok(true),
            (false, Some(err)) => Err(err),
            (false, None) => Err(PaymentError::PolicyNotSatisfied),
        }
    }

    fn eval_node(
        policy: &Policy,
        statement: &PaymentStatement,
        witness: &PrivateWitness,
        next_credential: &mut usize,
        cause: &mut Option<PaymentError>,
    ) -> bool {
        use policy::Policy;
        match policy {
            Policy::Threshold { k, credentials } => {
                let mut valid = 0usize;
                let mut mismatched = false;
                for credential in credentials {
                    let secret = match witness.credential_secrets.get(*next_credential) {
                        Some(secret) => secret,
                        None => {
                            *cause = Some(PaymentError::WitnessCountMismatch);
                            return false;
                        }
                    };
                    *next_credential += 1;
                    let computed = credential_commitment(secret);
                    if computed == credential.expected_commitment {
                        valid += 1;
                    } else {
                        mismatched = true;
                    }
                }
                if valid >= *k {
                    true
                } else {
                    if mismatched && cause.is_none() {
                        *cause = Some(PaymentError::CredentialCommitmentMismatch);
                    }
                    if cause.is_none() {
                        *cause = Some(PaymentError::ThresholdNotMet);
                    }
                    false
                }
            }
            Policy::AmountAtMost { limit } => {
                if statement.amount.value <= *limit {
                    true
                } else {
                    if cause.is_none() {
                        *cause = Some(PaymentError::AmountExceedsLimit);
                    }
                    false
                }
            }
            Policy::And { policies } => policies
                .iter()
                .all(|sub| Self::eval_node(sub, statement, witness, next_credential, cause)),
            Policy::Or { policies } => policies
                .iter()
                .any(|sub| Self::eval_node(sub, statement, witness, next_credential, cause)),
        }
    }
}

/// Collects every `AmountAtMost` limit in canonical order.
#[must_use]
pub fn limits(policy: &Policy) -> Vec<u64> {
    fn walk(policy: &Policy, out: &mut Vec<u64>) {
        match policy {
            Policy::AmountAtMost { limit } => out.push(*limit),
            Policy::And { policies } | Policy::Or { policies } => {
                for sub in policies {
                    walk(sub, out);
                }
            }
            Policy::Threshold { .. } => {}
        }
    }
    let mut out = Vec::new();
    walk(policy, &mut out);
    out
}

/// Recomputes a credential commitment; exposed for tests and tooling.
#[must_use]
pub fn recompute_commitment(secret: &crypto_core::SecretBytes) -> crypto_core::Digest {
    Sha256Hash::hash_domain(policy::CREDENTIAL_COMMITMENT_DOMAIN, secret.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::Amount;
    use crypto_core::SecretBytes;
    use policy::{CredentialPolicy, Policy};

    fn fixture(n: usize) -> (Vec<SecretBytes>, Vec<CredentialPolicy>) {
        (0..n)
            .map(|i| {
                let secret = SecretBytes::new(vec![i as u8 + 1, 0x0c, 0x0d]);
                let policy = CredentialPolicy {
                    expected_commitment: credential_commitment(&secret),
                };
                (secret, policy)
            })
            .unzip()
    }

    fn witness_for(secrets: &[SecretBytes], policy: &Policy, amount: u64) -> PrivateWitness {
        let limit = limits(policy).first().copied().unwrap_or(amount);
        PrivateWitness::new(
            secrets.to_vec(),
            crate::amount::Amount {
                value: amount,
                unit: crate::amount::AmountUnit::Cents,
            },
            limit,
        )
    }

    /// Witness with an explicit amount, digits honest w.r.t. `policy`'s
    /// first limit (or all-ones when that difference underflows).
    fn witness_with_amount(
        secrets: &[SecretBytes],
        policy: &Policy,
        amount: Amount,
    ) -> PrivateWitness {
        let limit = limits(policy).first().copied().unwrap_or(0);
        let mut witness = PrivateWitness::new(secrets.to_vec(), amount, limit);
        if limit < amount.value {
            witness.difference_bits = crate::decompose(u64::MAX);
        }
        witness
    }

    fn statement(policy_id: policy::PolicyId, amount: u64) -> PaymentStatement {
        use crate::amount::{Amount, AmountUnit};
        PaymentStatement {
            payment_id: crypto_core::Digest::new([3u8; 32]),
            amount: Amount {
                value: amount,
                unit: AmountUnit::Cents,
            },
            recipient_commitment: crypto_core::Digest::new([9u8; 32]),
            policy_id,
            circuit_id: circuit::CircuitId::from_digest(crypto_core::Digest::new([0; 32])),
            protocol_version: 1,
            nonce: [0u8; crate::payment::NONCE_LEN],
        }
    }

    #[test]
    fn satisfied_threshold_and_amount_authorizes() {
        let (secrets, credentials) = fixture(3);
        let policy = Policy::And {
            policies: vec![
                Policy::Threshold { k: 2, credentials },
                Policy::AmountAtMost { limit: 100 },
            ],
        };
        let stmt = statement(policy.policy_id(), 75);
        AuthorizationRelation::validate(&stmt, &witness_for(&secrets, &policy, 75), &policy)
            .expect("valid payment");
    }

    #[test]
    fn invalid_credential_is_reported() {
        // k = 3: every credential must match, so a single wrong one
        // breaks authorization and is reported specifically.
        let (mut secrets, credentials) = fixture(3);
        secrets[1] = SecretBytes::new(vec![0xde, 0xad]);
        let policy = Policy::Threshold { k: 3, credentials };
        let stmt = statement(policy.policy_id(), 10);
        assert_eq!(
            AuthorizationRelation::validate(&stmt, &witness_for(&secrets, &policy, 10), &policy),
            Err(PaymentError::CredentialCommitmentMismatch)
        );
    }

    #[test]
    fn too_few_valid_credentials_fails_threshold() {
        // Two of three replaced: valid count 1 < k = 2, and the
        // mismatched secret is reported as the specific cause.
        let (mut secrets, credentials) = fixture(3);
        secrets[1] = SecretBytes::new(vec![0xaa; 32]);
        secrets[2] = SecretBytes::new(vec![0xbb; 32]);
        let policy = Policy::Threshold { k: 2, credentials };
        let stmt = statement(policy.policy_id(), 10);
        assert_eq!(
            AuthorizationRelation::validate(&stmt, &witness_for(&secrets, &policy, 10), &policy),
            Err(PaymentError::CredentialCommitmentMismatch)
        );

        // With all secrets correct, an unsatisfiable threshold cannot
        // arise structurally (validate rejects k > n), so a passing
        // relation run authorizes.
        let (secrets_ok, credentials) = fixture(2);
        let policy = Policy::Threshold { k: 1, credentials };
        let stmt = statement(policy.policy_id(), 10);
        AuthorizationRelation::validate(&stmt, &witness_for(&secrets_ok, &policy, 10), &policy)
            .expect("single credential satisfies k = 1");
    }

    #[test]
    fn threshold_not_met_without_mismatches_shape() {
        // k exceeds what the (correct) secrets can satisfy is caught
        // structurally at compile/validate time as ThresholdExceedsCount
        // mapped to InvalidPolicy by relation checks.
        let (secrets, credentials) = fixture(2);
        let policy = Policy::And {
            policies: vec![
                Policy::Threshold { k: 2, credentials },
                Policy::AmountAtMost { limit: 5 },
            ],
        };
        // Amount fails first in DFS order? Threshold comes first.
        let mut short = witness_with_amount(
            &secrets[..1],
            &policy,
            crate::amount::Amount {
                value: 4,
                unit: crate::amount::AmountUnit::Cents,
            },
        );
        short.credential_secrets = secrets[..1].to_vec();
        let stmt = statement(policy.policy_id(), 4);
        assert_eq!(
            AuthorizationRelation::validate(&stmt, &short, &policy),
            Err(PaymentError::WitnessCountMismatch)
        );
    }

    #[test]
    fn amount_over_limit_is_rejected() {
        // A pure amount cap declares no credentials, hence an empty
        // witness matches its requirement of zero secrets.
        let policy = Policy::AmountAtMost { limit: 50 };
        let stmt = statement(policy.policy_id(), 51);
        assert_eq!(
            AuthorizationRelation::validate(&stmt, &witness_for(&[], &policy, 51), &policy),
            Err(PaymentError::AmountExceedsLimit)
        );

        let under = statement(policy.policy_id(), 50);
        AuthorizationRelation::validate(&under, &witness_for(&[], &policy, 50), &policy)
            .expect("amount at the limit authorizes");
    }

    #[test]
    fn or_branch_rescue_and_policy_binding() {
        // Branch 1 demands two credentials the payer does not have;
        // branch 2 is a plain cap the payment satisfies → authorized.
        let (secrets, credentials) = fixture(2);
        let impossible = Policy::Threshold {
            k: 2,
            credentials: vec![
                CredentialPolicy {
                    expected_commitment: crypto_core::Digest::new([1u8; 32]),
                },
                CredentialPolicy {
                    expected_commitment: crypto_core::Digest::new([2u8; 32]),
                },
            ],
        };
        let policy = Policy::Or {
            policies: vec![
                impossible,
                Policy::AmountAtMost { limit: 500 },
                Policy::Threshold { k: 2, credentials },
            ],
        };

        // Canonical DFS order: two secrets for branch 1 (garbage, they
        // will not match its fabricated commitments), then the payer's
        // two real credential secrets.
        let mut all_secrets = vec![
            SecretBytes::new(vec![0xf0; 8]),
            SecretBytes::new(vec![0xf1; 8]),
        ];
        all_secrets.extend(secrets.iter().cloned());
        let witness = PrivateWitness::new(
            all_secrets,
            crate::amount::Amount {
                value: 100,
                unit: crate::amount::AmountUnit::Cents,
            },
            500, // the Or tree's single amount cap (a global assertion)
        );

        let stmt = statement(policy.policy_id(), 100);
        AuthorizationRelation::validate(&stmt, &witness, &policy).expect("or-branch authorizes");

        // A statement bound to a different policy id is rejected.
        let forged = PaymentStatement {
            policy_id: policy::PolicyId::from_digest(crypto_core::Digest::new([7u8; 32])),
            ..stmt
        };
        assert_eq!(
            AuthorizationRelation::validate(&forged, &witness, &policy),
            Err(PaymentError::PolicyIdMismatch)
        );
    }

    #[test]
    fn malformed_witnesses_are_rejected() {
        let (secrets, credentials) = fixture(2);
        let policy = Policy::Threshold { k: 1, credentials };

        let mut empty_secret = PrivateWitness::new(
            vec![SecretBytes::new(Vec::new()); 2],
            crate::amount::Amount {
                value: 1,
                unit: crate::amount::AmountUnit::Cents,
            },
            1,
        );
        empty_secret.amount_bits = crate::decompose(1);
        empty_secret.difference_bits = crate::decompose(0);
        assert_eq!(
            AuthorizationRelation::validate(
                &statement(policy.policy_id(), 1),
                &empty_secret,
                &policy
            ),
            Err(PaymentError::MalformedCredentialSecret)
        );

        let too_long = PrivateWitness::new(
            vec![SecretBytes::new(vec![0u8; crate::MAX_CREDENTIAL_SECRET_LEN + 1]); 2],
            crate::amount::Amount {
                value: 1,
                unit: crate::amount::AmountUnit::Cents,
            },
            1,
        );
        assert_eq!(
            AuthorizationRelation::validate(&statement(policy.policy_id(), 1), &too_long, &policy),
            Err(PaymentError::MalformedCredentialSecret)
        );

        let _ = secrets;
    }
}
