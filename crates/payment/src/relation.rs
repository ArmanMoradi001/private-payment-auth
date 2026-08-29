//! The plaintext authorization relation.
//!
//! [`AuthorizationRelation::validate`] is the *reference semantics* of
//! a payment authorization: it checks, in the clear, that the witness
//! satisfies the policy for the statement. It runs before proving (a
//! prover must not waste time proving an invalid payment) and doubles
//! as the executable specification the compiled circuit must agree
//! with. The policy's ground-truth semantics come from
//! [`policy::evaluate`].

use policy::{compile_with_layout, evaluate, Policy};

use crate::error::PaymentError;
use crate::statement::PaymentStatement;
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
    ///    secrets and the amount.
    /// 3. Every amount cap's digit witnesses are consistent with the
    ///    value and its difference to the limit.
    /// 4. The policy tree evaluates to authorized under the witness.
    /// 5. As defense in depth, the compiled circuit's reference
    ///    evaluation over the same inputs agrees with the policy eval.
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
        //    consistency. In the u64 domain the subtraction does not
        //    underflow whenever the cap holds; the circuit proves the
        //    same over field elements.
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

        // 4. Policy evaluation (the reference ground truth).
        let policy_witness = witness.to_policy_witness(policy)?;
        let result = evaluate(policy, &policy_witness).map_err(|_| PaymentError::InvalidPolicy)?;
        if !result.authorized {
            return Err(PaymentError::PolicyNotSatisfied);
        }

        // 5. Arithmetic encoding agreement (defense in depth).
        let compiled = compile_with_layout::<ark_ed25519::Fr>(policy)
            .map_err(|_| PaymentError::InvalidPolicy)?;
        let authorized = compiled
            .reference_evaluate(policy, &policy_witness)
            .map_err(|_| PaymentError::InvalidPolicy)?;
        if !authorized {
            return Err(PaymentError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Collects every `AmountAtMost` limit in canonical (depth-first) order.
#[must_use]
pub fn limits(policy: &Policy) -> Vec<u64> {
    fn walk(policy: &Policy, out: &mut Vec<u64>) {
        match policy {
            Policy::AmountAtMost(limit) => out.push(limit.value()),
            Policy::Credential(_) => {}
            Policy::Threshold { members, .. } => {
                for sub in members {
                    walk(sub, out);
                }
            }
            Policy::And(policies) | Policy::Or(policies) => {
                for sub in policies {
                    walk(sub, out);
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(policy, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amount::Amount;
    use crypto_core::SecretBytes;
    use policy::{credential_commitment, AmountLimit, CredentialId, Policy};

    fn credential_leaf(secret: &SecretBytes) -> (CredentialId, Policy) {
        let id = CredentialId::from_commitment(credential_commitment(secret));
        (id, Policy::Credential(id))
    }

    fn fixture(limit: u64, n: usize) -> (Vec<SecretBytes>, Policy) {
        let mut secrets = Vec::new();
        let mut members = Vec::new();
        for _ in 0..n {
            let secret = SecretBytes::new(vec![secrets.len() as u8 + 1, 0x0c, 0x0d]);
            secrets.push(secret.clone());
            let (_, leaf) = credential_leaf(&secret);
            members.push(leaf);
        }
        let amount = Policy::AmountAtMost(AmountLimit::new(limit));
        let policy = if n == 0 {
            amount
        } else {
            Policy::And(vec![
                Policy::Threshold {
                    k: policy::ThresholdK::new(2),
                    members,
                },
                amount,
            ])
        };
        (secrets, policy)
    }

    fn witness_for(
        secrets: &[SecretBytes],
        _policy: &Policy,
        amount: u64,
        limit: u64,
    ) -> PrivateWitness {
        PrivateWitness::new(
            secrets.to_vec(),
            Amount {
                value: amount,
                unit: crate::amount::AmountUnit::Cents,
            },
            limit,
        )
    }

    fn statement(policy: &Policy, amount: u64) -> PaymentStatement {
        use crate::amount::{Amount, AmountUnit};
        PaymentStatement {
            payment_id: crypto_core::Digest::new([3u8; 32]),
            amount: Amount {
                value: amount,
                unit: AmountUnit::Cents,
            },
            recipient_commitment: crypto_core::Digest::new([9u8; 32]),
            policy_id: policy.policy_id(),
            circuit_id: circuit::CircuitId::from_digest(crypto_core::Digest::new([0; 32])),
            protocol_version: 1,
            nonce: [0u8; crate::payment::NONCE_LEN],
        }
    }

    #[test]
    fn satisfied_threshold_and_amount_authorizes() {
        let (secrets, policy) = fixture(100, 3);
        let stmt = statement(&policy, 75);
        AuthorizationRelation::validate(&stmt, &witness_for(&secrets, &policy, 75, 100), &policy)
            .expect("valid payment");
    }

    #[test]
    fn invalid_credential_is_reported() {
        let (mut secrets, policy) = fixture(100, 3);
        // Corrupt two of the three credentials so fewer than k=2 remain
        // valid; the threshold is no longer satisfied.
        secrets[1] = SecretBytes::new(vec![0xde, 0xad]);
        secrets[2] = SecretBytes::new(vec![0xbe, 0xef]);
        let stmt = statement(&policy, 10);
        assert_eq!(
            AuthorizationRelation::validate(
                &stmt,
                &witness_for(&secrets, &policy, 10, 100),
                &policy
            ),
            Err(PaymentError::PolicyNotSatisfied)
        );
    }

    #[test]
    fn amount_over_limit_is_rejected() {
        let (_secrets, policy) = fixture(50, 0);
        let stmt = statement(&policy, 51);
        assert_eq!(
            AuthorizationRelation::validate(&stmt, &witness_for(&[], &policy, 51, 50), &policy),
            Err(PaymentError::AmountExceedsLimit)
        );

        let under = statement(&policy, 50);
        AuthorizationRelation::validate(&under, &witness_for(&[], &policy, 50, 50), &policy)
            .expect("amount at the limit authorizes");
    }

    #[test]
    fn or_branch_rescue_and_policy_binding() {
        let (secrets, _policy) = fixture(500, 2);
        let c1 = CredentialId::from_commitment(crypto_core::Digest::new([1u8; 32]));
        let c2 = CredentialId::from_commitment(crypto_core::Digest::new([2u8; 32]));
        let impossible = Policy::Threshold {
            k: policy::ThresholdK::new(2),
            members: vec![Policy::Credential(c1), Policy::Credential(c2)],
        };
        let policy = Policy::Or(vec![
            impossible,
            Policy::AmountAtMost(AmountLimit::new(500)),
            Policy::Threshold {
                k: policy::ThresholdK::new(2),
                members: vec![
                    Policy::Credential(CredentialId::from_commitment(credential_commitment(
                        &secrets[0],
                    ))),
                    Policy::Credential(CredentialId::from_commitment(credential_commitment(
                        &secrets[1],
                    ))),
                ],
            },
        ]);
        // The policy references four credentials in depth-first order:
        // `c1`, `c2`, then the two real `secrets`. The witness must carry
        // a secret for every credential leaf (the prover knows them all);
        // `c1`/`c2` simply won't match, forcing the impossible branch to
        // fail while the amount and the 2-of-2 real branches hold.
        let all_secrets = vec![
            SecretBytes::new(vec![0xa1, 0xa2, 0xa3]),
            SecretBytes::new(vec![0xb1, 0xb2, 0xb3]),
            secrets[0].clone(),
            secrets[1].clone(),
        ];
        let stmt = statement(&policy, 100);
        AuthorizationRelation::validate(
            &stmt,
            &witness_for(&all_secrets, &policy, 100, 500),
            &policy,
        )
        .expect("or-branch authorizes");

        let forged = PaymentStatement {
            policy_id: policy::PolicyId::from_digest(crypto_core::Digest::new([7u8; 32])),
            ..stmt
        };
        assert_eq!(
            AuthorizationRelation::validate(
                &forged,
                &witness_for(&all_secrets, &policy, 100, 500),
                &policy
            ),
            Err(PaymentError::PolicyIdMismatch)
        );
    }
}
