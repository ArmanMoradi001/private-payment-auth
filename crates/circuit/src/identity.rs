//! Hash-based semantic identity of circuits.
//!
//! A circuit's id is `SHA-256("private-payment-auth/circuit/v1" ||
//! canonical_encoding)`, computed with the domain-separated
//! [`crypto_core::Sha256Hash::hash_domain`]. Because the encoding is
//! injective, any difference in constants, operations, input
//! declarations, output set, or node ordering yields a different id.

use crypto_core::hash::Sha256Hash;
use crypto_core::HashFunction;

use crate::circuit::Circuit;
use crate::encoding;
use crate::types::CircuitId;

/// Domain separator binding circuit ids to this application and
/// encoding version.
pub const CIRCUIT_ID_DOMAIN: &[u8] = b"private-payment-auth/circuit/v1";

/// Computes the domain-separated semantic id of a circuit.
pub fn compute_id<F: ark_ff::PrimeField>(circuit: &Circuit<F>) -> CircuitId {
    let bytes = encoding::serialize(circuit);
    CircuitId::from_digest(Sha256Hash::hash_domain(CIRCUIT_ID_DOMAIN, &bytes).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::CircuitBuilder;
    use ark_ed25519::Fr;
    use ark_ff::Zero;

    fn build(mut f: impl FnMut(&mut CircuitBuilder<Fr>)) -> Circuit<Fr> {
        let mut b = CircuitBuilder::new();
        f(&mut b);
        b.build().expect("valid")
    }

    #[test]
    fn identical_constructions_have_identical_ids() {
        let make = || {
            build(|b| {
                let x = b.secret_input();
                let c = b.constant(Fr::from(2u64));
                let m = b.mul(x, c).expect("valid");
                b.output(m).expect("valid");
            })
        };
        assert_eq!(make().compute_id(), make().compute_id());
    }

    #[test]
    fn changed_constant_changes_id() {
        let a = build(|b| {
            let x = b.secret_input();
            let c = b.constant(Fr::from(2u64));
            let m = b.mul(x, c).expect("valid");
            b.output(m).expect("valid");
        });
        let b_circ = build(|b| {
            let x = b.secret_input();
            let c = b.constant(Fr::from(3u64));
            let m = b.mul(x, c).expect("valid");
            b.output(m).expect("valid");
        });
        assert_ne!(a.compute_id(), b_circ.compute_id());
    }

    #[test]
    fn changed_operation_changes_id() {
        let a = build(|b| {
            let x = b.secret_input();
            let y = b.public_input();
            let s = b.add(x, y).expect("valid");
            b.output(s).expect("valid");
        });
        let b_circ = build(|b| {
            let x = b.secret_input();
            let y = b.public_input();
            let m = b.mul(x, y).expect("valid");
            b.output(m).expect("valid");
        });
        assert_ne!(a.compute_id(), b_circ.compute_id());
    }

    #[test]
    fn reordered_nodes_change_id() {
        // Same gate, different construction order (different node ids).
        let a = build(|b| {
            let x = b.secret_input();
            let p = b.public_input();
            let s = b.add(x, p).expect("valid");
            b.output(s).expect("valid");
        });
        let b_circ = build(|b| {
            let p = b.public_input();
            let x = b.secret_input();
            let s = b.add(p, x).expect("valid");
            b.output(s).expect("valid");
        });
        assert_ne!(a.compute_id(), b_circ.compute_id());
    }

    #[test]
    fn extra_output_changes_id() {
        let base = |outputs: usize| {
            build(move |b| {
                let x = b.secret_input();
                let z = b.constant(Fr::zero());
                b.output(x).expect("valid");
                if outputs > 1 {
                    b.output(z).expect("valid");
                }
            })
        };
        assert_ne!(base(1).compute_id(), base(2).compute_id());
    }

    #[test]
    fn ids_differ_across_domains() {
        // The domain separator must bind the id; hashing the same
        // encoding under another domain gives a different digest.
        let circuit = build(|b| {
            let x = b.secret_input();
            b.output(x).expect("valid");
        });
        let bytes = crate::encoding::serialize(&circuit);
        assert_ne!(
            Sha256Hash::hash_domain(CIRCUIT_ID_DOMAIN, &bytes),
            Sha256Hash::hash_domain(b"other-domain", &bytes)
        );
        assert_eq!(
            compute_id(&circuit),
            compute_id(&crate::encoding::deserialize::<Fr>(&bytes).expect("valid"))
        );
    }
}
