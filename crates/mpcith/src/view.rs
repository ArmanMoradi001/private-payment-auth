//! Per-party execution views.
//!
//! A [`PartyView`] is everything one virtual party did during one
//! repetition: the shares it holds of the secret inputs, the local
//! result share it computed for every gate that touched its state, its
//! shares of the Beaver triples it consumed, and the masked values
//! (`d`, `e`) that were opened to the group. Views are committed
//! before the challenge; only two of three are ever opened.

use core::fmt;

use circuit::NodeId;

use crate::types::{FieldElement, PartyId, RepetitionId};

/// One party's share `(a_i, b_i, c_i)` of a Beaver triple with
/// `c = a · b`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TripleShare {
    /// Share of the first multiplicand mask.
    pub a: FieldElement,
    /// Share of the second multiplicand mask.
    pub b: FieldElement,
    /// Share of the precomputed product `a · b`.
    pub c: FieldElement,
}

/// A local operation one party performed for one gate.
///
/// The verifier replays the circuit and checks each recorded operation
/// in order against its own recomputation; the `output` node id makes
/// misalignment detectable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LocalOperation {
    /// Shared addition (possibly adding a plaintext public value):
    /// `share = lhs + rhs` where at most one side is this party's
    /// secret share.
    Add {
        /// Node whose share this operation produces.
        output: NodeId,
        /// The party's resulting share.
        share: FieldElement,
    },
    /// Local multiplication by a public scalar:
    /// `share = operand_share · public`.
    MulPublic {
        /// Node whose share this operation produces.
        output: NodeId,
        /// The public scalar.
        public: FieldElement,
        /// The party's resulting share.
        share: FieldElement,
    },
    /// Beaver multiplication of two shared values. The masks `d`, `e`
    /// were opened publicly; the share is
    /// `c_i + d·b_i + e·a_i + d·e`.
    BeaverMul {
        /// Node whose share this operation produces.
        output: NodeId,
        /// Index into the view's `triple_shares` for the triple used.
        triple_index: usize,
        /// Opened mask `d = x - a` (identical across parties).
        d: FieldElement,
        /// Opened mask `e = y - b` (identical across parties).
        e: FieldElement,
        /// The party's resulting share.
        share: FieldElement,
    },
}

/// Everything one virtual party did during one repetition.
#[derive(Clone, PartialEq, Eq)]
pub struct PartyView {
    /// Repetition this view belongs to (guards cross-repetition mixing).
    pub repetition_id: RepetitionId,
    /// Which of the three parties produced this view.
    pub party_id: PartyId,
    /// This party's additive shares of the circuit's secret inputs, in
    /// circuit input order.
    pub input_shares: Vec<FieldElement>,
    /// Local operations in circuit evaluation order.
    pub local_operations: Vec<LocalOperation>,
    /// This party's shares of the Beaver triples used, in usage order.
    pub triple_shares: Vec<TripleShare>,
    /// Publicly opened mask values, in opening order: `d, e` per
    /// Beaver multiplication.
    pub opened_values: Vec<FieldElement>,
}

impl fmt::Debug for PartyView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only structural counts are shown; share values never appear.
        f.debug_struct("PartyView")
            .field("repetition_id", &self.repetition_id)
            .field("party_id", &self.party_id)
            .field(
                "input_shares",
                &format!("[{} REDACTED]", self.input_shares.len()),
            )
            .field("local_operations", &self.local_operations.len())
            .field(
                "triple_shares",
                &format!("[{} REDACTED]", self.triple_shares.len()),
            )
            .field("opened_values", &self.opened_values.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{One, Zero};

    fn sample_view() -> PartyView {
        let mut view = PartyView {
            repetition_id: RepetitionId::new(4),
            party_id: PartyId::new(1).expect("valid"),
            input_shares: vec![FieldElement::from(11u64), FieldElement::from(12u64)],
            local_operations: vec![LocalOperation::Add {
                output: NodeId::new(2),
                share: FieldElement::one(),
            }],
            triple_shares: vec![TripleShare {
                a: FieldElement::from(3u64),
                b: FieldElement::from(5u64),
                c: FieldElement::from(15u64),
            }],
            opened_values: vec![FieldElement::zero(), FieldElement::one()],
        };
        view.party_id = PartyId::new(1).expect("valid");
        view
    }

    #[test]
    fn debug_redacts_share_values() {
        let rendered = format!("{:?}", sample_view());
        assert!(!rendered.contains("11"));
        assert!(!rendered.contains("12"));
        assert!(rendered.contains("REDACTED"));
        assert!(rendered.contains("party_id: PartyId(1)"));
        assert!(rendered.contains("local_operations: 1"));
    }

    #[test]
    fn operations_carry_node_ids_and_shares() {
        let view = sample_view();
        match &view.local_operations[0] {
            LocalOperation::Add { output, .. } => assert_eq!(*output, NodeId::new(2)),
            _ => panic!("expected Add"),
        }
        assert_eq!(view.triple_shares[0].c, FieldElement::from(15u64));
    }
}
