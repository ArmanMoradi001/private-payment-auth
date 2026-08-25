//! Sound range-check gadget: dual bit-decomposition in the prime field.
//!
//! Proves `0 ≤ value ≤ limit` for field-representable `value`/`limit`
//! without any wrap-around escape route, using only the existing
//! `{+, ×}` circuit language — no new node types.
//!
//! Construction (for `L < 2^64`, amounts bounded by [`AMOUNT_BIT_LEN`]
//! bits): the witness supplies the 64 binary digits of `value` and the
//! 64 binary digits of `d = L − value` as separate secret inputs. The
//! gadget emits four published outputs, all of which must be **zero**:
//!
//! 1. `Σᵢ bᵢ·(1 − bᵢ)` over the value bits — zero iff every digit is
//!    boolean;
//! 2. `Σᵢ bᵢ·2ⁱ − value` — zero iff the digits reconstruct `value`;
//! 3. the analogues (1) and (2) for the difference bits.
//!
//! Soundness: accepting proofs have `value = Σ bᵢ2ⁱ ≤ 2^64 − 1` and
//! `d = Σ dⱼ2ʲ ≤ 2^64 − 1` *as integers*, hence `value + d = L` holds
//! over the integers without wrap-around, forcing `0 ≤ value ≤ L`.
//! When `value > L`, `L − value (mod p)` exceeds `2^64 − 1`, no 64-bit
//! digit assignment reconstructs it, and output (4) cannot be zero —
//! exactly the exploit class the phase 7 window gadget left open.

use ark_ff::{One, PrimeField};
use circuit::{CircuitBuilder, NodeId};

use crate::error::PolicyError;

/// Number of binary digits proven per value (`value, d < 2^64`).
pub const AMOUNT_BIT_LEN: usize = 64;

/// The declared secret-input nodes for one range check.
#[derive(Clone, Copy, Debug)]
pub struct RangeCheckBits {
    /// Little-endian binary digits of the value (64 nodes).
    pub value_bits: [NodeId; AMOUNT_BIT_LEN],
    /// Little-endian binary digits of `limit − value` (64 nodes).
    pub difference_bits: [NodeId; AMOUNT_BIT_LEN],
}

impl RangeCheckBits {
    /// Declares the 128 witness-digit secret inputs.
    ///
    /// Callers track slot order themselves; the returned arrays are in
    /// declaration order (all value digits, then all difference
    /// digits, each little-endian).
    pub fn declare<F: PrimeField>(builder: &mut CircuitBuilder<F>) -> Self {
        let value_bits: [NodeId; AMOUNT_BIT_LEN] = std::array::from_fn(|_| builder.secret_input());
        let difference_bits: [NodeId; AMOUNT_BIT_LEN] =
            std::array::from_fn(|_| builder.secret_input());
        Self {
            value_bits,
            difference_bits,
        }
    }
}

/// The four published constraint wires of [`prove_bounded_difference`],
/// in output order. All four are zero exactly when the range check
/// holds.
pub type RangeCheckOutputs = [NodeId; 4];

/// Emits the dual bit-decomposition range check for `value ≤ limit`.
///
/// `limit` may be any already-defined node (typically a public input
/// carrying the policy limit, or a constant). `bits` must have been
/// declared against the same builder via [`RangeCheckBits::declare`].
///
/// # Errors
///
/// Returns [`PolicyError::CircuitCompilationFailed`] if a gate
/// references an undefined node (an internal invariant).
pub fn prove_bounded_difference<F: PrimeField>(
    builder: &mut CircuitBuilder<F>,
    value: NodeId,
    limit: NodeId,
    bits: &RangeCheckBits,
) -> Result<RangeCheckOutputs, PolicyError> {
    let value_checks = emit_side::<F>(builder, value, &bits.value_bits)?;
    let difference = subtract(builder, limit, value)?;
    let difference_checks = emit_side::<F>(builder, difference, &bits.difference_bits)?;
    Ok([
        value_checks.0,
        value_checks.1,
        difference_checks.0,
        difference_checks.1,
    ])
}

/// Emits `(bit_booleanity_sum, reconstruction_diff)` for one side.
fn emit_side<F: PrimeField>(
    builder: &mut CircuitBuilder<F>,
    target: NodeId,
    bits: &[NodeId; AMOUNT_BIT_LEN],
) -> Result<(NodeId, NodeId), PolicyError> {
    let mut booleanity = builder.constant(F::zero());
    let mut reconstruction = builder.constant(F::zero());
    for (index, bit) in bits.iter().enumerate() {
        // Booleanity: b · (1 − b).
        let negated = multiply_by(builder, *bit, -<F as One>::one())?;
        let one_minus = add_constant::<F>(builder, negated, <F as One>::one())?;
        let term = mul_gate(builder, *bit, one_minus)?;
        booleanity = add_gate(builder, booleanity, term)?;

        // Reconstruction weight: b · 2^index.
        let weight = 1u64
            .checked_shl(index as u32)
            .ok_or(PolicyError::CircuitCompilationFailed)?;
        let weighted = mul_by_constant(builder, *bit, F::from(weight))?;
        reconstruction = add_gate(builder, reconstruction, weighted)?;
    }
    let reconstruction_diff = subtract(builder, reconstruction, target)?;
    Ok((booleanity, reconstruction_diff))
}

fn add_constant<F: PrimeField>(
    builder: &mut CircuitBuilder<F>,
    node: NodeId,
    constant: F,
) -> Result<NodeId, PolicyError> {
    let c = builder.constant(constant);
    add_gate(builder, node, c)
}

fn multiply_by<F: PrimeField>(
    builder: &mut CircuitBuilder<F>,
    node: NodeId,
    factor: F,
) -> Result<NodeId, PolicyError> {
    mul_by_constant(builder, node, factor)
}

fn mul_by_constant<F: PrimeField>(
    builder: &mut CircuitBuilder<F>,
    node: NodeId,
    factor: F,
) -> Result<NodeId, PolicyError> {
    let c = builder.constant(factor);
    mul_gate(builder, node, c)
}

fn add_gate<F: PrimeField>(
    builder: &mut CircuitBuilder<F>,
    a: NodeId,
    b: NodeId,
) -> Result<NodeId, PolicyError> {
    builder
        .add(a, b)
        .map_err(|_| PolicyError::CircuitCompilationFailed)
}

fn mul_gate<F: PrimeField>(
    builder: &mut CircuitBuilder<F>,
    a: NodeId,
    b: NodeId,
) -> Result<NodeId, PolicyError> {
    builder
        .mul(a, b)
        .map_err(|_| PolicyError::CircuitCompilationFailed)
}

/// `a − b` as `a + (−1)·b`.
fn subtract<F: PrimeField>(
    builder: &mut CircuitBuilder<F>,
    a: NodeId,
    b: NodeId,
) -> Result<NodeId, PolicyError> {
    let negated = mul_by_constant(builder, b, -<F as One>::one())?;
    add_gate(builder, a, negated)
}
