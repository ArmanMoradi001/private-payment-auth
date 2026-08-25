//! Plaintext reference for the circuit range check.
//!
//! Mirrors `policy::range_check` semantics over plain `u64`s so tests
//! (including property tests) can compare the reference outcome with
//! the compiled circuit's published outputs. The two must agree on
//! every input: the circuit accepts exactly the pairs the reference
//! accepts.

use ark_ed25519::Fr;
use circuit::{evaluate_reference, CircuitBuilder};
use policy::range_check::{prove_bounded_difference, RangeCheckBits, AMOUNT_BIT_LEN};

/// Why a plaintext range check can fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeCheckError {
    /// The value exceeds the limit.
    ValueAboveLimit,
}

impl core::fmt::Display for RangeCheckError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ValueAboveLimit => f.write_str("amount exceeds limit"),
        }
    }
}

impl std::error::Error for RangeCheckError {}

/// Little-endian binary decomposition of a `u64`.
#[must_use]
pub fn decompose(value: u64) -> [bool; AMOUNT_BIT_LEN] {
    let mut bits = [false; AMOUNT_BIT_LEN];
    for (index, slot) in bits.iter_mut().enumerate() {
        *slot = (value >> index) & 1 == 1;
    }
    bits
}

/// The plaintext range check mirrored by the circuit gadget.
///
/// Checks `value ≤ limit`; the structural invariants `value < 2^64`
/// and `limit − value < 2^64` hold by construction in the `u64` domain
/// and are exactly what the dual decomposition proves in-circuit.
///
/// # Errors
///
/// - [`RangeCheckError::ValueAboveLimit`] when `value > limit`.
pub fn reference_range_check(value: u64, limit: u64) -> Result<(), RangeCheckError> {
    if value > limit {
        return Err(RangeCheckError::ValueAboveLimit);
    }
    Ok(())
}

/// Evaluates the standalone range-check circuit for `(value, limit)`
/// with an honest digit witness, returning the four published outputs
/// (`value booleanity`, `value reconstruction`, `difference
/// booleanity`, `difference reconstruction`).
///
/// All four are zero iff the pair satisfies `0 ≤ value ≤ limit`; this
/// is the function property tests compare against
/// [`reference_range_check`].
#[must_use]
pub fn circuit_range_check_outputs(value: u64, limit: u64) -> [Fr; 4] {
    let mut builder = CircuitBuilder::<Fr>::new();
    let amount = builder.secret_input();
    let limit_node = builder.constant(Fr::from(limit));
    let bits = RangeCheckBits::declare(&mut builder);
    let outputs = prove_bounded_difference::<Fr>(&mut builder, amount, limit_node, &bits)
        .expect("gadget wires validly");
    let circuit = builder.build().expect("range-check circuit validates");

    let mut secrets = Vec::with_capacity(1 + 2 * AMOUNT_BIT_LEN);
    secrets.push(Fr::from(value));
    for bit in decompose(value) {
        secrets.push(Fr::from(u64::from(bit)));
    }
    for bit in decompose(limit.wrapping_sub(value)) {
        secrets.push(Fr::from(u64::from(bit)));
    }

    let values = evaluate_reference(&circuit, &secrets, &[]).expect("evaluates");
    outputs.map(|id| values[id.as_usize()])
}
