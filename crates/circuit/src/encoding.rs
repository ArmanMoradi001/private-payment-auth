//! Canonical, hand-rolled serialization of circuits.
//!
//! Layout (all integers big-endian, no external serialization
//! framework — the encoding is injective by construction):
//!
//! ```text
//! version            u8   (= 1)
//! num_nodes          u32
//! nodes              [node] * num_nodes
//! num_outputs        u32
//! output node ids    u32 * num_outputs
//! ```
//!
//! Each node encodes as a one-byte variant tag followed by its payload:
//!
//! | tag | variant       | payload                          |
//! |-----|---------------|----------------------------------|
//! | 0   | `SecretInput` | —                                |
//! | 1   | `PublicInput` | —                                |
//! | 2   | `Constant`    | field element, fixed-width BE    |
//! | 3   | `Add`         | operand a (u32), operand b (u32) |
//! | 4   | `Mul`         | operand a (u32), operand b (u32) |
//!
//! Decoding rejects unknown versions, truncated input, trailing bytes,
//! and any circuit that fails structural validation.

use ark_ff::{BigInteger, PrimeField};

use crate::circuit::Circuit;
use crate::error::CircuitError;
use crate::node::Node;
use crate::types::NodeId;
use mpc::PublicValue;

/// Current canonical encoding version.
pub const ENCODING_VERSION: u8 = 1;

/// Node variant tags.
const TAG_SECRET_INPUT: u8 = 0;
const TAG_PUBLIC_INPUT: u8 = 1;
const TAG_CONSTANT: u8 = 2;
const TAG_ADD: u8 = 3;
const TAG_MUL: u8 = 4;

/// Serializes `circuit` into its canonical byte representation.
pub fn serialize<F: PrimeField>(circuit: &Circuit<F>) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ENCODING_VERSION);

    let num_nodes = u32::try_from(circuit.nodes().len()).expect("circuit exceeds u32 node count");
    out.extend_from_slice(&num_nodes.to_be_bytes());

    let width = element_width::<F>();
    for node in circuit.nodes() {
        match node {
            Node::SecretInput => out.push(TAG_SECRET_INPUT),
            Node::PublicInput => out.push(TAG_PUBLIC_INPUT),
            Node::Constant(value) => {
                out.push(TAG_CONSTANT);
                out.extend_from_slice(&element_to_be_bytes::<F>(value.value(), width));
            }
            Node::Add(a, b) => {
                out.push(TAG_ADD);
                out.extend_from_slice(&a.get().to_be_bytes());
                out.extend_from_slice(&b.get().to_be_bytes());
            }
            Node::Mul(a, b) => {
                out.push(TAG_MUL);
                out.extend_from_slice(&a.get().to_be_bytes());
                out.extend_from_slice(&b.get().to_be_bytes());
            }
        }
    }

    let num_outputs =
        u32::try_from(circuit.outputs().len()).expect("circuit exceeds u32 output count");
    out.extend_from_slice(&num_outputs.to_be_bytes());
    for output in circuit.outputs() {
        out.extend_from_slice(&output.get().to_be_bytes());
    }
    out
}

/// Parses a circuit from its canonical byte representation.
///
/// # Errors
///
/// - [`CircuitError::UnsupportedVersion`] for unknown version bytes.
/// - [`CircuitError::UnexpectedEnd`] on truncated input.
/// - [`CircuitError::TrailingBytes`] when bytes remain after decoding.
/// - [`CircuitError::MalformedNode`] for bad tags or constants that do
///   not represent a valid field element.
/// - Any validation error of the decoded structure.
pub fn deserialize<F: PrimeField>(bytes: &[u8]) -> Result<Circuit<F>, CircuitError> {
    let mut cursor = Cursor { bytes, pos: 0 };

    let version = cursor.read_u8()?;
    if version != ENCODING_VERSION {
        return Err(CircuitError::UnsupportedVersion);
    }

    let num_nodes = cursor.read_u32()? as usize;
    let width = element_width::<F>();
    let mut nodes = Vec::with_capacity(num_nodes.min(1024));
    for _ in 0..num_nodes {
        let tag = cursor.read_u8()?;
        let node = match tag {
            TAG_SECRET_INPUT => Node::SecretInput,
            TAG_PUBLIC_INPUT => Node::PublicInput,
            TAG_CONSTANT => {
                let raw = cursor.read_bytes(width)?;
                let value = element_from_be_bytes::<F>(raw).ok_or(CircuitError::MalformedNode)?;
                Node::Constant(PublicValue::new(value))
            }
            TAG_ADD => {
                let a = NodeId::new(cursor.read_u32()?);
                let b = NodeId::new(cursor.read_u32()?);
                Node::Add(a, b)
            }
            TAG_MUL => {
                let a = NodeId::new(cursor.read_u32()?);
                let b = NodeId::new(cursor.read_u32()?);
                Node::Mul(a, b)
            }
            _ => return Err(CircuitError::MalformedNode),
        };
        nodes.push(node);
    }

    let num_outputs = cursor.read_u32()? as usize;
    let mut outputs = Vec::with_capacity(num_outputs.min(1024));
    for _ in 0..num_outputs {
        outputs.push(NodeId::new(cursor.read_u32()?));
    }

    if cursor.pos != cursor.bytes.len() {
        return Err(CircuitError::TrailingBytes);
    }

    // Input counts are derived from the decoded leaves so the circuit's
    // declared counts always match its structure.
    let num_secret_inputs = nodes
        .iter()
        .filter(|n| matches!(n, Node::SecretInput))
        .count();
    let num_public_inputs = nodes
        .iter()
        .filter(|n| matches!(n, Node::PublicInput))
        .count();

    let circuit = Circuit::new(nodes, num_secret_inputs, num_public_inputs, outputs);
    circuit.validate()?;
    Ok(circuit)
}

/// Big-endian byte width of a single field element for `F`.
fn element_width<F: PrimeField>() -> usize {
    F::zero().into_bigint().to_bytes_be().len()
}

/// Canonical fixed-width big-endian bytes of a field element.
fn element_to_be_bytes<F: PrimeField>(value: &F, width: usize) -> Vec<u8> {
    let bytes = value.into_bigint().to_bytes_be();
    debug_assert_eq!(bytes.len(), width);
    bytes
}

/// Parses fixed-width big-endian bytes into a field element.
///
/// Returns `None` when the value is not a canonical field element
/// (i.e. it is at or above the field modulus).
fn element_from_be_bytes<F: PrimeField>(bytes: &[u8]) -> Option<F> {
    let bits: Vec<bool> = bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> (7 - i)) & 1 == 1))
        .collect();
    F::from_bigint(<F::BigInt as BigInteger>::from_bits_be(&bits))
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn read_u8(&mut self) -> Result<u8, CircuitError> {
        let raw = self.read_bytes(1)?;
        Ok(raw[0])
    }

    fn read_u32(&mut self) -> Result<u32, CircuitError> {
        let raw = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&[u8], CircuitError> {
        if self.pos + len > self.bytes.len() {
            return Err(CircuitError::UnexpectedEnd);
        }
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builder::CircuitBuilder;
    use ark_ed25519::Fr;
    use ark_ff::Zero;

    fn sample_circuit() -> Circuit<Fr> {
        let mut b = CircuitBuilder::new();
        let x = b.secret_input();
        let p = b.public_input();
        let c = b.constant(Fr::from(123456789u64));
        let t = b.mul(x, c).expect("valid");
        let s = b.add(t, p).expect("valid");
        b.output(s).expect("valid");
        b.output(x).expect("valid");
        b.build().expect("valid")
    }

    #[test]
    fn round_trip_preserves_structure() {
        let circuit = sample_circuit();
        let bytes = serialize(&circuit);
        let decoded: Circuit<Fr> = deserialize(&bytes).expect("valid");
        assert_eq!(decoded, circuit);
    }

    #[test]
    fn serialization_is_deterministic() {
        assert_eq!(serialize(&sample_circuit()), serialize(&sample_circuit()));
    }

    #[test]
    fn version_byte_is_first() {
        let bytes = serialize(&sample_circuit());
        assert_eq!(bytes[0], ENCODING_VERSION);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let bytes = serialize(&sample_circuit());
        let mut extended = bytes.clone();
        extended.push(0);
        assert_eq!(
            deserialize::<Fr>(&extended).unwrap_err(),
            CircuitError::TrailingBytes
        );
    }

    #[test]
    fn truncated_input_is_rejected() {
        let bytes = serialize(&sample_circuit());
        for cut in [1usize, 5, 17] {
            assert_eq!(
                deserialize::<Fr>(&bytes[..cut]).unwrap_err(),
                CircuitError::UnexpectedEnd
            );
        }
    }

    #[test]
    fn wrong_version_is_rejected() {
        let mut bytes = serialize(&sample_circuit());
        bytes[0] = 99;
        assert_eq!(
            deserialize::<Fr>(&bytes).unwrap_err(),
            CircuitError::UnsupportedVersion
        );
    }

    #[test]
    fn unknown_node_tag_is_rejected() {
        let mut bytes = serialize(&sample_circuit());
        // First node tag sits right after version + num_nodes.
        let tag_pos = 1 + 4;
        bytes[tag_pos] = 42;
        assert_eq!(
            deserialize::<Fr>(&bytes).unwrap_err(),
            CircuitError::MalformedNode
        );
    }

    #[test]
    fn invalid_reference_in_encoding_fails_validation() {
        let mut b = CircuitBuilder::<Fr>::new();
        let x = b.secret_input();
        let s = b.add(x, x).expect("valid");
        b.output(s).expect("valid");
        let mut bytes = serialize(&b.build().expect("valid"));
        // Layout: ver(1) n(4) tag_secret(1) tag_add(1) a(4) b(4)
        //         tag_output(1) n_out(4) out(4). Operand `b` sits at
        // offset 11; corrupt it to point beyond the node count.
        bytes[11..15].copy_from_slice(&77u32.to_be_bytes());
        assert_eq!(
            deserialize::<Fr>(&bytes).unwrap_err(),
            CircuitError::InvalidReference
        );
    }

    #[test]
    fn zero_constant_round_trips() {
        let mut b = CircuitBuilder::new();
        let z = b.constant(Fr::zero());
        b.output(z).expect("valid");
        let circuit = b.build().expect("valid");
        let decoded: Circuit<Fr> = deserialize(&serialize(&circuit)).expect("valid");
        assert_eq!(decoded, circuit);
    }

    #[test]
    fn modulus_minus_one_round_trips() {
        // A value near the modulus exercises the canonical element path.
        let mut b = CircuitBuilder::new();
        let big = b.constant(Fr::from(-1i64)); // p - 1
        b.output(big).expect("valid");
        let circuit = b.build().expect("valid");
        let decoded: Circuit<Fr> = deserialize(&serialize(&circuit)).expect("valid");
        assert_eq!(decoded, circuit);
    }
}
