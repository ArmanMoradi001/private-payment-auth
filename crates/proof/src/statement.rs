//! The public statement being proven.
//!
//! A statement pins a circuit by its semantic id, the public inputs,
//! and the expected plaintext outputs. Secret inputs (the witness)
//! never appear here. The canonical encoding of the statement is a
//! Fiat–Shamir input: changing anything in it changes every challenge.

use circuit::CircuitId;
use crypto_core::Digest;
use mpc::PublicValue;
use mpcith::FieldElement;

use crate::error::ProofError;

/// Current statement-encoding version.
pub const STATEMENT_VERSION: u8 = 1;

/// Public description of what is proven.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Statement {
    /// Semantic hash of the circuit this statement refers to.
    pub circuit_id: CircuitId,
    /// Public inputs in circuit declaration order.
    pub public_inputs: Vec<PublicValue<FieldElement>>,
    /// Expected outputs in circuit output order.
    pub expected_outputs: Vec<PublicValue<FieldElement>>,
}

impl Statement {
    /// Checks consistency against `circuit`.
    ///
    /// # Errors
    ///
    /// - [`ProofError::InvalidCircuit`] if the circuit fails
    ///   validation or its id differs from [`Self::circuit_id`].
    /// - [`ProofError::InvalidStatement`] if counts disagree with the
    ///   circuit's declarations.
    pub fn validate(&self, circuit: &circuit::Circuit<FieldElement>) -> Result<(), ProofError> {
        use mpcith::MpcithError;
        circuit.validate().map_err(|_| ProofError::InvalidCircuit)?;
        if self.circuit_id != circuit.compute_id() {
            return Err(ProofError::CircuitIdMismatch);
        }
        if self.public_inputs.len() != circuit.num_public_inputs()
            || self.expected_outputs.len() != circuit.outputs().len()
        {
            return Err(MpcithError::InvalidStatement).map_err(|_| ProofError::InvalidStatement);
        }
        Ok(())
    }

    /// Canonical encoding:
    /// `version(u8) ‖ circuit_id(32B) ‖ n_pub(u32) [32B] ‖ n_out(u32) [32B]`.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.encode_into(&mut out);
        out
    }

    /// Appends the canonical encoding to `out`.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        out.push(STATEMENT_VERSION);
        out.extend_from_slice(self.circuit_id.as_digest().as_bytes());
        out.extend_from_slice(&(self.public_inputs.len() as u32).to_be_bytes());
        for value in &self.public_inputs {
            put_element(out, value.value());
        }
        out.extend_from_slice(&(self.expected_outputs.len() as u32).to_be_bytes());
        for value in &self.expected_outputs {
            put_element(out, value.value());
        }
    }

    /// Parses a statement; rejects truncation, bad versions, values at
    /// or above the field modulus, and trailing bytes.
    ///
    /// # Errors
    ///
    /// - [`ProofError::InvalidVersion`], [`ProofError::MalformedEncoding`].
    pub fn decode(bytes: &[u8]) -> Result<Self, ProofError> {
        let (statement, consumed) = Self::decode_prefix(bytes)?;
        if consumed != bytes.len() {
            return Err(ProofError::MalformedEncoding);
        }
        Ok(statement)
    }

    /// Parses a statement from the front of `bytes`, returning it with
    /// the number of bytes consumed. Trailing bytes are allowed, so an
    /// embedded statement can be decoded from a larger buffer (a proof,
    /// for instance).
    ///
    /// # Errors
    ///
    /// - [`ProofError::InvalidVersion`], [`ProofError::MalformedEncoding`].
    pub fn decode_prefix(bytes: &[u8]) -> Result<(Self, usize), ProofError> {
        let mut c = Cursor { bytes, pos: 0 };
        let version = c.read_u8()?;
        if version != STATEMENT_VERSION {
            return Err(ProofError::InvalidVersion);
        }
        let id_raw = c.read_bytes(32)?;
        let circuit_id = CircuitId::from_digest(Digest::from(
            <[u8; 32]>::try_from(id_raw).map_err(|_| ProofError::MalformedEncoding)?,
        ));

        let n_pub = c.read_u32()? as usize;
        let mut public_inputs = Vec::with_capacity(n_pub.min(1024));
        for _ in 0..n_pub {
            public_inputs.push(PublicValue::new(read_element(&mut c)?));
        }
        let n_out = c.read_u32()? as usize;
        let mut expected_outputs = Vec::with_capacity(n_out.min(1024));
        for _ in 0..n_out {
            expected_outputs.push(PublicValue::new(read_element(&mut c)?));
        }
        Ok((
            Self {
                circuit_id,
                public_inputs,
                expected_outputs,
            },
            c.pos,
        ))
    }

    /// Converts into the mpcith-layer statement type.
    pub fn to_mpcith(&self) -> mpcith::Statement {
        mpcith::Statement {
            circuit_id: self.circuit_id,
            public_inputs: self.public_inputs.clone(),
            expected_outputs: self.expected_outputs.clone(),
        }
    }

    /// Builds a proof-layer statement from the mpcith-layer type.
    pub fn from_mpcith(statement: &mpcith::Statement) -> Self {
        Self {
            circuit_id: statement.circuit_id,
            public_inputs: statement.public_inputs.clone(),
            expected_outputs: statement.expected_outputs.clone(),
        }
    }
}

fn put_element(out: &mut Vec<u8>, value: &FieldElement) {
    use ark_ff::{BigInteger, PrimeField};
    let bytes = PrimeField::into_bigint(*value).to_bytes_be();
    debug_assert!(bytes.len() <= 32);
    out.resize(out.len() + 32 - bytes.len(), 0);
    out.extend_from_slice(&bytes);
}

fn read_element(c: &mut Cursor<'_>) -> Result<FieldElement, ProofError> {
    use ark_ff::{BigInteger, PrimeField};
    let raw = c.read_bytes(32)?;
    let bits: Vec<bool> = raw
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> (7 - i)) & 1 == 1))
        .collect();
    FieldElement::from_bigint(<FieldElement as PrimeField>::BigInt::from_bits_be(&bits))
        .ok_or(ProofError::MalformedEncoding)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn read_u8(&mut self) -> Result<u8, ProofError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, ProofError> {
        let raw = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'_ [u8], ProofError> {
        if self.bytes.len() - self.pos < len {
            return Err(ProofError::MalformedEncoding);
        }
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }
}
