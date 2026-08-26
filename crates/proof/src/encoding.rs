//! Canonical serialization for non-interactive proofs.
//!
//! Layout (integers big-endian; field elements fixed-width BE):
//!
//! ```text
//! NonInteractiveProof
//!   version(u8) ‖ protocol_id(u8) ‖ statement ‖ n_reps(u32) [repetition]
//!
//! statement   ver(u8) ‖ circuit_id(32B) ‖ n_pub(u32)[32B] ‖ n_out(u32)[32B]
//! repetition  commitments(3×32B) ‖ challenge(u8)
//!             ‖ n_broadcasts(u32) [value(32B)]
//!             ‖ 2×( len(u32) ‖ view-bytes ‖ randomness(32B) )
//! ```
//!
//! Views reuse the `mpcith` canonical view encoding. Decoding rejects
//! wrong versions, truncation, malformed views, and trailing bytes.
//! `deserialize(serialize(proof))` reproduces identical bytes.

use crypto_core::Digest;
use mpcith::FieldElement;

use crate::error::ProofError;
use crate::proof::{NonInteractiveProof, ProofRepetition};
use crate::statement::Statement;

/// Proof-encoding version.
pub const ENCODING_VERSION: u8 = 1;
/// Protocol id bound into encodings.
pub const PROTOCOL_ID: u8 = 1;

/// Serializes a proof into its canonical byte representation.
pub fn serialize_proof(proof: &NonInteractiveProof) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(proof.version());
    out.push(proof.protocol_id());
    proof.statement().encode_into(&mut out);

    let reps = proof.repetitions();
    out.extend_from_slice(&(reps.len() as u32).to_be_bytes());
    for rep in reps {
        for commitment in rep.commitments() {
            out.extend_from_slice(commitment.as_digest().as_bytes());
        }
        out.push(rep.challenge().hidden_party.get());

        out.extend_from_slice(&(rep.hidden_broadcasts().len() as u32).to_be_bytes());
        for value in rep.hidden_broadcasts() {
            put_element(&mut out, value);
        }

        out.extend_from_slice(&(rep.hidden_output_shares().len() as u32).to_be_bytes());
        for value in rep.hidden_output_shares() {
            put_element(&mut out, value);
        }

        let views = rep.opened_views();
        let randomness = rep.opening_randomness();
        out.extend_from_slice(&(views.len() as u32).to_be_bytes());
        for (view, r) in views.iter().zip(randomness) {
            let mut view_bytes = Vec::new();
            mpcith::encode_view(view, &mut view_bytes);
            out.extend_from_slice(&(view_bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(&view_bytes);
            out.extend_from_slice(r.as_bytes());
        }
    }
    out
}

/// Parses a proof from its canonical encoding.
///
/// # Errors
///
/// [`ProofError::InvalidVersion`] on unknown version/protocol bytes,
/// [`ProofError::MalformedEncoding`] on any structural problem,
/// trailing bytes, or a view that fails to decode.
pub fn deserialize_proof(bytes: &[u8]) -> Result<NonInteractiveProof, ProofError> {
    let mut c = Cursor { bytes, pos: 0 };
    let version = c.read_u8()?;
    if version != ENCODING_VERSION {
        return Err(ProofError::InvalidVersion);
    }
    let protocol_id = c.read_u8()?;
    if protocol_id != PROTOCOL_ID {
        return Err(ProofError::InvalidVersion);
    }

    // The statement has its own self-delimiting decoder; feed it the
    // remainder and resume after it.
    let (statement, consumed) = Statement::decode_prefix(&bytes[c.pos..])?;
    c.pos += consumed;

    let n_reps = c.read_u32()? as usize;
    let mut repetitions = Vec::with_capacity(n_reps.min(1024));
    for _ in 0..n_reps {
        repetitions.push(decode_repetition(&mut c)?);
    }
    if c.pos != bytes.len() {
        return Err(ProofError::MalformedEncoding);
    }

    Ok(NonInteractiveProof::new(
        version,
        protocol_id,
        statement,
        repetitions,
    ))
}

fn decode_repetition(c: &mut Cursor<'_>) -> Result<ProofRepetition, ProofError> {
    use mpcith::ViewCommitment;

    let mut commitments = Vec::with_capacity(3);
    for _ in 0..3 {
        let raw = c.read_bytes(32)?;
        commitments.push(ViewCommitment::from_digest(Digest::from(
            <[u8; 32]>::try_from(raw).map_err(|_| ProofError::MalformedEncoding)?,
        )));
    }
    let challenge = mpcith::Challenge {
        hidden_party: mpcith::PartyId::new(c.read_u8()?)
            .map_err(|_| ProofError::MalformedEncoding)?,
    };

    let n_broadcasts = c.read_u32()? as usize;
    let mut hidden_broadcasts = Vec::with_capacity(n_broadcasts.min(1024));
    for _ in 0..n_broadcasts {
        hidden_broadcasts.push(read_element(c)?);
    }

    let n_hidden_out = c.read_u32()? as usize;
    let mut hidden_output_shares = Vec::with_capacity(n_hidden_out.min(1024));
    for _ in 0..n_hidden_out {
        hidden_output_shares.push(read_element(c)?);
    }

    let n_opened = c.read_u32()? as usize;
    if n_opened != 2 {
        return Err(ProofError::MalformedEncoding);
    }
    let mut opened_views = Vec::with_capacity(2);
    let mut opening_randomness = Vec::with_capacity(2);
    for _ in 0..n_opened {
        let len = c.read_u32()? as usize;
        let view_bytes = c.read_bytes(len)?;
        let (view, consumed) =
            mpcith::decode_view(view_bytes).map_err(|_| ProofError::MalformedEncoding)?;
        if consumed != view_bytes.len() {
            return Err(ProofError::MalformedEncoding);
        }
        opened_views.push(view);
        opening_randomness.push(crypto_core::SecretBytes::new(
            c.read_bytes(mpcith::types::RANDOMNESS_LEN_MPCITH)?.to_vec(),
        ));
    }

    Ok(ProofRepetition::new(
        commitments,
        challenge,
        opened_views,
        opening_randomness,
        hidden_broadcasts,
        hidden_output_shares,
    ))
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
