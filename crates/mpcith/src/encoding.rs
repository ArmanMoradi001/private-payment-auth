//! Canonical, hand-rolled serialization for MPCitH artifacts.
//!
//! Encoding rules (all integers big-endian, field elements fixed-width
//! big-endian over the ed25519 scalar field):
//!
//! ```text
//! PartyView      rep_id(u32) || party_id(u8)
//!                || n_shares(u32) [share(32B)]
//!                || n_ops(u32) [op]
//!                || n_triples(u32) [(a,b,c)(96B)]
//!                || n_opened(u32) [value(32B)]
//!
//! op             tag(u8): Add=0        → output(u32) ‖ share(32B)
//!                         MulPublic=1   → output(u32) ‖ public(32B) ‖ share(32B)
//!                         BeaverMul=2   → output(u32) ‖ triple_index(u32)
//!                                          ‖ d(32B) ‖ e(32B) ‖ share(32B)
//!
//! Challenge      hidden_party(u8)
//! Repetition     rep_id(u32) || 3×commitment(32B) || challenge(u8)
//!                || n_hidden_out(u32) [share(32B)]
//!                || 2×( len(u32) ‖ view bytes ‖ randomness(32B) )
//! MpcithProof    version(u8 = 1) || n_reps(u32) [repetition]
//! ```
//!
//! Decoding rejects unknown versions, truncation, unknown tags,
//! out-of-range party ids, and trailing bytes. No external
//! serialization framework is used.

use ark_ff::{BigInteger, PrimeField};
use circuit::NodeId;

use crate::error::MpcithError;
use crate::types::{FieldElement, PartyId, PARTY_COUNT};
use crate::view::{LocalOperation, PartyView, TripleShare};

/// Current canonical encoding version.
pub const ENCODING_VERSION: u8 = 1;

/// Maximum number of repetitions a proof decoder will accept.
///
/// Bounds decode-time work and guards against a hostile proof forcing
/// unbounded verification cost. Mirrors the proof-layer limit.
pub const MAX_REPETITIONS: usize = 10_000;

const TAG_ADD: u8 = 0;
const TAG_MUL_PUBLIC: u8 = 1;
const TAG_BEAVER_MUL: u8 = 2;

/// Big-endian byte width of one [`FieldElement`] (ed25519 scalar).
pub const ELEMENT_WIDTH: usize = 32;

// ---------------------------------------------------------------------
// Field elements
// ---------------------------------------------------------------------

fn element_to_be_bytes(value: &FieldElement) -> [u8; ELEMENT_WIDTH] {
    let mut out = [0u8; ELEMENT_WIDTH];
    let bytes = PrimeField::into_bigint(*value).to_bytes_be();
    debug_assert!(bytes.len() <= ELEMENT_WIDTH);
    out[ELEMENT_WIDTH - bytes.len()..].copy_from_slice(&bytes);
    out
}

fn element_from_be_bytes(bytes: &[u8]) -> Option<FieldElement> {
    if bytes.len() != ELEMENT_WIDTH {
        return None;
    }
    let bits: Vec<bool> = bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |i| (byte >> (7 - i)) & 1 == 1))
        .collect();
    FieldElement::from_bigint(<FieldElement as PrimeField>::BigInt::from_bits_be(&bits))
}

fn put_element(out: &mut Vec<u8>, value: &FieldElement) {
    out.extend_from_slice(&element_to_be_bytes(value));
}

// ---------------------------------------------------------------------
// PartyView
// ---------------------------------------------------------------------

/// Appends the canonical encoding of `view` to `out`.
pub fn encode_view(view: &PartyView, out: &mut Vec<u8>) {
    out.extend_from_slice(&view.repetition_id.get().to_be_bytes());
    out.push(view.party_id.get());

    out.extend_from_slice(&(view.input_shares.len() as u32).to_be_bytes());
    for share in &view.input_shares {
        put_element(out, share);
    }

    out.extend_from_slice(&(view.local_operations.len() as u32).to_be_bytes());
    for op in &view.local_operations {
        match op {
            LocalOperation::Add { output, share } => {
                out.push(TAG_ADD);
                out.extend_from_slice(&output.get().to_be_bytes());
                put_element(out, share);
            }
            LocalOperation::MulPublic {
                output,
                public,
                share,
            } => {
                out.push(TAG_MUL_PUBLIC);
                out.extend_from_slice(&output.get().to_be_bytes());
                put_element(out, public);
                put_element(out, share);
            }
            LocalOperation::BeaverMul {
                output,
                triple_index,
                d,
                e,
                share,
            } => {
                out.push(TAG_BEAVER_MUL);
                out.extend_from_slice(&output.get().to_be_bytes());
                out.extend_from_slice(&(*triple_index as u32).to_be_bytes());
                put_element(out, d);
                put_element(out, e);
                put_element(out, share);
            }
        }
    }

    out.extend_from_slice(&(view.triple_shares.len() as u32).to_be_bytes());
    for t in &view.triple_shares {
        put_element(out, &t.a);
        put_element(out, &t.b);
        put_element(out, &t.c);
    }

    out.extend_from_slice(&(view.opened_values.len() as u32).to_be_bytes());
    for v in &view.opened_values {
        put_element(out, v);
    }
}

/// Parses a [`PartyView`] from the front of `bytes`, returning the
/// decoded view and the number of bytes consumed.
///
/// # Errors
///
/// - [`MpcithError::MalformedEncoding`] on any structural problem.
pub fn decode_view(bytes: &[u8]) -> Result<(PartyView, usize), MpcithError> {
    let mut c = Cursor::new(bytes);

    let repetition_id = crate::types::RepetitionId::new(c.read_u32()?);
    let party_id = read_party_id(&mut c)?;

    let n_shares = c.read_u32()? as usize;
    let input_shares = read_elements(&mut c, n_shares)?;

    let n_ops = c.read_u32()? as usize;
    let mut local_operations = Vec::with_capacity(n_ops.min(1024));
    for _ in 0..n_ops {
        let tag = c.read_u8()?;
        let op = match tag {
            TAG_ADD => {
                let output = NodeId::new(c.read_u32()?);
                let share = read_element(&mut c)?;
                LocalOperation::Add { output, share }
            }
            TAG_MUL_PUBLIC => {
                let output = NodeId::new(c.read_u32()?);
                let public = read_element(&mut c)?;
                let share = read_element(&mut c)?;
                LocalOperation::MulPublic {
                    output,
                    public,
                    share,
                }
            }
            TAG_BEAVER_MUL => {
                let output = NodeId::new(c.read_u32()?);
                let triple_index = c.read_u32()? as usize;
                let d = read_element(&mut c)?;
                let e = read_element(&mut c)?;
                let share = read_element(&mut c)?;
                LocalOperation::BeaverMul {
                    output,
                    triple_index,
                    d,
                    e,
                    share,
                }
            }
            _ => return Err(MpcithError::MalformedEncoding),
        };
        local_operations.push(op);
    }

    let n_triples = c.read_u32()? as usize;
    let mut triple_shares = Vec::with_capacity(n_triples.min(1024));
    for _ in 0..n_triples {
        let a = read_element(&mut c)?;
        let b = read_element(&mut c)?;
        let cc = read_element(&mut c)?;
        triple_shares.push(TripleShare { a, b, c: cc });
    }

    let n_opened = c.read_u32()? as usize;
    let opened_values = read_elements(&mut c, n_opened)?;

    Ok((
        PartyView {
            repetition_id,
            party_id,
            input_shares,
            local_operations,
            triple_shares,
            opened_values,
        },
        c.pos,
    ))
}

fn read_party_id(c: &mut Cursor<'_>) -> Result<PartyId, MpcithError> {
    PartyId::new(c.read_u8()?).map_err(|_| MpcithError::MalformedEncoding)
}

fn read_element(c: &mut Cursor<'_>) -> Result<FieldElement, MpcithError> {
    let raw = c.read_bytes(ELEMENT_WIDTH)?;
    element_from_be_bytes(raw).ok_or(MpcithError::MalformedEncoding)
}

fn read_elements(c: &mut Cursor<'_>, count: usize) -> Result<Vec<FieldElement>, MpcithError> {
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        out.push(read_element(c)?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------
// Challenge / Commitment / Repetition / Proof
// ---------------------------------------------------------------------

/// Encodes a challenge (one byte: the hidden party id).
pub fn encode_challenge(hidden_party: PartyId, out: &mut Vec<u8>) {
    out.push(hidden_party.get());
}

/// Decodes a one-byte challenge.
pub fn decode_challenge(bytes: &[u8]) -> Result<(crate::types::Challenge, usize), MpcithError> {
    let mut c = Cursor::new(bytes);
    let hidden_party = read_party_id(&mut c)?;
    Ok((crate::types::Challenge { hidden_party }, c.pos))
}

/// Encodes a repetition.
pub fn encode_repetition(repetition: &crate::prover::Repetition, out: &mut Vec<u8>) {
    out.extend_from_slice(&repetition.id.get().to_be_bytes());
    for commitment in &repetition.commitments {
        out.extend_from_slice(commitment.as_digest().as_bytes());
    }
    encode_challenge(repetition.challenge.hidden_party, out);

    out.extend_from_slice(&(repetition.hidden_output_shares.len() as u32).to_be_bytes());
    for share in &repetition.hidden_output_shares {
        put_element(out, share);
    }

    out.extend_from_slice(&(repetition.hidden_broadcasts.len() as u32).to_be_bytes());
    for value in &repetition.hidden_broadcasts {
        put_element(out, value);
    }

    for opened in &repetition.opened_views {
        let mut view_bytes = Vec::new();
        encode_view(&opened.view, &mut view_bytes);
        out.extend_from_slice(&(view_bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(&view_bytes);
        out.extend_from_slice(opened.randomness.as_bytes());
    }
}

/// Decodes a repetition.
pub fn decode_repetition(bytes: &[u8]) -> Result<(crate::prover::Repetition, usize), MpcithError> {
    let mut c = Cursor::new(bytes);
    let id = crate::types::RepetitionId::new(c.read_u32()?);

    let mut commitments = Vec::with_capacity(PARTY_COUNT as usize);
    for _ in 0..PARTY_COUNT {
        let raw = c.read_bytes(crate::types::DIGEST_LEN_MPCITH)?;
        let digest = crypto_core::Digest::from(
            <[u8; 32]>::try_from(raw).map_err(|_| MpcithError::MalformedEncoding)?,
        );
        commitments.push(crate::commitment::ViewCommitment::from_digest(digest));
    }

    let (challenge, _) =
        decode_challenge(&bytes[c.pos..]).map_err(|_| MpcithError::MalformedEncoding)?;
    // Advance past the single challenge byte manually for clarity.
    c.pos += 1;

    let n_hidden_out = c.read_u32()? as usize;
    let hidden_output_shares = read_elements(&mut c, n_hidden_out)?;

    let n_broadcasts = c.read_u32()? as usize;
    let hidden_broadcasts = read_elements(&mut c, n_broadcasts)?;

    let mut opened_views = Vec::with_capacity(2);
    for _ in 0..2 {
        let len = c.read_u32()? as usize;
        let view_bytes = c.read_bytes(len)?;
        let (view, _) = decode_view(view_bytes)?;
        let randomness_raw = c.read_bytes(crate::types::RANDOMNESS_LEN_MPCITH)?;
        let randomness = crypto_core::SecretBytes::new(randomness_raw.to_vec());
        opened_views.push(crate::prover::OpenedView { view, randomness });
    }

    Ok((
        crate::prover::Repetition {
            id,
            commitments,
            challenge,
            opened_views,
            hidden_output_shares,
            hidden_broadcasts,
        },
        c.pos,
    ))
}

/// Encodes a full proof.
pub fn encode_proof(proof: &crate::prover::MpcithProof, out: &mut Vec<u8>) {
    out.push(ENCODING_VERSION);
    out.extend_from_slice(&(proof.repetitions.len() as u32).to_be_bytes());
    for repetition in &proof.repetitions {
        encode_repetition(repetition, out);
    }
}

/// Convenience wrapper: serializes a proof into a fresh byte vector.
pub fn serialize_proof(proof: &crate::prover::MpcithProof) -> Vec<u8> {
    let mut out = Vec::new();
    encode_proof(proof, &mut out);
    out
}

/// Decodes a full proof, rejecting version mismatches and trailing
/// bytes.
pub fn decode_proof(bytes: &[u8]) -> Result<crate::prover::MpcithProof, MpcithError> {
    let mut c = Cursor::new(bytes);
    if c.read_u8()? != ENCODING_VERSION {
        return Err(MpcithError::MalformedEncoding);
    }
    let n_reps = c.read_u32()? as usize;
    if n_reps > MAX_REPETITIONS {
        return Err(MpcithError::MalformedEncoding);
    }
    let mut repetitions = Vec::with_capacity(n_reps.min(1024));
    while repetitions.len() < n_reps {
        let remaining = &bytes[c.pos..];
        let (repetition, consumed) = decode_repetition(remaining)?;
        c.pos += consumed;
        repetitions.push(repetition);
    }
    if c.pos != bytes.len() {
        return Err(MpcithError::MalformedEncoding);
    }
    Ok(crate::prover::MpcithProof { repetitions })
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn read_u8(&mut self) -> Result<u8, MpcithError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, MpcithError> {
        let raw = self.read_bytes(4)?;
        Ok(u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], MpcithError> {
        if self.bytes.len() - self.pos < len {
            return Err(MpcithError::MalformedEncoding);
        }
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }
}
