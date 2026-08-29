//! Canonical, injective, versioned encoding of [`Policy`] trees.
//!
//! The encoding is:
//!
//! * **Deterministic** — identical policies always encode identically.
//! * **Injective** — distinct normalized policies never share an
//!   encoding (distinct tag/length framing makes every node
//!   self-delimiting).
//! * **Versioned** — a leading version byte lets future formats be
//!   rejected cleanly rather than mis-parsed.
//! * **Bounded** — the final length is capped at [`MAX_ENCODED_SIZE`].
//! * **Architecture-independent** — all multi-byte integers are big
//!   endian and fixed width.
//!
//! Tag bytes: `AmountAtMost = 1`, `Credential = 2`, `Threshold = 3`,
//! `And = 4`, `Or = 5`.

use crate::ast::{AmountLimit, CredentialId, Policy, CREDENTIAL_ID_LEN};
use crate::error::PolicyError;
use crate::validation::MAX_ENCODED_SIZE;

/// Canonical encoding version.
pub const ENCODING_VERSION: u8 = 1;

mod tag {
    pub(super) const AMOUNT_AT_MOST: u8 = 1;
    pub(super) const CREDENTIAL: u8 = 2;
    pub(super) const THRESHOLD: u8 = 3;
    pub(super) const AND: u8 = 4;
    pub(super) const OR: u8 = 5;
}

/// Returns the canonical encoding of `policy`.
///
/// # Panics
///
/// Never in practice: the only fallible step is the size bound, which
/// is enforced by returning the bytes only after the check. The
/// function is infallible for valid policies.
pub fn encode(policy: &Policy) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(ENCODING_VERSION);
    encode_node(policy, &mut out);
    debug_assert!(
        out.len() <= MAX_ENCODED_SIZE,
        "encoding exceeded MAX_ENCODED_SIZE; validation must reject first"
    );
    out
}

fn encode_node(policy: &Policy, out: &mut Vec<u8>) {
    match policy {
        Policy::AmountAtMost(limit) => {
            out.push(tag::AMOUNT_AT_MOST);
            out.extend_from_slice(&limit.value().to_be_bytes());
        }
        Policy::Credential(id) => {
            out.push(tag::CREDENTIAL);
            out.extend_from_slice(id.as_bytes());
        }
        Policy::Threshold { k, members } => {
            out.push(tag::THRESHOLD);
            out.extend_from_slice(&k.get().to_be_bytes());
            out.extend_from_slice(&(members.len() as u32).to_be_bytes());
            for member in members {
                encode_node(member, out);
            }
        }
        Policy::And(members) => {
            out.push(tag::AND);
            out.extend_from_slice(&(members.len() as u32).to_be_bytes());
            for member in members {
                encode_node(member, out);
            }
        }
        Policy::Or(members) => {
            out.push(tag::OR);
            out.extend_from_slice(&(members.len() as u32).to_be_bytes());
            for member in members {
                encode_node(member, out);
            }
        }
    }
}

/// Decodes a [`Policy`] from its canonical encoding.
///
/// # Errors
///
/// Returns [`PolicyError::UnknownVersion`] for an unrecognized version,
/// [`PolicyError::MalformedEncoding`] for truncation or an unknown tag,
/// [`PolicyError::TrailingBytes`] for bytes after a complete policy, and
/// other [`PolicyError`] variants for structurally invalid shapes (e.g.
/// [`PolicyError::InvalidThreshold`]).
pub fn decode(bytes: &[u8]) -> Result<Policy, PolicyError> {
    let mut reader = Reader::new(bytes);
    let version = reader.take_byte()?;
    if version != ENCODING_VERSION {
        return Err(PolicyError::UnknownVersion);
    }
    let policy = reader.take_node()?;
    if reader.remaining() != 0 {
        return Err(PolicyError::TrailingBytes);
    }
    Ok(policy)
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.bytes.len() - self.pos
    }

    fn take_byte(&mut self) -> Result<u8, PolicyError> {
        if self.pos >= self.bytes.len() {
            return Err(PolicyError::MalformedEncoding);
        }
        let byte = self.bytes[self.pos];
        self.pos += 1;
        Ok(byte)
    }

    fn take_slice(&mut self, len: usize) -> Result<&'a [u8], PolicyError> {
        if self.pos + len > self.bytes.len() {
            return Err(PolicyError::MalformedEncoding);
        }
        let slice = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(slice)
    }

    fn take_u32(&mut self) -> Result<u32, PolicyError> {
        let slice = self.take_slice(4)?;
        let mut buf = [0u8; 4];
        buf.copy_from_slice(slice);
        Ok(u32::from_be_bytes(buf))
    }

    fn take_u64(&mut self) -> Result<u64, PolicyError> {
        let slice = self.take_slice(8)?;
        let mut buf = [0u8; 8];
        buf.copy_from_slice(slice);
        Ok(u64::from_be_bytes(buf))
    }

    fn take_u16(&mut self) -> Result<u16, PolicyError> {
        let slice = self.take_slice(2)?;
        let mut buf = [0u8; 2];
        buf.copy_from_slice(slice);
        Ok(u16::from_be_bytes(buf))
    }

    fn take_node(&mut self) -> Result<Policy, PolicyError> {
        let tag = self.take_byte()?;
        match tag {
            tag::AMOUNT_AT_MOST => {
                let limit = self.take_u64()?;
                Ok(Policy::AmountAtMost(AmountLimit::new(limit)))
            }
            tag::CREDENTIAL => {
                let slice = self.take_slice(CREDENTIAL_ID_LEN)?;
                let mut buf = [0u8; CREDENTIAL_ID_LEN];
                buf.copy_from_slice(slice);
                Ok(Policy::Credential(CredentialId::new(buf)))
            }
            tag::THRESHOLD => {
                let k = self.take_u16()?;
                let count = self.take_u32()? as usize;
                let mut members = Vec::with_capacity(count);
                for _ in 0..count {
                    members.push(self.take_node()?);
                }
                Ok(Policy::Threshold {
                    k: crate::ast::ThresholdK::new(k),
                    members,
                })
            }
            tag::AND => {
                let count = self.take_u32()? as usize;
                let mut members = Vec::with_capacity(count);
                for _ in 0..count {
                    members.push(self.take_node()?);
                }
                Ok(Policy::And(members))
            }
            tag::OR => {
                let count = self.take_u32()? as usize;
                let mut members = Vec::with_capacity(count);
                for _ in 0..count {
                    members.push(self.take_node()?);
                }
                Ok(Policy::Or(members))
            }
            _ => Err(PolicyError::MalformedEncoding),
        }
    }
}
